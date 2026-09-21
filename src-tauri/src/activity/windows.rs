use core::ffi::c_void;
use std::mem::size_of;
use std::ptr::{self, null, null_mut};
use std::sync::mpsc::{Sender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, GetLastError, HWND, LPARAM, LRESULT, SetLastError, WPARAM,
};
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK,
    WTS_SESSIONSTATE_UNLOCK, WTSActive, WTSClientProtocolType, WTSFreeMemory, WTSINFOEXW,
    WTSQuerySessionInformationW, WTSRegisterSessionNotification, WTSSessionId, WTSSessionInfoEx,
    WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, CreateWindowExW, DestroyWindow, DispatchMessageW, GWLP_USERDATA, GWLP_WNDPROC,
    GetMessageW, GetWindowLongPtrW, MSG, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND,
    PBT_APMSUSPEND, PostMessageW, PostQuitMessage, SetWindowLongPtrW, TranslateMessage, WM_APP,
    WM_CLOSE, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDPROC, WTS_CONSOLE_CONNECT,
    WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_CREATE,
    WTS_SESSION_LOCK, WTS_SESSION_LOGOFF, WTS_SESSION_LOGON, WTS_SESSION_REMOTE_CONTROL,
    WTS_SESSION_TERMINATE, WTS_SESSION_UNLOCK,
};

use super::observer::{
    ActivitySampler, ObserverStartError, ObserverStopError, PollingObserver, monotonic_time,
};
use super::policy::{
    ActivityObservation, ActivitySampleValue, EligibleInputClass, InputSampleFailure,
    InputSampleValue, ObservationKind, UnlockGateFailure, UnlockGateState,
};
use super::windows_logic::{
    ConnectState, LastInputTracker, LockState, SessionProtocol, SessionTransition,
    transition_state, unlock_gate,
};

const STATIC_WINDOW_CLASS: &[u16] = &[
    b'S' as u16,
    b'T' as u16,
    b'A' as u16,
    b'T' as u16,
    b'I' as u16,
    b'C' as u16,
    0,
];
const EMPTY_WINDOW_NAME: &[u16] = &[0];
const WM_AETERNA_STOP: u32 = WM_APP + 0x41;
const WTS_INFO_LEVEL_ONE: u32 = 1;
const CLIENT_PROTOCOL_CONSOLE: u16 = 0;
const CLIENT_PROTOCOL_RDP: u16 = 2;

struct WtsBuffer {
    pointer: *mut u16,
    byte_count: u32,
}

impl WtsBuffer {
    fn query(session_id: u32, information_class: i32) -> Result<Self, ()> {
        let mut pointer = null_mut();
        let mut byte_count = 0_u32;
        // SAFETY: Windows initializes `pointer` and `byte_count` on success. The
        // returned allocation is owned by this RAII wrapper and released once.
        let succeeded = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                information_class,
                &mut pointer,
                &mut byte_count,
            )
        };
        if succeeded == 0 || pointer.is_null() {
            return Err(());
        }
        Ok(Self {
            pointer,
            byte_count,
        })
    }

    fn read_copy<T: Copy>(&self) -> Result<T, ()> {
        if usize::try_from(self.byte_count).map_err(|_| ())? < size_of::<T>() {
            return Err(());
        }
        // SAFETY: the size check above proves the WTS allocation contains a full
        // `T`. `read_unaligned` avoids imposing an undocumented alignment claim.
        Ok(unsafe { ptr::read_unaligned(self.pointer.cast::<T>()) })
    }
}

impl Drop for WtsBuffer {
    fn drop(&mut self) {
        if self.pointer.is_null() {
            return;
        }
        if let Ok(length) = usize::try_from(self.byte_count) {
            // SAFETY: WTS allocated `byte_count` writable bytes at `pointer`.
            // Clearing the whole allocation minimizes retention of fields such
            // as username/domain that this adapter never reads.
            unsafe { ptr::write_bytes(self.pointer.cast::<u8>(), 0, length) };
        }
        // SAFETY: this is the exact non-null allocation returned by WTS and it is
        // released once by this owner.
        unsafe { WTSFreeMemory(self.pointer.cast::<c_void>()) };
    }
}

fn current_session_id() -> Result<u32, ObserverStartError> {
    let buffer = WtsBuffer::query(WTS_CURRENT_SESSION, WTSSessionId)
        .map_err(|()| ObserverStartError::NativeInitializationFailed)?;
    buffer
        .read_copy::<u32>()
        .map_err(|()| ObserverStartError::NativeInitializationFailed)
}

fn query_unlock_gate(session_id: u32) -> UnlockGateState {
    let Ok(info_buffer) = WtsBuffer::query(session_id, WTSSessionInfoEx) else {
        return UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed);
    };
    let Ok(info) = info_buffer.read_copy::<WTSINFOEXW>() else {
        return UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed);
    };
    if info.Level != WTS_INFO_LEVEL_ONE {
        return UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed);
    }
    // SAFETY: WTSINFOEXW declares level 1 and therefore initializes the level-1
    // union member documented for `WTSSessionInfoEx`.
    let level = unsafe { info.Data.WTSInfoExLevel1 };
    if level.SessionId != session_id {
        return UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed);
    }
    let connect_state = if level.SessionState == WTSActive {
        ConnectState::Active
    } else {
        ConnectState::Other
    };
    let lock_state = match u32::try_from(level.SessionFlags) {
        Ok(WTS_SESSIONSTATE_LOCK) => LockState::Locked,
        Ok(WTS_SESSIONSTATE_UNLOCK) => LockState::Unlocked,
        _ => LockState::Unknown,
    };

    let protocol = WtsBuffer::query(session_id, WTSClientProtocolType)
        .and_then(|buffer| buffer.read_copy::<u16>())
        .map_or(SessionProtocol::Unknown, |value| match value {
            CLIENT_PROTOCOL_CONSOLE => SessionProtocol::Console,
            CLIENT_PROTOCOL_RDP => SessionProtocol::RemoteDesktop,
            _ => SessionProtocol::Unknown,
        });
    unlock_gate(connect_state, lock_state, protocol)
}

struct WindowsActivitySampler {
    session_id: u32,
    last_input: LastInputTracker,
}

impl WindowsActivitySampler {
    fn new(session_id: u32) -> Self {
        Self {
            session_id,
            last_input: LastInputTracker::default(),
        }
    }

    fn input_age(&mut self) -> InputSampleValue {
        let mut information = LASTINPUTINFO {
            cbSize: size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        // SAFETY: `information` has the documented size and remains writable for
        // the synchronous call. The API returns no input content.
        if unsafe { GetLastInputInfo(&mut information) } == 0 {
            return InputSampleValue::Failed(InputSampleFailure::NativeReadFailed);
        }
        // SAFETY: GetTickCount64 has no pointer or ownership preconditions.
        let uptime_milliseconds = unsafe { GetTickCount64() };
        self.last_input
            .sample_age_seconds(uptime_milliseconds, information.dwTime)
            .map_or(
                InputSampleValue::Failed(InputSampleFailure::NativeReadFailed),
                InputSampleValue::AgeSeconds,
            )
    }
}

impl ActivitySampler for WindowsActivitySampler {
    fn sample_activity(&mut self) -> ActivitySampleValue {
        // Preserve this order: a successful WTS gate read must follow the input
        // query so the next distinct input epoch has an intervening gate check.
        let eligible = self.input_age();
        let unlock_gate = query_unlock_gate(self.session_id);
        ActivitySampleValue {
            eligible,
            broader: None,
            eligible_class: EligibleInputClass::CurrentSession,
            unlock_gate,
        }
    }
}

struct WindowContext {
    observations: Sender<ActivityObservation>,
    epoch: Instant,
    session_id: u32,
    previous_window_proc: WNDPROC,
    previous_user_data: isize,
    session_notification_registered: bool,
    shutdown_failed: bool,
}

impl WindowContext {
    fn send(&self, kind: ObservationKind) {
        let observed_at = monotonic_time(self.epoch);
        let _ = self
            .observations
            .send(ActivityObservation { observed_at, kind });
    }
}

fn native_transition(code: u32) -> Option<SessionTransition> {
    match code {
        WTS_CONSOLE_CONNECT => Some(SessionTransition::ConsoleConnect),
        WTS_CONSOLE_DISCONNECT => Some(SessionTransition::ConsoleDisconnect),
        WTS_REMOTE_CONNECT => Some(SessionTransition::RemoteConnect),
        WTS_REMOTE_DISCONNECT => Some(SessionTransition::RemoteDisconnect),
        WTS_SESSION_LOGON => Some(SessionTransition::Logon),
        WTS_SESSION_LOGOFF => Some(SessionTransition::Logoff),
        WTS_SESSION_LOCK => Some(SessionTransition::Lock),
        WTS_SESSION_UNLOCK => Some(SessionTransition::Unlock),
        WTS_SESSION_REMOTE_CONTROL => Some(SessionTransition::RemoteControl),
        WTS_SESSION_CREATE => Some(SessionTransition::Create),
        WTS_SESSION_TERMINATE => Some(SessionTransition::Terminate),
        _ => None,
    }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: this procedure is installed only after GWLP_USERDATA receives the
    // stable address of a live `WindowContext` owned by the same window thread.
    let context_pointer = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut WindowContext;
    if context_pointer.is_null() {
        return 0;
    }
    // SAFETY: window creation, dispatch, and destruction all occur on this one
    // thread, and the Box outlives the message loop.
    let context = unsafe { &mut *context_pointer };

    match message {
        WM_WTSSESSION_CHANGE => {
            if u32::try_from(lparam).ok() == Some(context.session_id)
                && let Ok(code) = u32::try_from(wparam)
                && let Some(transition) = native_transition(code)
            {
                context.send(ObservationKind::SessionChanged(transition_state(
                    transition,
                )));
            }
            return 0;
        }
        WM_POWERBROADCAST => {
            if let Ok(code) = u32::try_from(wparam) {
                match code {
                    PBT_APMSUSPEND => context.send(ObservationKind::WillSleep),
                    PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => {
                        context.send(ObservationKind::DidWake)
                    }
                    _ => {}
                }
            }
            return 1;
        }
        WM_AETERNA_STOP | WM_CLOSE => {
            if context.session_notification_registered {
                // SAFETY: the registration belongs to this live HWND and is
                // removed on its owning thread before the window is destroyed.
                if unsafe { WTSUnRegisterSessionNotification(window) } == 0 {
                    context.shutdown_failed = true;
                }
                context.session_notification_registered = false;
            }
            // SAFETY: restoring the exact previous procedure and clearing the
            // context pointer prevents callbacks into Rust during destruction.
            unsafe {
                SetWindowLongPtrW(
                    window,
                    GWLP_WNDPROC,
                    context
                        .previous_window_proc
                        .map_or(0, |procedure| procedure as usize as isize),
                );
                SetWindowLongPtrW(window, GWLP_USERDATA, context.previous_user_data);
                if DestroyWindow(window) == 0 {
                    context.shutdown_failed = true;
                }
                PostQuitMessage(0);
            }
            return 0;
        }
        _ => {}
    }

    // SAFETY: `previous_window_proc` is the procedure returned by the successful
    // subclass operation for this exact window and remains valid until restore.
    unsafe {
        CallWindowProcW(
            context.previous_window_proc,
            window,
            message,
            wparam,
            lparam,
        )
    }
}

fn install_window_context(window: HWND, context: &mut WindowContext) -> Result<(), ()> {
    // SAFETY: the Box containing `context` stays at a stable address until after
    // the message loop ends. Last-error disambiguates a valid zero prior value.
    unsafe {
        SetLastError(ERROR_SUCCESS);
        let previous = SetWindowLongPtrW(
            window,
            GWLP_USERDATA,
            ptr::from_mut(context).addr() as isize,
        );
        if previous == 0 && GetLastError() != ERROR_SUCCESS {
            return Err(());
        }
        context.previous_user_data = previous;

        let previous_proc = SetWindowLongPtrW(window, GWLP_WNDPROC, window_proc as usize as isize);
        if previous_proc == 0 {
            SetWindowLongPtrW(window, GWLP_USERDATA, context.previous_user_data);
            return Err(());
        }
        // SAFETY: Windows returned a non-null executable window-procedure
        // pointer. WNDPROC is its ABI-compatible typed representation.
        context.previous_window_proc = Some(std::mem::transmute::<
            isize,
            unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT,
        >(previous_proc));
    }
    Ok(())
}

fn native_window_thread(
    observations: Sender<ActivityObservation>,
    epoch: Instant,
    session_id: u32,
    ready: std::sync::mpsc::SyncSender<Result<usize, ObserverStartError>>,
) -> Result<(), ObserverStopError> {
    // SAFETY: STATIC is a process-available system class. A null parent and no
    // visible style create an invisible top-level window that can receive power
    // broadcasts; all ownership remains on this thread.
    let window = unsafe {
        CreateWindowExW(
            0,
            STATIC_WINDOW_CLASS.as_ptr(),
            EMPTY_WINDOW_NAME.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            null(),
        )
    };
    if window.is_null() {
        let _ = ready.send(Err(ObserverStartError::NativeInitializationFailed));
        return Ok(());
    }

    let mut context = Box::new(WindowContext {
        observations,
        epoch,
        session_id,
        previous_window_proc: None,
        previous_user_data: 0,
        session_notification_registered: false,
        shutdown_failed: false,
    });
    if install_window_context(window, &mut context).is_err() {
        // SAFETY: no Rust subclass remains installed on this owned window.
        unsafe { DestroyWindow(window) };
        let _ = ready.send(Err(ObserverStartError::NativeInitializationFailed));
        return Ok(());
    }

    // SAFETY: the HWND is live, owned by this thread, and remains live until the
    // registered notification is removed during the stop message.
    if unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) } == 0 {
        // SAFETY: restore the system procedure and clear the borrowed pointer
        // before destroying the failed initialization window.
        unsafe {
            SetWindowLongPtrW(
                window,
                GWLP_WNDPROC,
                context
                    .previous_window_proc
                    .map_or(0, |procedure| procedure as usize as isize),
            );
            SetWindowLongPtrW(window, GWLP_USERDATA, context.previous_user_data);
            DestroyWindow(window);
        }
        let _ = ready.send(Err(ObserverStartError::NativeInitializationFailed));
        return Ok(());
    }
    context.session_notification_registered = true;

    if ready.send(Ok(window.addr())).is_err() {
        // SAFETY: the parent disappeared before start completed; dispatch the
        // same deterministic stop path on the owning thread.
        unsafe { window_proc(window, WM_AETERNA_STOP, 0, 0) };
    }

    let mut message = MSG::default();
    loop {
        // SAFETY: `message` remains writable, and null HWND requests this
        // thread's queue until WM_QUIT or an error.
        let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if result == 0 {
            break;
        }
        if result == -1 {
            context.shutdown_failed = true;
            break;
        }
        // SAFETY: `message` was initialized by GetMessageW for this thread.
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    if context.session_notification_registered {
        // SAFETY: error-exit cleanup runs on the owning thread for the same HWND.
        unsafe {
            if WTSUnRegisterSessionNotification(window) == 0 {
                context.shutdown_failed = true;
            }
            SetWindowLongPtrW(
                window,
                GWLP_WNDPROC,
                context
                    .previous_window_proc
                    .map_or(0, |procedure| procedure as usize as isize),
            );
            SetWindowLongPtrW(window, GWLP_USERDATA, context.previous_user_data);
            if DestroyWindow(window) == 0 {
                context.shutdown_failed = true;
            }
        }
        context.session_notification_registered = false;
    }

    if context.shutdown_failed {
        Err(ObserverStopError::NativeShutdownFailed)
    } else {
        Ok(())
    }
}

struct NativeWindowObserver {
    window: usize,
    worker: Option<JoinHandle<Result<(), ObserverStopError>>>,
}

impl NativeWindowObserver {
    fn start(
        observations: Sender<ActivityObservation>,
        epoch: Instant,
        session_id: u32,
    ) -> Result<Self, ObserverStartError> {
        let (ready_sender, ready_receiver) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("aeterna-i04-windows-session".to_owned())
            .spawn(move || native_window_thread(observations, epoch, session_id, ready_sender))
            .map_err(|_| ObserverStartError::ThreadInitializationFailed)?;

        match ready_receiver.recv() {
            Ok(Ok(window)) => Ok(Self {
                window,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(ObserverStartError::NativeInitializationFailed)
            }
        }
    }

    fn stop(&mut self) -> Result<(), ObserverStopError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let window = self.window as HWND;
        // SAFETY: the address was returned only after the native thread created,
        // subclassed, and registered this invisible window.
        let posted = unsafe { PostMessageW(window, WM_AETERNA_STOP, 0, 0) };
        let thread_result = worker
            .join()
            .map_err(|_| ObserverStopError::WorkerPanicked)?;
        if posted == 0 {
            return Err(ObserverStopError::NativeShutdownFailed);
        }
        thread_result
    }
}

impl Drop for NativeWindowObserver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub struct WindowsActivityObserver {
    native: NativeWindowObserver,
    poller: PollingObserver,
    stopped: bool,
}

impl WindowsActivityObserver {
    pub fn start(
        observations: Sender<ActivityObservation>,
        epoch: Instant,
        poll_interval: Duration,
    ) -> Result<Self, ObserverStartError> {
        let session_id = current_session_id()?;
        let mut native = NativeWindowObserver::start(observations.clone(), epoch, session_id)?;
        let poller = match PollingObserver::start(
            WindowsActivitySampler::new(session_id),
            poll_interval,
            epoch,
            observations,
        ) {
            Ok(poller) => poller,
            Err(error) => {
                let _ = native.stop();
                return Err(error);
            }
        };
        Ok(Self {
            native,
            poller,
            stopped: false,
        })
    }

    pub fn stop(&mut self) -> Result<(), ObserverStopError> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        let poller_result = self.poller.stop();
        let native_result = self.native.stop();
        poller_result.and(native_result)
    }
}

impl Drop for WindowsActivityObserver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
