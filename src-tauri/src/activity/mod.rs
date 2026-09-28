pub mod diagnostics;
pub mod observer;
pub mod policy;
#[cfg(any(all(feature = "activity-prototype", target_os = "windows"), test))]
mod windows_logic;

#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(all(target_os = "macos", feature = "i08-native-probe"))]
pub mod native_gate_probe;

#[cfg(all(feature = "activity-prototype", target_os = "windows"))]
mod windows;

#[cfg(feature = "activity-prototype")]
pub mod prototype;
