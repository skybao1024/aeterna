use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER,
    ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW,
};

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUN_VALUE_NAME: &str = "AeternaI04ActivityProbe";
const AUTOSTART_ARGUMENT: &str = " --i04-autostart-probe";
const MAX_RUN_COMMAND_UNITS: usize = 260;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevAutostartError {
    AccessDenied,
    InvalidConfiguration,
    NativeFailure,
}

impl DevAutostartError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AccessDenied => "dev_autostart_access_denied",
            Self::InvalidConfiguration => "dev_autostart_invalid_configuration",
            Self::NativeFailure => "dev_autostart_native_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevAutostartStatus {
    Absent,
    Installed,
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this handle was returned by RegCreateKeyExW and is closed
            // exactly once by its owner.
            unsafe { RegCloseKey(self.0) };
        }
    }
}

pub fn install_dev_autostart() -> Result<bool, DevAutostartError> {
    if !cfg!(feature = "activity-prototype") {
        return Err(DevAutostartError::InvalidConfiguration);
    }
    let expected = expected_command()?;
    let key = open_run_key()?;
    match query_status(&key, &expected)? {
        DevAutostartStatus::Installed => return Ok(false),
        DevAutostartStatus::Absent => {}
    }
    let value_name = wide_string(RUN_VALUE_NAME)?;
    let bytes = wide_bytes(&expected);
    // SAFETY: the key is open for KEY_SET_VALUE; name and data are live,
    // null-terminated buffers and the byte count is exact.
    let result = unsafe {
        RegSetValueExW(
            key.0,
            value_name.as_ptr(),
            0,
            REG_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(classify_error(result));
    }
    if query_status(&key, &expected)? != DevAutostartStatus::Installed {
        return Err(DevAutostartError::NativeFailure);
    }
    Ok(true)
}

pub fn dev_autostart_status() -> Result<DevAutostartStatus, DevAutostartError> {
    let expected = expected_command()?;
    let key = open_run_key()?;
    query_status(&key, &expected)
}

pub fn remove_dev_autostart() -> Result<bool, DevAutostartError> {
    let expected = expected_command()?;
    let key = open_run_key()?;
    if query_status(&key, &expected)? == DevAutostartStatus::Absent {
        return Ok(false);
    }
    let value_name = wide_string(RUN_VALUE_NAME)?;
    // SAFETY: this deletes only the exact value under the current user's Run
    // key after its data was verified to match this executable and argument.
    let result = unsafe { RegDeleteValueW(key.0, value_name.as_ptr()) };
    match result {
        ERROR_SUCCESS => {}
        ERROR_FILE_NOT_FOUND => return Ok(false),
        other => return Err(classify_error(other)),
    }
    if query_status(&key, &expected)? != DevAutostartStatus::Absent {
        return Err(DevAutostartError::NativeFailure);
    }
    Ok(true)
}

fn open_run_key() -> Result<RegistryKey, DevAutostartError> {
    let subkey = wide_string(RUN_KEY)?;
    let mut key = null_mut();
    let mut disposition = 0_u32;
    // SAFETY: all output pointers are valid; the optional class and security
    // pointers are null. The returned current-user handle is wrapped once.
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            null(),
            &mut key,
            &mut disposition,
        )
    };
    if result == ERROR_SUCCESS && !key.is_null() {
        Ok(RegistryKey(key))
    } else {
        Err(classify_error(result))
    }
}

fn query_status(
    key: &RegistryKey,
    expected_command: &[u16],
) -> Result<DevAutostartStatus, DevAutostartError> {
    let value_name = wide_string(RUN_VALUE_NAME)?;
    let mut value_type = 0_u32;
    let mut byte_count = 0_u32;
    // SAFETY: the key and value name are live; this first query requests only
    // the bounded data size and type.
    let first = unsafe {
        RegQueryValueExW(
            key.0,
            value_name.as_ptr(),
            null(),
            &mut value_type,
            null_mut(),
            &mut byte_count,
        )
    };
    match first {
        ERROR_FILE_NOT_FOUND => return Ok(DevAutostartStatus::Absent),
        ERROR_SUCCESS => {}
        other => return Err(classify_error(other)),
    }
    let maximum_bytes = (MAX_RUN_COMMAND_UNITS + 1) * size_of::<u16>();
    let length =
        usize::try_from(byte_count).map_err(|_| DevAutostartError::InvalidConfiguration)?;
    if value_type != REG_SZ || length == 0 || length > maximum_bytes {
        return Err(DevAutostartError::InvalidConfiguration);
    }
    let mut actual = vec![0_u8; length];
    // SAFETY: `actual` has exactly the writable size supplied to Windows.
    let second = unsafe {
        RegQueryValueExW(
            key.0,
            value_name.as_ptr(),
            null(),
            &mut value_type,
            actual.as_mut_ptr(),
            &mut byte_count,
        )
    };
    if second != ERROR_SUCCESS {
        return Err(classify_error(second));
    }
    if value_type != REG_SZ || actual != wide_bytes(expected_command) {
        return Err(DevAutostartError::InvalidConfiguration);
    }
    Ok(DevAutostartStatus::Installed)
}

fn expected_command() -> Result<Vec<u16>, DevAutostartError> {
    let executable = std::env::current_exe().map_err(|_| DevAutostartError::NativeFailure)?;
    command_for_path(&executable)
}

fn command_for_path(path: &Path) -> Result<Vec<u16>, DevAutostartError> {
    let path_units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path_units.is_empty() || path_units.iter().any(|unit| matches!(*unit, 0 | 34)) {
        return Err(DevAutostartError::InvalidConfiguration);
    }
    let argument_units = AUTOSTART_ARGUMENT.encode_utf16();
    let mut command = Vec::with_capacity(path_units.len() + AUTOSTART_ARGUMENT.len() + 3);
    command.push(34);
    command.extend(path_units);
    command.push(34);
    command.extend(argument_units);
    if command.len() > MAX_RUN_COMMAND_UNITS {
        return Err(DevAutostartError::InvalidConfiguration);
    }
    command.push(0);
    Ok(command)
}

fn wide_string(value: &str) -> Result<Vec<u16>, DevAutostartError> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(DevAutostartError::InvalidConfiguration);
    }
    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    encoded.push(0);
    Ok(encoded)
}

fn wide_bytes(value: &[u16]) -> Vec<u8> {
    value.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn classify_error(error: u32) -> DevAutostartError {
    match error {
        ERROR_ACCESS_DENIED => DevAutostartError::AccessDenied,
        ERROR_INVALID_DATA | ERROR_INVALID_PARAMETER => DevAutostartError::InvalidConfiguration,
        _ => DevAutostartError::NativeFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_quoted_bounded_and_has_only_the_fixed_argument() {
        let command = command_for_path(Path::new(r"C:\synthetic path\aeterna.exe"))
            .unwrap_or_else(|error| panic!("synthetic path should be accepted: {error:?}"));
        let decoded = String::from_utf16(&command[..command.len() - 1])
            .unwrap_or_else(|error| panic!("command should be UTF-16: {error}"));
        assert_eq!(
            decoded,
            r#""C:\synthetic path\aeterna.exe" --i04-autostart-probe"#
        );
        assert!(command.len() <= MAX_RUN_COMMAND_UNITS + 1);
    }

    #[test]
    fn command_rejects_quote_injection_and_overlong_values() {
        assert_eq!(
            command_for_path(Path::new("C:\\bad\"path\\aeterna.exe")),
            Err(DevAutostartError::InvalidConfiguration)
        );
        let long = format!("C:\\{}\\aeterna.exe", "a".repeat(MAX_RUN_COMMAND_UNITS));
        assert_eq!(
            command_for_path(Path::new(&long)),
            Err(DevAutostartError::InvalidConfiguration)
        );
    }
}
