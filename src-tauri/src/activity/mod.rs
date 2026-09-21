pub mod diagnostics;
pub mod observer;
pub mod policy;
#[cfg(any(all(feature = "activity-prototype", target_os = "windows"), test))]
mod windows_logic;

#[cfg(all(feature = "activity-prototype", target_os = "macos"))]
mod macos;

#[cfg(all(feature = "activity-prototype", target_os = "windows"))]
mod windows;

#[cfg(feature = "activity-prototype")]
pub mod prototype;
