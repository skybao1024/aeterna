#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "windows")]
    if let Some(exit_code) = handle_i04_windows_action() {
        std::process::exit(exit_code);
    }

    if aeterna_lib::run().is_err() {
        eprintln!("Aeterna failed to start.");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn handle_i04_windows_action() -> Option<i32> {
    use aeterna_lib::windows_dev::{
        DevAutostartStatus, dev_autostart_status, install_dev_autostart, remove_dev_autostart,
    };

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let action = arguments.first()?;
    if action == "--i04-autostart-probe" {
        if arguments.len() == 1 && cfg!(feature = "activity-prototype") {
            return None;
        }
        eprintln!("i04_autostart_probe_failed=dev_autostart_invalid_configuration");
        return Some(2);
    }
    let result = match action.as_str() {
        "install-dev-autostart" if arguments.len() == 1 => {
            install_dev_autostart().map(|installed| println!("dev_autostart_installed={installed}"))
        }
        "status-dev-autostart" if arguments.len() == 1 => dev_autostart_status().map(|status| {
            println!(
                "dev_autostart_installed={}",
                status == DevAutostartStatus::Installed
            );
        }),
        "remove-dev-autostart" if arguments.len() == 1 => {
            remove_dev_autostart().map(|removed| println!("dev_autostart_removed={removed}"))
        }
        "install-dev-autostart" | "status-dev-autostart" | "remove-dev-autostart" => {
            eprintln!("i04_autostart_action_failed=dev_autostart_invalid_configuration");
            return Some(2);
        }
        _ => return None,
    };
    match result {
        Ok(()) => Some(0),
        Err(error) => {
            eprintln!("i04_autostart_action_failed={}", error.code());
            Some(1)
        }
    }
}
