#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "macos")]
    if let Some(exit_code) = handle_i08_macos_gate_action() {
        std::process::exit(exit_code);
    }

    #[cfg(target_os = "windows")]
    if let Some(exit_code) = handle_i04_windows_action() {
        std::process::exit(exit_code);
    }

    if aeterna_lib::run().is_err() {
        eprintln!("Aeterna failed to start.");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn handle_i08_macos_gate_action() -> Option<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let action = match parse_i08_macos_gate_action(&arguments)? {
        Ok(action) => action,
        Err(()) => {
            eprintln!("i08_gate_probe_failed=invalid_arguments");
            return Some(2);
        }
    };

    #[cfg(not(feature = "i08-native-probe"))]
    {
        let _ = action;
        eprintln!("i08_gate_probe_failed=probe_feature_disabled");
        Some(2)
    }

    #[cfg(feature = "i08-native-probe")]
    {
        use aeterna_lib::activity::native_gate_probe;

        let result = match action {
            I08GateAction::Metadata => native_gate_probe::verify_metadata()
                .map(|()| println!("gate_metadata_valid=true"))
                .map_err(str::to_owned),
            I08GateAction::UpdateSameValue => native_gate_probe::update_same_value()
                .map(|()| println!("gate_update_verified=true"))
                .map_err(str::to_owned),
            I08GateAction::Delete => native_gate_probe::delete_exact().map(|deleted| {
                println!("gate_deleted={deleted},gate_not_found={}", !deleted);
            }),
        };
        match result {
            Ok(()) => Some(0),
            Err(error) => {
                eprintln!("i08_gate_probe_failed={error}");
                Some(1)
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I08GateAction {
    Metadata,
    UpdateSameValue,
    Delete,
}

#[cfg(target_os = "macos")]
fn parse_i08_macos_gate_action(arguments: &[String]) -> Option<Result<I08GateAction, ()>> {
    if arguments.first().map(String::as_str) != Some("--i08-gate-probe") {
        return None;
    }
    if arguments.len() != 2 {
        return Some(Err(()));
    }
    Some(match arguments[1].as_str() {
        "metadata" => Ok(I08GateAction::Metadata),
        "update-same-value" => Ok(I08GateAction::UpdateSameValue),
        "delete" => Ok(I08GateAction::Delete),
        _ => Err(()),
    })
}

#[cfg(all(test, target_os = "macos"))]
mod i08_gate_action_tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn ordinary_arguments_do_not_enter_the_probe() {
        assert_eq!(parse_i08_macos_gate_action(&arguments(&[])), None);
        assert_eq!(
            parse_i08_macos_gate_action(&arguments(&["--ordinary"])),
            None
        );
    }

    #[test]
    fn probe_accepts_only_fixed_actions_and_exact_arity() {
        assert_eq!(
            parse_i08_macos_gate_action(&arguments(&["--i08-gate-probe", "metadata"])),
            Some(Ok(I08GateAction::Metadata))
        );
        assert_eq!(
            parse_i08_macos_gate_action(&arguments(&["--i08-gate-probe", "update-same-value"])),
            Some(Ok(I08GateAction::UpdateSameValue))
        );
        assert_eq!(
            parse_i08_macos_gate_action(&arguments(&["--i08-gate-probe", "delete"])),
            Some(Ok(I08GateAction::Delete))
        );
        assert_eq!(
            parse_i08_macos_gate_action(&arguments(&["--i08-gate-probe"])),
            Some(Err(()))
        );
        assert_eq!(
            parse_i08_macos_gate_action(&arguments(&[
                "--i08-gate-probe",
                "metadata",
                "unexpected"
            ])),
            Some(Err(()))
        );
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
