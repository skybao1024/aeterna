pub mod activity;
pub mod crypto;
#[cfg(target_os = "macos")]
mod file_panel;
pub mod heartbeat;
mod ipc;
#[cfg(target_os = "macos")]
mod lifecycle;
pub mod protocol;
pub mod recovery;
pub mod secure_storage;
pub mod vault;
#[cfg(target_os = "windows")]
pub mod windows_dev;

use tauri::Manager;

macro_rules! invoke_commands {
    ($($lifecycle:path),* $(,)?) => {
        tauri::generate_handler![
            ipc::vault_status,
            ipc::vault_initialize,
            ipc::vault_unlock,
            ipc::vault_lock,
            ipc::vault_list_items,
            ipc::vault_get_item,
            ipc::vault_create_item,
            ipc::vault_update_item,
            ipc::vault_delete_item,
            ipc::vault_prepare_attachment,
            ipc::vault_commit_attachment,
            ipc::vault_cancel_attachment,
            ipc::vault_read_attachment,
            ipc::vault_remove_attachment,
            ipc::vault_export_choose,
            ipc::vault_export_start,
            ipc::vault_import_choose,
            ipc::vault_import_start,
            ipc::vault_transfer_status,
            ipc::vault_transfer_cancel,
            $($lifecycle,)*
        ]
    };
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> Result<(), tauri::Error> {
    let builder = tauri::Builder::default().setup(|app| {
        let app_local_data_directory = app.path().app_local_data_dir()?;
        let vault_state = ipc::VaultAppState::load(&app_local_data_directory)
            .map_err(|_| std::io::Error::other("vault_startup_failed"))?;
        app.manage(vault_state);
        #[cfg(not(target_os = "macos"))]
        if let Some(window) = app.get_webview_window("main") {
            window.show()?;
        }
        #[cfg(target_os = "macos")]
        app.manage(lifecycle::LifecycleAppState::load(
            &app_local_data_directory,
        ));
        Ok(())
    });

    #[cfg(target_os = "macos")]
    let builder = builder.invoke_handler(invoke_commands![
        lifecycle::lifecycle_status,
        lifecycle::lifecycle_set_autostart,
        lifecycle::lifecycle_request_notification_permission,
        lifecycle::lifecycle_set_locale,
        lifecycle::lifecycle_reset_health_state,
    ]);
    #[cfg(not(target_os = "macos"))]
    let builder = builder.invoke_handler(invoke_commands![]);

    #[cfg(feature = "activity-prototype")]
    {
        let app = builder.build(tauri::generate_context!())?;
        activity::prototype::run(app);
        Ok(())
    }

    #[cfg(not(feature = "activity-prototype"))]
    {
        #[cfg(target_os = "macos")]
        {
            let app = builder.build(tauri::generate_context!())?;
            let mut runtime = None;
            app.run(move |app, event| {
                // Tauri executes `Builder::setup` immediately before it
                // delivers `Ready`; managed state does not exist earlier.
                if should_start_macos_runtime(runtime.is_some(), &event) {
                    match lifecycle::runtime::MacAppRuntime::start(app) {
                        Ok(started) => runtime = Some(started),
                        Err(_) => {
                            eprintln!("Aeterna lifecycle runtime failed to start.");
                            app.exit(1);
                            return;
                        }
                    }
                }
                if let Some(runtime) = runtime.as_mut() {
                    runtime.handle(app, event);
                }
            });
            Ok(())
        }

        #[cfg(not(target_os = "macos"))]
        {
            builder.run(tauri::generate_context!())
        }
    }
}

#[cfg(all(target_os = "macos", not(feature = "activity-prototype")))]
fn should_start_macos_runtime(runtime_started: bool, event: &tauri::RunEvent) -> bool {
    !runtime_started && matches!(event, tauri::RunEvent::Ready)
}

#[cfg(all(test, target_os = "macos", not(feature = "activity-prototype")))]
mod macos_runtime_start_tests {
    use super::*;

    #[test]
    fn lifecycle_runtime_starts_only_on_the_first_ready_event() {
        assert!(should_start_macos_runtime(false, &tauri::RunEvent::Ready));
        assert!(!should_start_macos_runtime(true, &tauri::RunEvent::Ready));
        assert!(!should_start_macos_runtime(false, &tauri::RunEvent::Exit));
    }
}
