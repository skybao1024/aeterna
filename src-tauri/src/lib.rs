pub mod activity;
pub mod crypto;
mod ipc;
pub mod secure_storage;
pub mod vault;
#[cfg(target_os = "windows")]
pub mod windows_dev;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> Result<(), tauri::Error> {
    let builder = tauri::Builder::default()
        .setup(|app| {
            let app_local_data_directory = app.path().app_local_data_dir()?;
            let vault_state = ipc::VaultAppState::load(&app_local_data_directory)
                .map_err(|_| std::io::Error::other("vault_startup_failed"))?;
            app.manage(vault_state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
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
        ]);

    #[cfg(feature = "activity-prototype")]
    {
        let app = builder.build(tauri::generate_context!())?;
        activity::prototype::run(app);
        Ok(())
    }

    #[cfg(not(feature = "activity-prototype"))]
    {
        builder.run(tauri::generate_context!())
    }
}
