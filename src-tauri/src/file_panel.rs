use std::path::PathBuf;

use objc2::MainThreadMarker;
use objc2_app_kit::{NSModalResponseOK, NSOpenPanel, NSSavePanel};
use objc2_foundation::{NSArray, NSString};

pub(crate) enum PanelOutcome {
    Selected(PathBuf),
    Cancelled,
}

pub(crate) fn choose_export() -> Result<PanelOutcome, ()> {
    let marker = MainThreadMarker::new().ok_or(())?;
    let panel = NSSavePanel::savePanel(marker);
    configure_types(&panel);
    panel.setAllowsOtherFileTypes(false);
    panel.setCanCreateDirectories(true);
    panel.setExtensionHidden(false);
    panel.setNameFieldStringValue(&NSString::from_str("vault.aeterna-vault"));
    finish_panel(panel.runModal(), panel.URL())
}

pub(crate) fn choose_import() -> Result<PanelOutcome, ()> {
    let marker = MainThreadMarker::new().ok_or(())?;
    let panel = NSOpenPanel::openPanel(marker);
    configure_types(&panel);
    panel.setCanChooseFiles(true);
    panel.setCanChooseDirectories(false);
    panel.setAllowsMultipleSelection(false);
    panel.setResolvesAliases(false);
    finish_panel(panel.runModal(), panel.URL())
}

#[allow(deprecated)]
fn configure_types(panel: &NSSavePanel) {
    let extension = NSString::from_str("aeterna-vault");
    let types = NSArray::from_slice(&[&*extension]);
    panel.setAllowedFileTypes(Some(&types));
}

fn finish_panel(
    response: objc2_app_kit::NSModalResponse,
    url: Option<objc2::rc::Retained<objc2_foundation::NSURL>>,
) -> Result<PanelOutcome, ()> {
    if response != NSModalResponseOK {
        return Ok(PanelOutcome::Cancelled);
    }
    let url = url.ok_or(())?;
    if !url.isFileURL() {
        return Err(());
    }
    url.to_file_path().map(PanelOutcome::Selected).ok_or(())
}
