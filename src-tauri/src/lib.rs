use serde::{Deserialize, Serialize};

pub mod activity;
pub mod crypto;
pub mod secure_storage;
pub mod vault;
#[cfg(target_os = "windows")]
pub mod windows_dev;

const MAX_DISPLAY_NAME_CHARACTERS: usize = 64;
const EMPTY_DISPLAY_NAME_ERROR: &str = "The display name must not be empty.";
const LONG_DISPLAY_NAME_ERROR: &str = "The display name is too long.";
const CONTROL_CHARACTER_ERROR: &str = "The display name contains an invalid character.";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FoundationRequest {
    display_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundationResponse {
    status: &'static str,
    display_name: String,
}

fn validate_display_name(display_name: &str) -> Result<&str, &'static str> {
    let normalized = display_name.trim();
    if normalized.is_empty() {
        return Err(EMPTY_DISPLAY_NAME_ERROR);
    }
    if normalized.chars().count() > MAX_DISPLAY_NAME_CHARACTERS {
        return Err(LONG_DISPLAY_NAME_ERROR);
    }
    if normalized.chars().any(char::is_control) {
        return Err(CONTROL_CHARACTER_ERROR);
    }
    Ok(normalized)
}

#[tauri::command]
fn check_desktop_foundation(
    request: FoundationRequest,
) -> Result<FoundationResponse, &'static str> {
    let display_name = validate_display_name(&request.display_name)?;
    Ok(FoundationResponse {
        status: "ready",
        display_name: display_name.to_owned(),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> Result<(), tauri::Error> {
    let builder = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![check_desktop_foundation]);

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

#[cfg(test)]
mod tests {
    use super::{
        CONTROL_CHARACTER_ERROR, EMPTY_DISPLAY_NAME_ERROR, FoundationRequest,
        LONG_DISPLAY_NAME_ERROR, check_desktop_foundation,
    };

    #[test]
    fn accepts_a_bounded_display_name() {
        let result = check_desktop_foundation(FoundationRequest {
            display_name: "  Contributor  ".to_owned(),
        });

        match result {
            Ok(response) => {
                assert_eq!(response.status, "ready");
                assert_eq!(response.display_name, "Contributor");
            }
            Err(error) => panic!("expected a valid response, received: {error}"),
        }
    }

    #[test]
    fn rejects_an_empty_display_name_with_a_safe_error() {
        let result = check_desktop_foundation(FoundationRequest {
            display_name: "   ".to_owned(),
        });

        assert!(matches!(result, Err(EMPTY_DISPLAY_NAME_ERROR)));
    }

    #[test]
    fn rejects_an_overlong_display_name_with_a_safe_error() {
        let result = check_desktop_foundation(FoundationRequest {
            display_name: "a".repeat(65),
        });

        assert!(matches!(result, Err(LONG_DISPLAY_NAME_ERROR)));
    }

    #[test]
    fn rejects_control_characters_with_a_safe_error() {
        let result = check_desktop_foundation(FoundationRequest {
            display_name: "Contributor\nInjected".to_owned(),
        });

        assert!(matches!(result, Err(CONTROL_CHARACTER_ERROR)));
    }
}
