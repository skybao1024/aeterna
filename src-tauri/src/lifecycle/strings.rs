#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Locale {
    En,
    ZhCn,
}

impl Locale {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }

    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::En => 0,
            Self::ZhCn => 1,
        }
    }

    pub(crate) const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::En),
            1 => Some(Self::ZhCn),
            _ => None,
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "en" => Some(Self::En),
            "zh-CN" => Some(Self::ZhCn),
            _ => None,
        }
    }
}

#[cfg(any(test, target_os = "macos"))]
pub(crate) struct NativeStrings {
    pub(crate) status_ready: &'static str,
    pub(crate) status_gate_unavailable: &'static str,
    pub(crate) status_agent_error: &'static str,
    pub(crate) open: &'static str,
    pub(crate) lock: &'static str,
    pub(crate) quit: &'static str,
    pub(crate) notification_title: &'static str,
    pub(crate) notification_body: &'static str,
}

#[cfg(any(test, target_os = "macos"))]
pub(crate) const fn native_strings(locale: Locale) -> NativeStrings {
    match locale {
        Locale::En => NativeStrings {
            status_ready: "Activity agent ready",
            status_gate_unavailable: "Activity gate unavailable",
            status_agent_error: "Activity agent needs attention",
            open: "Open Aeterna",
            lock: "Lock Vault",
            quit: "Quit Aeterna",
            notification_title: "Aeterna needs attention",
            notification_body: "Open Aeterna to review background status.",
        },
        Locale::ZhCn => NativeStrings {
            status_ready: "活动代理已就绪",
            status_gate_unavailable: "活动门控不可用",
            status_agent_error: "活动代理需要处理",
            open: "打开 Aeterna",
            lock: "锁定保险箱",
            quit: "退出 Aeterna",
            notification_title: "Aeterna 需要处理",
            notification_body: "请打开 Aeterna 检查后台状态。",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_locales_are_exact_and_native_strings_are_complete() {
        assert_eq!(Locale::parse("en"), Some(Locale::En));
        assert_eq!(Locale::parse("zh-CN"), Some(Locale::ZhCn));
        assert_eq!(Locale::parse("zh"), None);
        for locale in [Locale::En, Locale::ZhCn] {
            let strings = native_strings(locale);
            for value in [
                strings.status_ready,
                strings.status_gate_unavailable,
                strings.status_agent_error,
                strings.open,
                strings.lock,
                strings.quit,
                strings.notification_title,
                strings.notification_body,
            ] {
                assert!(!value.trim().is_empty());
            }
        }
    }
}
