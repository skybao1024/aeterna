import i18next, { type i18n } from "i18next";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import zhCN from "./locales/zh-CN.json";

export const DEFAULT_LOCALE = "en" as const;
export const LOCALE_STORAGE_KEY = "aeterna.locale";
export const SUPPORTED_LOCALES = [DEFAULT_LOCALE, "zh-CN"] as const;

export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

const resources = {
  en: { translation: en },
  "zh-CN": { translation: zhCN },
} as const;

export function resolveSavedLocale(
  savedLocale: string | null,
): SupportedLocale {
  return SUPPORTED_LOCALES.includes(savedLocale as SupportedLocale)
    ? (savedLocale as SupportedLocale)
    : DEFAULT_LOCALE;
}

function readSavedLocale(storage: Pick<Storage, "getItem">): SupportedLocale {
  try {
    return resolveSavedLocale(storage.getItem(LOCALE_STORAGE_KEY));
  } catch {
    return DEFAULT_LOCALE;
  }
}

export function persistLocale(
  storage: Pick<Storage, "setItem">,
  locale: SupportedLocale,
): boolean {
  try {
    storage.setItem(LOCALE_STORAGE_KEY, locale);
    return true;
  } catch {
    return false;
  }
}

export function createI18n(storage: Pick<Storage, "getItem">): i18n {
  const instance = i18next.createInstance();
  void instance.use(initReactI18next).init({
    resources,
    lng: readSavedLocale(storage),
    fallbackLng: DEFAULT_LOCALE,
    supportedLngs: [...SUPPORTED_LOCALES],
    nonExplicitSupportedLngs: false,
    interpolation: { escapeValue: false },
    initAsync: false,
  });
  return instance;
}

export const i18nInstance = createI18n(window.localStorage);
