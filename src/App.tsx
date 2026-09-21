import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "./components/ui/button";
import { DEFAULT_LOCALE, persistLocale, type SupportedLocale } from "./i18n";
import { checkDesktopFoundation } from "./lib/ipc";

type IpcState =
  | { phase: "checking" }
  | { phase: "ready"; displayName: string }
  | { phase: "unavailable" };

export function App() {
  const { i18n, t } = useTranslation();
  const [ipcState, setIpcState] = useState<IpcState>({ phase: "checking" });

  const currentLocale: SupportedLocale =
    i18n.resolvedLanguage === "zh-CN" ? "zh-CN" : DEFAULT_LOCALE;
  const nextLocale: SupportedLocale =
    currentLocale === DEFAULT_LOCALE ? "zh-CN" : DEFAULT_LOCALE;

  useEffect(() => {
    document.documentElement.lang = currentLocale;
    document.title = t("app.windowTitle");
  }, [currentLocale, t]);

  useEffect(() => {
    let active = true;

    void checkDesktopFoundation({ displayName: t("ipc.contributor") })
      .then((response) => {
        if (active) {
          setIpcState({ phase: "ready", displayName: response.displayName });
        }
      })
      .catch(() => {
        if (active) {
          setIpcState({ phase: "unavailable" });
        }
      });

    return () => {
      active = false;
    };
  }, [currentLocale, t]);

  const switchLocale = async () => {
    await i18n.changeLanguage(nextLocale);
    persistLocale(window.localStorage, nextLocale);
  };

  const ipcMessage =
    ipcState.phase === "ready"
      ? t("ipc.ready", { name: ipcState.displayName })
      : t(`ipc.${ipcState.phase}`);

  return (
    <main className="relative isolate min-h-screen overflow-hidden bg-stone-950 px-6 py-8 text-stone-100 sm:px-10">
      <div
        aria-hidden="true"
        className="absolute inset-x-0 top-0 -z-10 h-96 bg-[radial-gradient(circle_at_top_left,rgba(245,158,11,0.22),transparent_46%),radial-gradient(circle_at_70%_0%,rgba(120,113,108,0.3),transparent_38%)]"
      />

      <div className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-5xl flex-col">
        <header className="flex items-center justify-between border-b border-white/10 pb-5">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-full border border-amber-300/30 bg-amber-300/10 font-serif text-lg text-amber-100">
              A
            </span>
            <span className="font-serif text-lg tracking-wide">
              {t("app.brand")}
            </span>
          </div>
          <Button
            aria-label={t("locale.switchLabel")}
            variant="secondary"
            onClick={() => void switchLocale()}
          >
            {t("locale.switch")}
          </Button>
        </header>

        <section className="grid flex-1 items-center gap-12 py-16 lg:grid-cols-[1.35fr_0.65fr]">
          <div>
            <p className="mb-5 text-xs font-semibold uppercase tracking-[0.24em] text-amber-200/75">
              {t("app.eyebrow")}
            </p>
            <h1 className="max-w-3xl font-serif text-5xl leading-[1.06] tracking-tight text-stone-50 sm:text-6xl">
              {t("app.title")}
            </h1>
            <p className="mt-7 max-w-2xl text-base leading-7 text-stone-300 sm:text-lg">
              {t("app.description")}
            </p>
          </div>

          <aside className="rounded-3xl border border-white/10 bg-white/[0.045] p-6 shadow-2xl shadow-black/20 backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-stone-400">
              {t("foundation.label")}
            </p>
            <ul className="mt-5 space-y-4 text-sm text-stone-200">
              {(["local", "permissions", "toolchain"] as const).map((item) => (
                <li key={item} className="flex items-center gap-3">
                  <span
                    aria-hidden="true"
                    className="size-1.5 rounded-full bg-amber-300"
                  />
                  {t(`foundation.items.${item}`)}
                </li>
              ))}
            </ul>
            <div className="mt-7 border-t border-white/10 pt-5">
              <p className="text-xs uppercase tracking-[0.16em] text-stone-500">
                {t("ipc.label")}
              </p>
              <p aria-live="polite" className="mt-2 text-sm text-stone-300">
                {ipcMessage}
              </p>
            </div>
          </aside>
        </section>

        <footer className="flex items-center justify-between border-t border-white/10 py-5 text-xs text-stone-500">
          <span>{t("locale.current")}</span>
          <span aria-hidden="true">{t("foundation.iteration")}</span>
        </footer>
      </div>
    </main>
  );
}
