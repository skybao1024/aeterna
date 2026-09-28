import { useTranslation } from "react-i18next";

export type RecoveryDeviceState =
  "pending" | "not_enrolled" | "complete" | "excluded";

export interface RecoveryDeviceStatus {
  deviceId: string;
  label: string;
  state: RecoveryDeviceState;
}

export type RecoveryProtectionState =
  | { kind: "not_configured" }
  | { kind: "cooling_down"; readyAt: string }
  | { kind: "rekey_required" }
  | { kind: "partial"; devices: RecoveryDeviceStatus[] }
  | { kind: "protected" };

export function RecoveryStatusPanel({
  state,
}: {
  state: RecoveryProtectionState;
}) {
  const { t } = useTranslation();
  const urgent = state.kind === "rekey_required" || state.kind === "partial";

  return (
    <section
      aria-labelledby="recovery-status-heading"
      className={`rounded-xl border px-4 py-3 text-sm leading-6 lg:col-span-2 ${
        urgent
          ? "border-red-400/30 bg-red-400/10 text-red-100"
          : "border-white/10 bg-white/[0.035] text-stone-300"
      }`}
    >
      <h2 id="recovery-status-heading" className="font-medium text-stone-100">
        {t("recovery.heading")}
      </h2>
      <p>{t(`recovery.states.${state.kind}`)}</p>
      {state.kind === "cooling_down" ? (
        <p className="text-xs text-stone-400">
          {t("recovery.readyAt", { date: state.readyAt })}
        </p>
      ) : null}
      {state.kind === "partial" ? (
        <ul className="mt-2 space-y-1" aria-label={t("recovery.deviceList")}>
          {state.devices.map((device) => (
            <li key={device.deviceId} className="flex justify-between gap-3">
              <span>{device.label}</span>
              <span>{t(`recovery.deviceStates.${device.state}`)}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
