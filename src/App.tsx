import {
  type ChangeEvent,
  type ReactNode,
  type SyntheticEvent,
  useEffect,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";

import { Button } from "./components/ui/button";
import { DEFAULT_LOCALE, persistLocale, type SupportedLocale } from "./i18n";
import {
  cancelAttachment,
  cancelTransfer,
  chooseVaultExport,
  chooseVaultImport,
  commitAttachment,
  createItem,
  deleteItem,
  getItem,
  getTransferStatus,
  getVaultStatus,
  initializeVault,
  type ItemDraft,
  type ItemSummary,
  listItems,
  lockVault,
  MAX_ATTACHMENT_BYTES,
  prepareAttachment,
  readAttachment,
  removeAttachment,
  startVaultExport,
  startVaultImport,
  type TransferStatus,
  unlockVault,
  updateItem,
  type VaultItem,
  VaultIpcError,
} from "./lib/ipc";

type AppPhase =
  "checking" | "unavailable" | "uninitialized" | "locked" | "unlocked";

interface ConfirmDialogState {
  title: string;
  description: string;
  confirmLabel: string;
  destructive: boolean;
  action: () => void;
  alternateLabel?: string;
  alternateAction?: () => void;
}

interface AttachmentTarget {
  operation: "add" | "replace";
  attachmentId?: string;
}

interface AttachmentPreview {
  filename: string;
  content: string;
  format: "text" | "hex";
  truncated: boolean;
}

interface ActiveTransfer {
  operationId: string;
  status: TransferStatus;
}

const INITIAL_TRANSFER_STATUS: TransferStatus = {
  kind: "export",
  state: "running",
  phase: "preparing",
  bytesProcessed: "0",
  entriesProcessed: "0",
  cancellable: true,
};

const EMPTY_DRAFT: ItemDraft = {
  kind: "note",
  title: "",
  category: "",
  contactExplanation: "",
  body: "",
};

export function App() {
  const { i18n, t } = useTranslation();
  const [phase, setPhase] = useState<AppPhase>("checking");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [activeItem, setActiveItem] = useState<VaultItem | null>(null);
  const [draft, setDraft] = useState<ItemDraft>(EMPTY_DRAFT);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState<ConfirmDialogState | null>(
    null,
  );
  const [attachmentTarget, setAttachmentTarget] =
    useState<AttachmentTarget | null>(null);
  const [preview, setPreview] = useState<AttachmentPreview | null>(null);
  const [activeTransfer, setActiveTransfer] = useState<ActiveTransfer | null>(
    null,
  );
  const [lastExportAt, setLastExportAt] = useState<Date | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const confirmationInvokerRef = useRef<HTMLElement | null>(null);
  const lockingRef = useRef(false);
  const sessionEpoch = useRef(0);

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
    const epoch = sessionEpoch.current;
    const isCurrentSession = () => active && epoch === sessionEpoch.current;
    void getVaultStatus()
      .then(async (state) => {
        if (!isCurrentSession()) return;
        setPhase(state);
        if (state === "unlocked") {
          const nextItems = await listItems();
          if (isCurrentSession()) setItems(nextItems);
        }
      })
      .catch((error: unknown) => {
        if (!isCurrentSession()) return;
        setErrorCode(errorCodeFrom(error));
        setPhase("unavailable");
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!dirty) return;
    const preventClose = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", preventClose);
    return () => {
      window.removeEventListener("beforeunload", preventClose);
    };
  }, [dirty]);

  useEffect(() => {
    if (!activeTransfer || isTerminalTransfer(activeTransfer.status.state)) {
      return;
    }
    let active = true;
    const timer = window.setTimeout(() => {
      void getTransferStatus(activeTransfer.operationId)
        .then((status) => {
          if (!active) return;
          setActiveTransfer({
            operationId: activeTransfer.operationId,
            status,
          });
          if (status.state === "completed") {
            if (status.kind === "import") {
              sessionEpoch.current += 1;
              setActiveItem(null);
              setDraft(EMPTY_DRAFT);
              setDirty(false);
              setPreview(null);
              setAttachmentTarget(null);
              setItems([]);
              setPassword("");
              setPasswordConfirmation("");
              setPhase("locked");
            } else {
              setLastExportAt(new Date());
            }
          } else if (status.state === "failed" && status.errorCode) {
            setErrorCode(status.errorCode);
          }
        })
        .catch((error: unknown) => {
          if (active) setErrorCode(errorCodeFrom(error));
        });
    }, 250);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [activeTransfer]);

  const loadSummaries = async () => {
    const epoch = sessionEpoch.current;
    const nextItems = await listItems();
    if (epoch === sessionEpoch.current) setItems(nextItems);
  };

  const runBusy = async (operation: () => Promise<void>) => {
    const epoch = sessionEpoch.current;
    setBusy(true);
    setErrorCode(null);
    try {
      await operation();
      return true;
    } catch (error) {
      if (epoch === sessionEpoch.current) setErrorCode(errorCodeFrom(error));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const clearEditor = () => {
    setActiveItem(null);
    setDraft(EMPTY_DRAFT);
    setDirty(false);
    setPreview(null);
    setAttachmentTarget(null);
  };

  const clearUnlockedContent = () => {
    clearEditor();
    setItems([]);
    setPassword("");
    setPasswordConfirmation("");
  };

  const submitPassword = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (phase === "uninitialized" && password !== passwordConfirmation) {
      setErrorCode("ui_password_mismatch");
      return;
    }
    const submittedPassword = password;
    setPassword("");
    setPasswordConfirmation("");
    void runBusy(async () => {
      if (phase === "uninitialized") await initializeVault(submittedPassword);
      else await unlockVault(submittedPassword);
      setPhase("unlocked");
      await loadSummaries();
    });
  };

  const openConfirmation = (
    dialog: Omit<ConfirmDialogState, "action" | "alternateAction">,
    action: () => void,
    alternateAction?: () => void,
  ) => {
    confirmationInvokerRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    setConfirmDialog({ ...dialog, action, alternateAction });
  };

  const closeConfirmation = (action?: () => void) => {
    const invoker = confirmationInvokerRef.current;
    confirmationInvokerRef.current = null;
    setConfirmDialog(null);
    action?.();
    window.setTimeout(() => {
      if (invoker?.isConnected) invoker.focus();
    }, 0);
  };

  const persistDraft = async (): Promise<boolean> => {
    if (!dirty || busy) return false;
    const epoch = sessionEpoch.current;
    const saved = await runBusy(async () => {
      const saved = activeItem
        ? await updateItem(activeItem.itemId, activeItem.revision, draft)
        : await createItem(draft);
      if (epoch !== sessionEpoch.current) return;
      setActiveItem(saved);
      setDraft(draftFromItem(saved));
      setDirty(false);
      await loadSummaries();
    });
    return saved && epoch === sessionEpoch.current;
  };

  const withDiscardConfirmation = (action: () => void) => {
    if (!dirty) {
      action();
      return;
    }
    openConfirmation(
      {
        title: t("confirm.unsavedTitle"),
        description: t("confirm.unsavedDescription"),
        confirmLabel: t("confirm.discard"),
        destructive: false,
        alternateLabel: t("actions.save"),
      },
      action,
      () => {
        void persistDraft().then((saved) => {
          if (saved) action();
        });
      },
    );
  };

  const switchLocale = () => {
    withDiscardConfirmation(() => {
      clearEditor();
      void i18n.changeLanguage(nextLocale).then(() => {
        persistLocale(window.localStorage, nextLocale);
      });
    });
  };

  const performLock = () => {
    if (lockingRef.current) return;
    lockingRef.current = true;
    sessionEpoch.current += 1;
    clearUnlockedContent();
    setBusy(true);
    setErrorCode(null);
    setPhase("checking");
    void lockVault()
      .then(() => {
        setPhase("locked");
      })
      .catch((error: unknown) => {
        setErrorCode(errorCodeFrom(error));
        setPhase("unavailable");
      })
      .finally(() => {
        lockingRef.current = false;
        setBusy(false);
      });
  };

  const chooseExport = () => {
    withDiscardConfirmation(() => {
      if (dirty) clearEditor();
      void runBusy(async () => {
        const selection = await chooseVaultExport();
        if (selection.outcome === "cancelled") return;
        openConfirmation(
          {
            title: t("transfer.exportConfirmTitle"),
            description: t("transfer.exportConfirmDescription"),
            confirmLabel: t("actions.exportVault"),
            destructive: false,
          },
          () => {
            void runBusy(async () => {
              const operationId = await startVaultExport(selection.selectionId);
              setActiveTransfer({
                operationId,
                status: INITIAL_TRANSFER_STATUS,
              });
            });
          },
        );
      });
    });
  };

  const chooseImport = () => {
    if (!password) {
      setErrorCode("vault_invalid_input");
      return;
    }
    const submittedPassword = password;
    void runBusy(async () => {
      const selection = await chooseVaultImport();
      if (selection.outcome === "cancelled") return;
      openConfirmation(
        {
          title: t("transfer.importConfirmTitle"),
          description: t("transfer.importConfirmDescription"),
          confirmLabel: t("actions.importVault"),
          destructive: false,
        },
        () => {
          setPassword("");
          setPasswordConfirmation("");
          void runBusy(async () => {
            const operationId = await startVaultImport(
              selection.selectionId,
              submittedPassword,
            );
            setActiveTransfer({
              operationId,
              status: {
                ...INITIAL_TRANSFER_STATUS,
                kind: "import",
                phase: "copying",
              },
            });
          });
        },
      );
    });
  };

  const cancelActiveTransfer = () => {
    if (!activeTransfer?.status.cancellable) return;
    void cancelTransfer(activeTransfer.operationId)
      .then(() => {
        setActiveTransfer((current) =>
          current
            ? {
                ...current,
                status: {
                  ...current.status,
                  state: "cancelling",
                  phase: "cancelling",
                  cancellable: false,
                },
              }
            : null,
        );
      })
      .catch((error: unknown) => {
        setErrorCode(errorCodeFrom(error));
      });
  };

  const startNewItem = () => {
    withDiscardConfirmation(() => {
      setActiveItem(null);
      setDraft(EMPTY_DRAFT);
      setDirty(true);
      setPreview(null);
      setErrorCode(null);
    });
  };

  const openItem = (itemId: string) => {
    withDiscardConfirmation(() => {
      clearEditor();
      const epoch = sessionEpoch.current;
      void runBusy(async () => {
        const item = await getItem(itemId);
        if (epoch !== sessionEpoch.current) return;
        setActiveItem(item);
        setDraft(draftFromItem(item));
        setDirty(false);
        setPreview(null);
      });
    });
  };

  const saveDraft = () => {
    void persistDraft();
  };

  const updateDraft = <Key extends keyof ItemDraft>(
    key: Key,
    value: ItemDraft[Key],
  ) => {
    setDraft((current) => {
      const next = { ...current, [key]: value };
      if (key === "kind" && value === "note") next.contactExplanation = "";
      return next;
    });
    setDirty(true);
  };

  const requestDelete = () => {
    if (!activeItem || busy) return;
    openConfirmation(
      {
        title: t("confirm.deleteTitle"),
        description: t("confirm.deleteDescription"),
        confirmLabel: t("confirm.delete"),
        destructive: true,
      },
      () => {
        void runBusy(async () => {
          await deleteItem(activeItem.itemId, activeItem.revision);
          clearEditor();
          await loadSummaries();
        });
      },
    );
  };

  const chooseAttachment = (target: AttachmentTarget) => {
    if (!activeItem || dirty || busy) return;
    setAttachmentTarget(target);
    fileInputRef.current?.click();
  };

  const attachSelectedFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    const target = attachmentTarget;
    setAttachmentTarget(null);
    if (!file || !target || !activeItem || dirty) return;
    if (file.size > MAX_ATTACHMENT_BYTES) {
      setErrorCode("vault_attachment_too_large");
      return;
    }
    const itemAtStart = activeItem;
    const epoch = sessionEpoch.current;
    void runBusy(async () => {
      let uploadId: string | null = null;
      let bytes: Uint8Array | null = null;
      try {
        uploadId = await prepareAttachment({
          itemId: itemAtStart.itemId,
          expectedRevision: itemAtStart.revision,
          operation: target.operation,
          ...(target.attachmentId ? { attachmentId: target.attachmentId } : {}),
          filename: file.name,
          mediaType: file.type,
          byteLength: file.size.toString(),
        });
        if (epoch !== sessionEpoch.current) return;
        bytes = new Uint8Array(await file.arrayBuffer());
        if (epoch !== sessionEpoch.current) return;
        const updated = await commitAttachment(uploadId, bytes);
        uploadId = null;
        if (epoch !== sessionEpoch.current) return;
        setActiveItem(updated);
        setDraft(draftFromItem(updated));
        await loadSummaries();
      } finally {
        bytes?.fill(0);
        if (uploadId) {
          try {
            await cancelAttachment(uploadId);
          } catch {
            // The one-shot descriptor may already have been consumed.
          }
        }
      }
    });
  };

  const inspectAttachment = (attachmentId: string, filename: string) => {
    if (!activeItem || dirty || busy) return;
    const itemAtStart = activeItem;
    const epoch = sessionEpoch.current;
    void runBusy(async () => {
      const bytes = await readAttachment(
        itemAtStart.itemId,
        attachmentId,
        itemAtStart.revision,
      );
      try {
        const nextPreview = buildPreview(filename, bytes);
        if (epoch === sessionEpoch.current) setPreview(nextPreview);
      } finally {
        bytes.fill(0);
      }
    });
  };

  const removeSelectedAttachment = (attachmentId: string) => {
    if (!activeItem || dirty || busy) return;
    const itemAtStart = activeItem;
    const epoch = sessionEpoch.current;
    void runBusy(async () => {
      const updated = await removeAttachment(
        itemAtStart.itemId,
        attachmentId,
        itemAtStart.revision,
      );
      if (epoch !== sessionEpoch.current) return;
      setActiveItem(updated);
      setDraft(draftFromItem(updated));
      setPreview(null);
      await loadSummaries();
    });
  };

  const errorMessage = errorCode ? localizedError(t, errorCode) : null;

  return (
    <main className="min-h-screen bg-stone-950 text-stone-100">
      <header className="border-b border-white/10 bg-stone-950/95 px-5 py-4">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span
              aria-hidden="true"
              className="grid size-9 place-items-center rounded-full border border-amber-300/30 bg-amber-300/10 font-serif text-lg text-amber-100"
            >
              A
            </span>
            <div>
              <p className="font-serif text-lg tracking-wide">
                {t("app.brand")}
              </p>
              <p className="text-xs text-stone-500">{t("app.previewLabel")}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {phase === "unlocked" ? (
              <>
                <Button
                  variant="secondary"
                  disabled={busy || activeTransfer !== null}
                  onClick={chooseExport}
                >
                  {t("actions.exportVault")}
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => {
                    withDiscardConfirmation(performLock);
                  }}
                >
                  {t("actions.lock")}
                </Button>
              </>
            ) : null}
            <Button
              aria-label={t("locale.switchLabel")}
              variant="secondary"
              disabled={busy}
              onClick={switchLocale}
            >
              {t("locale.switch")}
            </Button>
          </div>
        </div>
      </header>

      {errorMessage ? (
        <div
          role="alert"
          className="mx-auto mt-4 max-w-7xl rounded-xl border border-red-400/30 bg-red-400/10 px-4 py-3 text-sm text-red-100"
        >
          {errorMessage}
        </div>
      ) : null}

      {phase === "checking" ? (
        <CenteredMessage>{t("status.checking")}</CenteredMessage>
      ) : null}
      {phase === "unavailable" ? (
        <CenteredMessage>{t("status.unavailable")}</CenteredMessage>
      ) : null}
      {phase === "uninitialized" || phase === "locked" ? (
        <PasswordPanel
          phase={phase}
          password={password}
          confirmation={passwordConfirmation}
          busy={busy}
          onPassword={setPassword}
          onConfirmation={setPasswordConfirmation}
          onSubmit={submitPassword}
          onImport={chooseImport}
        />
      ) : null}
      {phase === "unlocked" ? (
        <section className="mx-auto grid max-w-7xl gap-5 px-5 py-6 lg:grid-cols-[20rem_1fr]">
          <div
            role="note"
            className="rounded-xl border border-amber-300/25 bg-amber-300/10 px-4 py-3 text-sm leading-6 text-amber-100 lg:col-span-2"
          >
            {t("setup.warning")}
            {lastExportAt ? (
              <span className="mt-2 block text-xs text-amber-100/75">
                {t("transfer.lastExport", {
                  date: new Intl.DateTimeFormat(currentLocale, {
                    dateStyle: "medium",
                    timeStyle: "short",
                  }).format(lastExportAt),
                })}
              </span>
            ) : null}
          </div>
          <aside className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
            <div className="flex items-center justify-between gap-3">
              <h1 className="font-serif text-xl">{t("items.heading")}</h1>
              <Button disabled={busy} onClick={startNewItem}>
                {t("actions.newItem")}
              </Button>
            </div>
            {items.length === 0 ? (
              <p className="mt-6 text-sm text-stone-400">{t("items.empty")}</p>
            ) : (
              <ul className="mt-4 space-y-2" aria-label={t("items.listLabel")}>
                {items.map((item) => (
                  <li key={item.itemId}>
                    <button
                      type="button"
                      className="w-full rounded-xl border border-white/10 bg-stone-900/70 p-3 text-left transition hover:border-amber-300/40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-300"
                      onClick={() => {
                        openItem(item.itemId);
                      }}
                    >
                      <span className="block truncate font-medium">
                        {item.title}
                      </span>
                      <span className="mt-1 flex justify-between gap-2 text-xs text-stone-500">
                        <span>{t(`kinds.${item.kind}`)}</span>
                        <span>
                          {formatDate(item.updatedAtMs, currentLocale)}
                        </span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </aside>

          <section className="rounded-2xl border border-white/10 bg-white/[0.035] p-5 sm:p-7">
            {!dirty && !activeItem ? (
              <div className="grid min-h-96 place-items-center text-center text-stone-400">
                <div>
                  <p className="font-serif text-2xl text-stone-200">
                    {t("editor.emptyTitle")}
                  </p>
                  <p className="mt-2 text-sm">{t("editor.emptyDescription")}</p>
                </div>
              </div>
            ) : (
              <ItemEditor
                draft={draft}
                item={activeItem}
                dirty={dirty}
                busy={busy}
                locale={currentLocale}
                preview={preview}
                onDraft={updateDraft}
                onSave={saveDraft}
                onDelete={requestDelete}
                onChooseAttachment={chooseAttachment}
                onInspectAttachment={inspectAttachment}
                onRemoveAttachment={removeSelectedAttachment}
                onClosePreview={() => {
                  setPreview(null);
                }}
              />
            )}
          </section>
        </section>
      ) : null}

      <input
        ref={fileInputRef}
        className="sr-only"
        type="file"
        aria-label={t("attachments.fileInput")}
        onChange={attachSelectedFile}
      />

      {confirmDialog ? (
        <ConfirmDialog
          state={confirmDialog}
          onCancel={() => {
            closeConfirmation();
          }}
          onConfirm={() => {
            closeConfirmation(confirmDialog.action);
          }}
          onAlternate={
            confirmDialog.alternateAction
              ? () => {
                  closeConfirmation(confirmDialog.alternateAction);
                }
              : undefined
          }
        />
      ) : null}

      {activeTransfer ? (
        <TransferDialog
          transfer={activeTransfer}
          locale={currentLocale}
          onCancel={cancelActiveTransfer}
          onClose={() => {
            if (isTerminalTransfer(activeTransfer.status.state)) {
              setActiveTransfer(null);
            }
          }}
        />
      ) : null}
    </main>
  );
}

function PasswordPanel({
  phase,
  password,
  confirmation,
  busy,
  onPassword,
  onConfirmation,
  onSubmit,
  onImport,
}: {
  phase: "uninitialized" | "locked";
  password: string;
  confirmation: string;
  busy: boolean;
  onPassword: (value: string) => void;
  onConfirmation: (value: string) => void;
  onSubmit: (event: SyntheticEvent<HTMLFormElement>) => void;
  onImport: () => void;
}) {
  const { t } = useTranslation();
  const initializing = phase === "uninitialized";
  return (
    <section className="mx-auto grid min-h-[calc(100vh-6rem)] max-w-xl place-items-center px-5 py-10">
      <div className="w-full rounded-3xl border border-white/10 bg-white/[0.04] p-7 shadow-2xl shadow-black/30">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-200/75">
          {t("app.previewLabel")}
        </p>
        <h1 className="mt-3 font-serif text-3xl">
          {t(initializing ? "setup.title" : "unlock.title")}
        </h1>
        <p className="mt-3 text-sm leading-6 text-stone-400">
          {t(initializing ? "setup.description" : "unlock.description")}
        </p>
        {initializing ? (
          <div
            role="note"
            className="mt-5 rounded-xl border border-amber-300/25 bg-amber-300/10 p-4 text-sm leading-6 text-amber-100"
          >
            {t("setup.warning")}
          </div>
        ) : null}
        <form className="mt-6 space-y-4" onSubmit={onSubmit}>
          <label className="block">
            <span className="text-sm text-stone-300">
              {t("fields.password")}
            </span>
            <input
              autoComplete="off"
              className="mt-2 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 text-stone-100 outline-none focus:border-amber-300/60"
              type="password"
              required
              maxLength={1024}
              value={password}
              onChange={(event) => {
                onPassword(event.target.value);
              }}
            />
          </label>
          {initializing ? (
            <label className="block">
              <span className="text-sm text-stone-300">
                {t("fields.confirmPassword")}
              </span>
              <input
                autoComplete="off"
                className="mt-2 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 text-stone-100 outline-none focus:border-amber-300/60"
                type="password"
                required
                maxLength={1024}
                value={confirmation}
                onChange={(event) => {
                  onConfirmation(event.target.value);
                }}
              />
            </label>
          ) : null}
          <Button className="w-full" disabled={busy} type="submit">
            {t(initializing ? "actions.initialize" : "actions.unlock")}
          </Button>
          {initializing ? (
            <div className="border-t border-white/10 pt-4">
              <p className="text-xs leading-5 text-stone-400">
                {t("transfer.importWarning")}
              </p>
              <Button
                className="mt-3 w-full"
                disabled={busy || password.length === 0}
                type="button"
                variant="secondary"
                onClick={onImport}
              >
                {t("actions.importVault")}
              </Button>
            </div>
          ) : null}
        </form>
      </div>
    </section>
  );
}

function ItemEditor({
  draft,
  item,
  dirty,
  busy,
  locale,
  preview,
  onDraft,
  onSave,
  onDelete,
  onChooseAttachment,
  onInspectAttachment,
  onRemoveAttachment,
  onClosePreview,
}: {
  draft: ItemDraft;
  item: VaultItem | null;
  dirty: boolean;
  busy: boolean;
  locale: SupportedLocale;
  preview: AttachmentPreview | null;
  onDraft: <Key extends keyof ItemDraft>(
    key: Key,
    value: ItemDraft[Key],
  ) => void;
  onSave: () => void;
  onDelete: () => void;
  onChooseAttachment: (target: AttachmentTarget) => void;
  onInspectAttachment: (attachmentId: string, filename: string) => void;
  onRemoveAttachment: (attachmentId: string) => void;
  onClosePreview: () => void;
}) {
  const { t } = useTranslation();
  return (
    <form
      className="space-y-5"
      onSubmit={(event) => {
        event.preventDefault();
        onSave();
      }}
      onKeyDown={(event) => {
        if (
          (event.metaKey || event.ctrlKey) &&
          event.key.toLowerCase() === "s"
        ) {
          event.preventDefault();
          onSave();
        }
      }}
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-stone-500">
            {t(item ? "editor.editing" : "editor.creating")}
          </p>
          <h2 className="mt-1 font-serif text-2xl">
            {item ? item.title : t("editor.newTitle")}
          </h2>
          {item ? (
            <p className="mt-1 text-xs text-stone-500">
              {t("editor.updated", {
                date: formatDate(item.updatedAtMs, locale),
              })}
            </p>
          ) : null}
        </div>
        <div className="flex gap-2">
          {item ? (
            <Button
              type="button"
              variant="secondary"
              disabled={busy}
              onClick={onDelete}
            >
              {t("actions.delete")}
            </Button>
          ) : null}
          <Button type="submit" disabled={busy || !dirty}>
            {t("actions.save")}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block">
          <span className="text-sm text-stone-300">{t("fields.kind")}</span>
          <select
            className="mt-2 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 text-stone-100 outline-none focus:border-amber-300/60"
            value={draft.kind}
            onChange={(event) => {
              onDraft(
                "kind",
                event.target.value === "instruction" ? "instruction" : "note",
              );
            }}
          >
            <option value="note">{t("kinds.note")}</option>
            <option value="instruction">{t("kinds.instruction")}</option>
          </select>
        </label>
        <label className="block">
          <span className="text-sm text-stone-300">{t("fields.category")}</span>
          <input
            className="mt-2 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 text-stone-100 outline-none focus:border-amber-300/60"
            maxLength={128}
            value={draft.category}
            onChange={(event) => {
              onDraft("category", event.target.value);
            }}
          />
        </label>
      </div>

      <label className="block">
        <span className="text-sm text-stone-300">{t("fields.title")}</span>
        <input
          className="mt-2 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 text-stone-100 outline-none focus:border-amber-300/60"
          required
          maxLength={256}
          value={draft.title}
          onChange={(event) => {
            onDraft("title", event.target.value);
          }}
        />
      </label>

      {draft.kind === "instruction" ? (
        <label className="block">
          <span className="text-sm text-stone-300">
            {t("fields.contactExplanation")}
          </span>
          <textarea
            className="mt-2 min-h-28 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 text-stone-100 outline-none focus:border-amber-300/60"
            maxLength={8192}
            value={draft.contactExplanation}
            onChange={(event) => {
              onDraft("contactExplanation", event.target.value);
            }}
          />
        </label>
      ) : null}

      <label className="block">
        <span className="text-sm text-stone-300">{t("fields.body")}</span>
        <textarea
          className="mt-2 min-h-64 w-full rounded-xl border border-white/10 bg-stone-900 px-4 py-3 font-mono text-sm leading-6 text-stone-100 outline-none focus:border-amber-300/60"
          maxLength={131072}
          value={draft.body}
          onChange={(event) => {
            onDraft("body", event.target.value);
          }}
        />
      </label>

      <section
        className="border-t border-white/10 pt-5"
        aria-labelledby="attachments-heading"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 id="attachments-heading" className="font-medium">
              {t("attachments.heading")}
            </h3>
            <p className="mt-1 text-xs text-stone-500">
              {t("attachments.limit")}
            </p>
          </div>
          <Button
            type="button"
            variant="secondary"
            disabled={!item || dirty || busy || item.attachments.length >= 8}
            onClick={() => {
              onChooseAttachment({ operation: "add" });
            }}
          >
            {t("actions.addAttachment")}
          </Button>
        </div>
        {!item ? (
          <p className="mt-4 text-sm text-stone-400">
            {t("attachments.saveFirst")}
          </p>
        ) : dirty ? (
          <p className="mt-4 text-sm text-amber-200">
            {t("attachments.saveChangesFirst")}
          </p>
        ) : item.attachments.length === 0 ? (
          <p className="mt-4 text-sm text-stone-400">
            {t("attachments.empty")}
          </p>
        ) : (
          <ul className="mt-4 space-y-2">
            {item.attachments.map((attachment) => (
              <li
                key={attachment.attachmentId}
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 bg-stone-900/70 p-3"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">
                    {attachment.filename}
                  </p>
                  <p className="mt-1 text-xs text-stone-500">
                    {attachment.mediaType || t("attachments.unknownType")} ·{" "}
                    {formatBytes(attachment.byteLength, locale)}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={busy}
                    onClick={() => {
                      onInspectAttachment(
                        attachment.attachmentId,
                        attachment.filename,
                      );
                    }}
                  >
                    {t("actions.inspect")}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={busy}
                    onClick={() => {
                      onChooseAttachment({
                        operation: "replace",
                        attachmentId: attachment.attachmentId,
                      });
                    }}
                  >
                    {t("actions.replace")}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={busy}
                    onClick={() => {
                      onRemoveAttachment(attachment.attachmentId);
                    }}
                  >
                    {t("actions.remove")}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {preview ? (
        <section
          className="rounded-xl border border-white/10 bg-stone-900 p-4"
          aria-labelledby="preview-heading"
        >
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 id="preview-heading" className="font-medium">
                {t("attachments.previewTitle", { filename: preview.filename })}
              </h3>
              <p className="mt-1 text-xs text-stone-500">
                {t(
                  preview.format === "text"
                    ? "attachments.textPreview"
                    : "attachments.binaryPreview",
                )}
              </p>
            </div>
            <Button type="button" variant="secondary" onClick={onClosePreview}>
              {t("actions.close")}
            </Button>
          </div>
          <pre className="mt-4 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/30 p-3 text-xs leading-5 text-stone-300">
            {preview.content || t("attachments.emptyContent")}
          </pre>
          {preview.truncated ? (
            <p className="mt-2 text-xs text-amber-200">
              {t("attachments.previewTruncated")}
            </p>
          ) : null}
        </section>
      ) : null}
    </form>
  );
}

function ConfirmDialog({
  state,
  onCancel,
  onConfirm,
  onAlternate,
}: {
  state: ConfirmDialogState;
  onCancel: () => void;
  onConfirm: () => void;
  onAlternate?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-5">
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-description"
        className="w-full max-w-md rounded-2xl border border-white/10 bg-stone-900 p-6 shadow-2xl"
        onKeyDown={(event) => {
          if (event.key === "Escape") onCancel();
        }}
      >
        <h2 id="confirm-title" className="font-serif text-2xl">
          {state.title}
        </h2>
        <p
          id="confirm-description"
          className="mt-3 text-sm leading-6 text-stone-400"
        >
          {state.description}
        </p>
        <div className="mt-6 flex justify-end gap-3">
          <Button
            autoFocus
            type="button"
            variant="secondary"
            onClick={onCancel}
          >
            {t("actions.cancel")}
          </Button>
          {state.alternateLabel && onAlternate ? (
            <Button type="button" variant="secondary" onClick={onAlternate}>
              {state.alternateLabel}
            </Button>
          ) : null}
          <Button
            type="button"
            className={
              state.destructive
                ? "bg-red-600 text-white hover:bg-red-500"
                : undefined
            }
            onClick={onConfirm}
          >
            {state.confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

function TransferDialog({
  transfer,
  locale,
  onCancel,
  onClose,
}: {
  transfer: ActiveTransfer;
  locale: SupportedLocale;
  onCancel: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { status } = transfer;
  const terminal = isTerminalTransfer(status.state);
  const bytes = formatBytes(status.bytesProcessed, locale);
  const entries = new Intl.NumberFormat(locale).format(
    Number(status.entriesProcessed),
  );
  return (
    <div className="fixed inset-0 z-[60] grid place-items-center bg-black/75 p-5">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="transfer-title"
        aria-describedby="transfer-description"
        onKeyDown={(event) => {
          if (event.key !== "Escape") return;
          event.preventDefault();
          if (status.cancellable) onCancel();
          else if (terminal) onClose();
        }}
        className="w-full max-w-md rounded-2xl border border-white/10 bg-stone-900 p-6 shadow-2xl"
      >
        <h2 id="transfer-title" className="font-serif text-2xl">
          {t(`transfer.${status.kind}Title`)}
        </h2>
        <p
          id="transfer-description"
          className="mt-3 text-sm text-stone-400"
          aria-live="polite"
        >
          {t(`transfer.phases.${status.phase}`)}
        </p>
        <div className="mt-5 h-2 overflow-hidden rounded-full bg-white/10">
          <div
            className={`h-full bg-amber-300 transition-all ${terminal ? "w-full" : "w-2/3 animate-pulse"}`}
          />
        </div>
        <p className="mt-3 text-xs text-stone-500">
          {t("transfer.progress", { bytes, entries })}
        </p>
        <p className="sr-only" role="status" aria-live="polite">
          {t(`transfer.states.${status.state}`)}
        </p>
        <div className="mt-6 flex justify-end">
          {status.cancellable ? (
            <Button autoFocus variant="secondary" onClick={onCancel}>
              {t("actions.cancelTransfer")}
            </Button>
          ) : terminal ? (
            <Button autoFocus onClick={onClose}>
              {t("actions.close")}
            </Button>
          ) : (
            <Button variant="secondary" disabled>
              {t("transfer.states.cancelling")}
            </Button>
          )}
        </div>
      </section>
    </div>
  );
}

function CenteredMessage({ children }: { children: ReactNode }) {
  return (
    <section className="grid min-h-[calc(100vh-6rem)] place-items-center px-5 text-stone-400">
      <p role="status">{children}</p>
    </section>
  );
}

function isTerminalTransfer(state: TransferStatus["state"]): boolean {
  return state === "completed" || state === "cancelled" || state === "failed";
}

function draftFromItem(item: VaultItem): ItemDraft {
  return {
    kind: item.kind,
    title: item.title,
    category: item.category,
    contactExplanation: item.contactExplanation,
    body: item.body,
  };
}

function errorCodeFrom(error: unknown): string {
  return error instanceof VaultIpcError ? error.code : "ipc_unavailable";
}

function localizedError(t: (key: string) => string, code: string): string {
  const knownCodes = new Set([
    "crypto_authentication_failed",
    "crypto_randomness_unavailable",
    "ipc_invalid_request",
    "ipc_invalid_response",
    "ipc_unavailable",
    "ui_password_mismatch",
    "vault_already_initialized",
    "vault_attachment_not_found",
    "vault_attachment_too_large",
    "vault_busy",
    "vault_conflict",
    "vault_corrupt",
    "vault_internal_error",
    "vault_invalid_format",
    "vault_invalid_input",
    "vault_io_error",
    "vault_export_limit_exceeded",
    "vault_export_target_exists",
    "vault_import_invalid_package",
    "vault_import_limit_exceeded",
    "vault_import_target_exists",
    "vault_import_unsupported_version",
    "vault_item_invalid_format",
    "vault_item_unsupported_version",
    "vault_locked",
    "vault_not_found",
    "vault_operation_cancelled",
    "vault_operation_in_progress",
    "vault_operation_not_cancellable",
    "vault_operation_not_found",
    "vault_path_rejected",
    "vault_platform_unsupported",
    "vault_selection_not_found",
    "vault_uninitialized",
    "vault_unsupported_version",
    "vault_upload_not_found",
    "vault_upload_pending",
  ]);
  return t(`errors.${knownCodes.has(code) ? code : "generic"}`);
}

function formatDate(value: string, locale: SupportedLocale): string {
  const milliseconds = Number(value);
  if (!Number.isSafeInteger(milliseconds)) return "—";
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(milliseconds));
}

function formatBytes(value: string, locale: SupportedLocale): string {
  const bytes = Number(value);
  if (!Number.isSafeInteger(bytes)) return "—";
  return new Intl.NumberFormat(locale, {
    style: "unit",
    unit: "byte",
    unitDisplay: "short",
  }).format(bytes);
}

function buildPreview(filename: string, bytes: Uint8Array): AttachmentPreview {
  const textLimit = 65_536;
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return {
      filename,
      content: decoded.slice(0, textLimit),
      format: "text",
      truncated: decoded.length > textLimit,
    };
  } catch {
    const binaryLimit = 4_096;
    const visible = bytes.subarray(0, binaryLimit);
    return {
      filename,
      content: Array.from(visible, (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(" "),
      format: "hex",
      truncated: bytes.length > binaryLimit,
    };
  }
}
