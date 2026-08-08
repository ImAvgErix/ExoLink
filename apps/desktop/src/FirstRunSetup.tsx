import {
  Bell,
  Check,
  ChevronLeft,
  LoaderCircle,
  LockKeyhole,
  Maximize2,
  Mic,
  Minus,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import { coreBridge } from "./coreBridge";
import type { Member, NotificationMode } from "./models";
import { requestNotificationAccess } from "./nativeNotifications";

export const FIRST_RUN_SETUP_KEY = "exocord.first-run-setup-v1";
const LEGACY_PERMISSIONS_KEY = "exocord.permissions-onboarding-v1";

export function isFirstRunSetupComplete(): boolean {
  if (typeof window === "undefined") return true;
  return (
    window.localStorage.getItem(FIRST_RUN_SETUP_KEY) === "1" ||
    window.localStorage.getItem(LEGACY_PERMISSIONS_KEY) === "1"
  );
}

export function markFirstRunSetupComplete(): void {
  window.localStorage.setItem(FIRST_RUN_SETUP_KEY, "1");
  window.localStorage.setItem(LEGACY_PERMISSIONS_KEY, "1");
}

type SetupStep =
  | "welcome"
  | "name"
  | "microphone"
  | "notifications"
  | "alerts"
  | "privacy"
  | "ready";

const STEPS: SetupStep[] = [
  "welcome",
  "name",
  "microphone",
  "notifications",
  "alerts",
  "privacy",
  "ready",
];

const STEP_LABEL: Record<SetupStep, string> = {
  welcome: "Welcome",
  name: "Profile",
  microphone: "Microphone",
  notifications: "Notifications",
  alerts: "Alerts",
  privacy: "Privacy",
  ready: "Ready",
};

type PermissionState = "idle" | "asking" | "ready" | "denied" | "skipped";

function SetupWindowControls() {
  return (
    <div className="setup-chrome">
      <button
        className="setup-chrome-btn"
        type="button"
        aria-label="Minimize"
        onClick={() => void coreBridge.windowAction("minimize")}
      >
        <Minus size={16} strokeWidth={1.75} />
      </button>
      <button
        className="setup-chrome-btn"
        type="button"
        aria-label="Maximize"
        onClick={() => void coreBridge.windowAction("toggle_maximize")}
      >
        <Maximize2 size={14} strokeWidth={1.75} />
      </button>
      <button
        className="setup-chrome-btn is-close"
        type="button"
        aria-label="Close"
        onClick={() => void coreBridge.windowAction("close")}
      >
        <X size={16} strokeWidth={1.75} />
      </button>
    </div>
  );
}

function StatusDot({
  state,
}: {
  state: "idle" | "good" | "bad" | "warn" | "active";
}) {
  return <i className={`setup-dot setup-dot-${state}`} aria-hidden="true" />;
}

export function FirstRunSetup({
  currentUser,
  onComplete,
  onProfileSaved,
}: {
  currentUser: Member;
  onComplete: () => void;
  onProfileSaved?: (member: Member) => void;
}) {
  const [stepIndex, setStepIndex] = useState(0);
  const step = STEPS[stepIndex] ?? "welcome";
  const [displayName, setDisplayName] = useState(currentUser.name);
  const [nameBusy, setNameBusy] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [microphone, setMicrophone] = useState<PermissionState>("idle");
  const [notifications, setNotifications] = useState<PermissionState>(() =>
    typeof Notification !== "undefined" && Notification.permission === "granted"
      ? "ready"
      : "idle",
  );
  const [alertMode, setAlertMode] = useState<NotificationMode>("private");
  const [alertBusy, setAlertBusy] = useState(false);

  const progress = useMemo(
    () => ((stepIndex + 1) / STEPS.length) * 100,
    [stepIndex],
  );

  const goNext = () => {
    if (stepIndex >= STEPS.length - 1) {
      markFirstRunSetupComplete();
      onComplete();
      return;
    }
    setStepIndex((index) => Math.min(index + 1, STEPS.length - 1));
  };

  const goBack = () => {
    setStepIndex((index) => Math.max(index - 1, 0));
  };

  const requestMicrophone = async () => {
    setMicrophone("asking");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      stream.getTracks().forEach((track) => track.stop());
      setMicrophone("ready");
      window.setTimeout(() => goNext(), 380);
    } catch {
      setMicrophone("denied");
    }
  };

  const requestNotifications = async () => {
    setNotifications("asking");
    try {
      const granted = await requestNotificationAccess();
      setNotifications(granted ? "ready" : "denied");
      if (granted) window.setTimeout(() => goNext(), 380);
    } catch {
      setNotifications("denied");
    }
  };

  const saveDisplayName = async () => {
    const trimmed = displayName.trim();
    if (trimmed.length < 1 || trimmed.length > 64) {
      setNameError("Use a display name between 1 and 64 characters.");
      return;
    }
    setNameBusy(true);
    setNameError(null);
    try {
      const snapshot = await coreBridge.updateProfile({
        handle: currentUser.handle,
        displayName: trimmed,
        removeAvatar: false,
      });
      const member = snapshot.members.find(
        (candidate) => candidate.id === snapshot.currentUserId,
      );
      if (member) onProfileSaved?.(member);
      goNext();
    } catch (error) {
      setNameError(
        error instanceof Error
          ? error.message
          : "Your display name could not be saved.",
      );
    } finally {
      setNameBusy(false);
    }
  };

  const saveAlertMode = async () => {
    setAlertBusy(true);
    try {
      await coreBridge.saveNotificationSettings(alertMode);
      goNext();
    } catch {
      goNext();
    } finally {
      setAlertBusy(false);
    }
  };

  const finish = () => {
    markFirstRunSetupComplete();
    onComplete();
  };

  const permDot = (state: PermissionState) => {
    if (state === "ready") return "good" as const;
    if (state === "denied") return "bad" as const;
    if (state === "asking") return "warn" as const;
    if (state === "skipped") return "idle" as const;
    return "idle" as const;
  };

  return (
    <main className="setup-screen" aria-label="Exo Link setup">
      <header className="setup-titlebar">
        <div className="setup-titlebar-brand">
          <strong>Exo Link</strong>
          <span>
            Setup · {stepIndex + 1}/{STEPS.length} · {STEP_LABEL[step]}
          </span>
        </div>
        <SetupWindowControls />
      </header>

      <div className="setup-progress" aria-hidden="true">
        <i style={{ width: `${progress}%` }} />
      </div>

      <div className="setup-body">
        <section className="setup-stage" key={step}>
          {step === "welcome" ? (
            <>
              <p className="setup-kicker">Exo Link</p>
              <h1>Finish setup</h1>
              <p className="setup-lead">
                A few quiet steps — name, microphone, notifications. Same shell
                as the rest of the app. About a minute.
              </p>
              <div className="setup-card-stack" role="list">
                {(
                  [
                    ["Profile", "How you appear to friends"],
                    ["Microphone", "Voice rooms only when you join"],
                    ["Notifications", "Banners when minimized"],
                    ["Privacy", "What stays on this PC"],
                  ] as const
                ).map(([title, detail]) => (
                  <div key={title} className="setup-row" role="listitem">
                    <StatusDot state="idle" />
                    <div>
                      <strong>{title}</strong>
                      <small>{detail}</small>
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : null}

          {step === "name" ? (
            <>
              <p className="setup-kicker">Profile</p>
              <h1>Display name</h1>
              <p className="setup-lead">
                Shown next to your messages. Username{" "}
                <span className="setup-mono">@{currentUser.handle}</span> is
                permanent.
              </p>
              <label className="setup-field" htmlFor="setup-display-name">
                <span>Name</span>
                <input
                  id="setup-display-name"
                  className="setup-input-plain"
                  value={displayName}
                  autoFocus
                  maxLength={64}
                  autoComplete="nickname"
                  placeholder="Your name"
                  onChange={(event) => setDisplayName(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      void saveDisplayName();
                    }
                  }}
                />
              </label>
              {nameError ? (
                <p className="setup-error" role="alert">
                  {nameError}
                </p>
              ) : null}
            </>
          ) : null}

          {step === "microphone" ? (
            <>
              <p className="setup-kicker">Voice</p>
              <h1>Microphone</h1>
              <p className="setup-lead">
                Used only in voice rooms. Screen share asks separately.
              </p>
              <div className="setup-card-stack">
                <div className="setup-row">
                  <StatusDot state={permDot(microphone)} />
                  <div>
                    <strong>
                      {microphone === "ready"
                        ? "Ready"
                        : microphone === "denied"
                          ? "Blocked"
                          : microphone === "asking"
                            ? "Waiting…"
                            : microphone === "skipped"
                              ? "Skipped"
                              : "Not enabled"}
                    </strong>
                    <small>
                      {microphone === "denied"
                        ? "Windows Settings → Privacy → Microphone"
                        : "Change later in Windows or Settings"}
                    </small>
                  </div>
                  <Mic size={16} strokeWidth={1.75} className="setup-row-icon" />
                </div>
              </div>
            </>
          ) : null}

          {step === "notifications" ? (
            <>
              <p className="setup-kicker">Desktop</p>
              <h1>Notifications</h1>
              <p className="setup-lead">
                Optional banners while minimized. Next step picks how quiet.
              </p>
              <div className="setup-card-stack">
                <div className="setup-row">
                  <StatusDot state={permDot(notifications)} />
                  <div>
                    <strong>
                      {notifications === "ready"
                        ? "Ready"
                        : notifications === "denied"
                          ? "Blocked"
                          : notifications === "asking"
                            ? "Waiting…"
                            : notifications === "skipped"
                              ? "Skipped"
                              : "Not enabled"}
                    </strong>
                    <small>
                      {notifications === "denied"
                        ? "Windows Settings → System → Notifications"
                        : "Content can stay off-screen in quieter modes"}
                    </small>
                  </div>
                  <Bell size={16} strokeWidth={1.75} className="setup-row-icon" />
                </div>
              </div>
            </>
          ) : null}

          {step === "alerts" ? (
            <>
              <p className="setup-kicker">Preferences</p>
              <h1>Alert mode</h1>
              <p className="setup-lead">
                Default for desktop banners. Change anytime under Settings.
              </p>
              <div
                className="setup-card-stack"
                role="radiogroup"
                aria-label="Notification mode"
              >
                {(
                  [
                    {
                      id: "private" as const,
                      title: "Mentions and DMs",
                      detail: "Quiet — private traffic and @mentions only.",
                    },
                    {
                      id: "names" as const,
                      title: "All messages",
                      detail: "A banner for every new message while away.",
                    },
                    {
                      id: "off" as const,
                      title: "Off",
                      detail: "No banners. Unread still shows in the app.",
                    },
                  ] as const
                ).map((option) => {
                  const selected = alertMode === option.id;
                  return (
                    <button
                      key={option.id}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      className={`setup-row setup-row-btn ${selected ? "is-selected" : ""}`}
                      onClick={() => setAlertMode(option.id)}
                    >
                      <StatusDot state={selected ? "active" : "idle"} />
                      <div>
                        <strong>{option.title}</strong>
                        <small>{option.detail}</small>
                      </div>
                      {selected ? (
                        <Check size={15} strokeWidth={2} className="setup-row-icon is-check" />
                      ) : null}
                    </button>
                  );
                })}
              </div>
            </>
          ) : null}

          {step === "privacy" ? (
            <>
              <p className="setup-kicker">Privacy</p>
              <h1>On this PC</h1>
              <p className="setup-lead">Honest scope — what the code actually does.</p>
              <div className="setup-card-stack">
                {(
                  [
                    "Account keys in the Windows credential vault, per installation.",
                    "Local cache encrypted with SQLCipher on disk.",
                    "Private DMs use OpenMLS; server stores ciphertext, not epoch secrets.",
                    "Voice uses LiveKit with short-lived room grants.",
                  ] as const
                ).map((line) => (
                  <div key={line} className="setup-row">
                    <StatusDot state="good" />
                    <div>
                      <small className="setup-row-body">{line}</small>
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : null}

          {step === "ready" ? (
            <>
              <p className="setup-kicker">Done</p>
              <h1>You&apos;re ready</h1>
              <p className="setup-lead">
                Open Exo Link for servers, DMs, and voice. Revisit these in
                Settings anytime.
              </p>
              <div className="setup-card-stack">
                <div className="setup-row">
                  <StatusDot state="good" />
                  <div>
                    <strong>Name</strong>
                    <small>{displayName.trim() || currentUser.name}</small>
                  </div>
                </div>
                <div className="setup-row">
                  <StatusDot state={permDot(microphone)} />
                  <div>
                    <strong>Microphone</strong>
                    <small>
                      {microphone === "ready"
                        ? "Allowed"
                        : microphone === "denied"
                          ? "Blocked"
                          : "Skipped"}
                    </small>
                  </div>
                </div>
                <div className="setup-row">
                  <StatusDot state={permDot(notifications)} />
                  <div>
                    <strong>Notifications</strong>
                    <small>
                      {notifications === "ready"
                        ? "Allowed"
                        : notifications === "denied"
                          ? "Blocked"
                          : "Skipped"}
                    </small>
                  </div>
                </div>
                <div className="setup-row">
                  <StatusDot state="active" />
                  <div>
                    <strong>Alert mode</strong>
                    <small>
                      {alertMode === "private"
                        ? "Mentions and DMs"
                        : alertMode === "names"
                          ? "All messages"
                          : "Off"}
                    </small>
                  </div>
                </div>
              </div>
            </>
          ) : null}
        </section>
      </div>

      <footer className="setup-footer">
        {stepIndex > 0 && step !== "ready" ? (
          <button className="setup-ghost" type="button" onClick={goBack}>
            <ChevronLeft size={15} strokeWidth={1.75} />
            Back
          </button>
        ) : (
          <span />
        )}

        <div className="setup-footer-actions">
          {step === "welcome" ? (
            <button className="setup-primary exo-press" type="button" onClick={goNext}>
              Continue
            </button>
          ) : null}

          {step === "name" ? (
            <>
              <button
                className="setup-secondary"
                type="button"
                disabled={nameBusy}
                onClick={goNext}
              >
                Keep {currentUser.name}
              </button>
              <button
                className="setup-primary exo-press"
                type="button"
                disabled={nameBusy || !displayName.trim()}
                onClick={() => void saveDisplayName()}
              >
                {nameBusy ? <LoaderCircle className="spin" size={14} /> : null}
                Continue
              </button>
            </>
          ) : null}

          {step === "microphone" ? (
            <>
              <button
                className="setup-secondary"
                type="button"
                onClick={() => {
                  setMicrophone((current) =>
                    current === "ready" ? current : "skipped",
                  );
                  goNext();
                }}
              >
                Not now
              </button>
              {microphone === "ready" ? (
                <button className="setup-primary exo-press" type="button" onClick={goNext}>
                  Continue
                </button>
              ) : (
                <button
                  className="setup-primary exo-press"
                  type="button"
                  disabled={microphone === "asking"}
                  onClick={() => void requestMicrophone()}
                >
                  {microphone === "asking" ? (
                    <LoaderCircle className="spin" size={14} />
                  ) : null}
                  {microphone === "denied" ? "Retry" : "Allow"}
                </button>
              )}
            </>
          ) : null}

          {step === "notifications" ? (
            <>
              <button
                className="setup-secondary"
                type="button"
                onClick={() => {
                  setNotifications((current) =>
                    current === "ready" ? current : "skipped",
                  );
                  goNext();
                }}
              >
                Not now
              </button>
              {notifications === "ready" ? (
                <button className="setup-primary exo-press" type="button" onClick={goNext}>
                  Continue
                </button>
              ) : (
                <button
                  className="setup-primary exo-press"
                  type="button"
                  disabled={notifications === "asking"}
                  onClick={() => void requestNotifications()}
                >
                  {notifications === "asking" ? (
                    <LoaderCircle className="spin" size={14} />
                  ) : null}
                  {notifications === "denied" ? "Retry" : "Allow"}
                </button>
              )}
            </>
          ) : null}

          {step === "alerts" ? (
            <button
              className="setup-primary exo-press"
              type="button"
              disabled={alertBusy}
              onClick={() => void saveAlertMode()}
            >
              {alertBusy ? <LoaderCircle className="spin" size={14} /> : null}
              Continue
            </button>
          ) : null}

          {step === "privacy" ? (
            <button className="setup-primary exo-press" type="button" onClick={goNext}>
              Continue
            </button>
          ) : null}

          {step === "ready" ? (
            <button className="setup-primary exo-press" type="button" onClick={finish}>
              Open Exo Link
            </button>
          ) : null}
        </div>
      </footer>

      {/* quiet privacy mark — same density as Exo chrome, not marketing */}
      <span className="setup-footer-hint" aria-hidden="true">
        <LockKeyhole size={11} strokeWidth={1.75} />
        Local vault · no analytics in this step
      </span>
    </main>
  );
}
