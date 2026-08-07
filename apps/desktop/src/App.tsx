import {
  Apple,
  AtSign,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CloudOff,
  Copy,
  Download,
  FileText,
  Flag,
  Film,
  FolderOpen,
  Hash,
  Headphones,
  Link2,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Mail,
  Maximize2,
  Mic,
  MicOff,
  MessageCircle,
  Music,
  MoreHorizontal,
  Minus,
  MonitorUp,
  Paperclip,
  Pencil,
  Plus,
  RefreshCw,
  Reply,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  SmilePlus,
  Sparkles,
  Trash2,
  UserPlus,
  Users,
  Volume2,
  VolumeX,
  X,
} from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { coreBridge } from "./coreBridge";
import {
  FirstRunSetup,
  isFirstRunSetupComplete,
  markFirstRunSetupComplete,
} from "./FirstRunSetup";
import {
  createImageViewerState,
  imageViewerReducer,
  resolveAttachmentUrl,
} from "./imageViewer";
import type {
  BootstrapViewModel,
  AuthView,
  ChannelManagerView,
  ChannelOverwrite,
  ChatMessage,
  InvitePreview,
  InviteView,
  Member,
  ModerationManagerView,
  AutomodAction,
  AutomodRule,
  AutomodTriggerType,
  OverwriteTargetKind,
  RoleManagerView,
  ServerRole,
  VoiceRoom,
  VoiceDeviceSnapshot,
  VoiceSessionSnapshot,
  Workspace,
  MessageAttachment,
  SearchHit,
  SearchView,
  RelationshipView,
  DeviceSecurityView,
  ReportCategory,
  CoreDelta,
  CacheRecoveryView,
  AccountDeletionView,
  AccountDeletionStatusView,
  ServerOwnershipView,
  NetworkConfigurationView,
  NetworkProbeView,
  OperatorInfoView,
  NotificationMode,
  PasswordAuthenticationView,
  AccountAuthMethodsView,
  UpdateManifest,
} from "./models";
import {
  CACHE_RESET_CONFIRMATION,
  cacheResetConfirmed,
} from "./cacheRecovery";
import {
  ACCOUNT_DELETE_CONFIRMATION,
  accountDeleteConfirmed,
} from "./accountDeletion";
import { applyCoreDelta } from "./coreDelta";
import { voiceClient } from "./voiceClient";
import { serverNameConfirmed } from "./serverOwnership";
import {
  NotificationDeduper,
  notificationIntent,
} from "./notificationPolicy";
import {
  requestNotificationAccess,
  showNativeNotification,
} from "./nativeNotifications";
import { searchEmojiCatalog } from "./emojiCatalog";
import { GlassSurface } from "./LiquidGlass";
import {
  REFRACTIVE_GLASS_STORAGE_KEY,
  RefractiveBackdrop,
  readRefractiveGlassMode,
  type RefractiveGlassMode,
} from "./RefractiveBackdrop";
import { resolveVoiceDisplayName } from "./voiceDisplay";
import {
  reactionsEqual,
  reconcileMessageResult,
  type MessageReconcileOptions,
} from "./messageReconcile";
import {
  preferredNavigationContext,
  resolveNavigationContext,
  type NavigationContext,
} from "./navigationContext";

const EMPTY_MODEL: BootstrapViewModel = {
  revision: 0,
  cacheRecovery: null,
  cacheProtection: {
    encrypted: false,
    cipher: "Unavailable",
    keyStorage: "Operating-system credential vault",
  },
  currentUserId: "",
  activeWorkspaceId: "",
  activeChannelId: "",
  activeVoiceRoomId: null,
  connectionState: "offline",
  pendingOutbox: 0,
  workspaces: [],
  members: [],
  relationships: [],
  typing: [],
  messages: [],
};

function startWindowDrag(event: React.MouseEvent<HTMLElement>) {
  if (event.button !== 0) return;
  const target = event.target as HTMLElement | null;
  if (target?.closest("button, a, input, textarea, select, [role='button']")) {
    return;
  }
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
    return;
  }
  void getCurrentWindow().startDragging().catch(() => undefined);
}

function useDialogFocus<T extends HTMLElement>(
  open: boolean,
  onClose: () => void,
) {
  const dialogRef = useRef<T>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement;
    const dialog = dialogRef.current;
    const focusableSelector =
      "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex='-1'])";
    const focusFirst = () => {
      const focusable = dialog?.querySelector<HTMLElement>(focusableSelector);
      (focusable ?? dialog)?.focus();
    };
    const frame = window.requestAnimationFrame(focusFirst);
    const keydown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = [
        ...dialog.querySelectorAll<HTMLElement>(focusableSelector),
      ].filter(
        (element) =>
          element.getClientRects().length > 0 &&
          element.getAttribute("aria-hidden") !== "true",
      );
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", keydown);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", keydown);
      if (previous instanceof HTMLElement && previous.isConnected) {
        previous.focus();
      }
    };
  }, [open]);

  return dialogRef;
}

const EMPTY_VOICE_SESSION: VoiceSessionSnapshot = {
  roomId: null,
  status: "idle",
  participants: [],
  muted: false,
  deafened: false,
  sharing: false,
  canSpeak: false,
  canStream: false,
  transportEncrypted: false,
  endToEndEncrypted: false,
  error: null,
};

const ROLE_PERMISSION_GROUPS = [
  {
    label: "Community",
    items: [
      ["create_invite", "Create invites"],
      ["kick_members", "Remove members"],
      ["ban_members", "Ban members"],
      ["manage_guild", "Manage server"],
      ["manage_channels", "Manage channels"],
      ["manage_roles", "Manage roles"],
      ["moderate_members", "Time out members"],
      ["view_member_list", "View member list"],
    ],
  },
  {
    label: "Conversation",
    items: [
      ["view_channel", "View channels"],
      ["send_messages", "Send messages"],
      ["embed_links", "Embed links"],
      ["attach_files", "Attach files"],
      ["add_reactions", "Add reactions"],
      ["mention_everyone", "Mention everyone"],
      ["manage_messages", "Manage messages"],
      ["read_message_history", "Read history"],
      ["manage_pins", "Manage pins"],
    ],
  },
  {
    label: "Voice",
    items: [
      ["connect", "Join voice"],
      ["speak", "Speak"],
      ["stream", "Share screen"],
      ["mute_members", "Mute members"],
      ["deafen_members", "Deafen members"],
      ["move_members", "Move members"],
      ["use_vad", "Voice activity"],
    ],
  },
  {
    label: "Security & automation",
    items: [
      ["administrator", "Administrator"],
      ["view_audit_log", "View audit log"],
      ["manage_webhooks", "Manage webhooks"],
      ["manage_emoji", "Manage emoji"],
      ["manage_automod", "Manage automod"],
      ["view_automod_alerts", "View automod alerts"],
      ["manage_integrations", "Manage integrations"],
      ["enable_e2ee", "Enable E2EE"],
      ["manage_e2ee_members", "Manage E2EE members"],
    ],
  },
] as const;

const CHANNEL_PERMISSION_ITEMS = [
  ["view_channel", "View channel"],
  ["send_messages", "Send messages"],
  ["read_message_history", "Read history"],
  ["embed_links", "Embed links"],
  ["attach_files", "Attach files"],
  ["add_reactions", "Add reactions"],
  ["mention_everyone", "Mention everyone"],
  ["manage_messages", "Manage messages"],
  ["connect", "Join voice"],
  ["speak", "Speak"],
  ["stream", "Share screen"],
] as const;

function AuthScreen({
  auth,
  network,
  onAuthenticated,
}: {
  auth: AuthView;
  network: NetworkConfigurationView;
  onAuthenticated: (auth: AuthView) => void;
}) {
  const [authMode, setAuthMode] = useState<
    "signin" | "register" | "recover"
  >("signin");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [pendingPasswordAuth, setPendingPasswordAuth] =
    useState<PasswordAuthenticationView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [networkOpen, setNetworkOpen] = useState(
    network.source === "local_default" || Boolean(network.warning),
  );
  const [networkUrl, setNetworkUrl] = useState(network.apiUrl);
  const [networkBusy, setNetworkBusy] = useState<"probe" | "save" | null>(
    null,
  );
  const [networkProbe, setNetworkProbe] =
    useState<NetworkProbeView | null>(null);
  const [networkError, setNetworkError] = useState<string | null>(
    network.warning,
  );
  const [networkSaved, setNetworkSaved] = useState(false);
  const [operatorInfo, setOperatorInfo] = useState<OperatorInfoView | null>(null);
  const authCardRef = useRef<HTMLElement>(null);
  const setupRequired = network.source === "local_default";
  const showNetworkSettings = setupRequired || network.source !== "build";
  const networkHost = (() => {
    try {
      return new URL(network.apiUrl).host;
    } catch {
      return network.apiUrl;
    }
  })();
  const passwordCharacterCount = [...password].length;

  useEffect(() => {
    authCardRef.current?.scrollTo({ top: 0 });
  }, [authMode]);

  useEffect(() => {
    if (setupRequired) return;
    let active = true;
    void coreBridge
      .operatorInfo()
      .then((operator) => {
        if (active) setOperatorInfo(operator);
      })
      .catch(() => {
        if (active) setOperatorInfo(null);
      });
    return () => {
      active = false;
    };
  }, [network.apiUrl, setupRequired]);

  const openOperatorResource = async (
    resource: "privacy" | "terms" | "support" | "abuse",
  ) => {
    try {
      await coreBridge.openOperatorResource(resource);
    } catch (resourceError) {
      setError(
        resourceError instanceof Error
          ? resourceError.message
          : "That operator resource could not be opened.",
      );
    }
  };

  const testNetwork = async () => {
    setNetworkBusy("probe");
    setNetworkError(null);
    setNetworkSaved(false);
    setNetworkProbe(null);
    try {
      const probe = await coreBridge.probeNetworkConfiguration(networkUrl.trim());
      setNetworkProbe(probe);
      setOperatorInfo(probe.operator);
    } catch (probeError) {
      setNetworkError(
        probeError instanceof Error
          ? probeError.message
          : "That Exocord server could not be reached.",
      );
    } finally {
      setNetworkBusy(null);
    }
  };

  const saveNetwork = async () => {
    setNetworkBusy("save");
    setNetworkError(null);
    setNetworkSaved(false);
    try {
      await coreBridge.saveNetworkConfiguration(networkUrl.trim());
      setNetworkSaved(true);
    } catch (saveError) {
      setNetworkError(
        saveError instanceof Error
          ? saveError.message
          : "That Exocord network could not be activated.",
      );
    } finally {
      setNetworkBusy(null);
    }
  };

  const submitPassword = async (event: FormEvent) => {
    event.preventDefault();
    if (
      (authMode === "register" || authMode === "recover") &&
      password !== passwordConfirmation
    ) {
      setError("Those passwords do not match.");
      return;
    }
    if (
      (authMode === "register" || authMode === "recover") &&
      (passwordCharacterCount < 10 || passwordCharacterCount > 128)
    ) {
      setError("Use a password between 10 and 128 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (authMode === "register") {
        setPendingPasswordAuth(
          await coreBridge.registerWithPassword(email, username, password),
        );
      } else if (authMode === "recover") {
        setPendingPasswordAuth(
          await coreBridge.recoverPassword(email, recoveryCode, password),
        );
      } else {
        const result = await coreBridge.loginWithPassword(email, password);
        if (result.recoveryCodes.length > 0) {
          setPendingPasswordAuth(result);
        } else {
          onAuthenticated(result.auth);
        }
      }
    } catch (authError) {
      setError(
        authError instanceof Error
          ? authError.message
          : authMode === "register"
            ? "The account could not be created."
            : authMode === "recover"
              ? "The recovery code could not reset this account."
              : "The email or password is incorrect.",
      );
    } finally {
      setBusy(false);
    }
  };

  const submitApple = async () => {
    setBusy(true);
    setError(null);
    try {
      onAuthenticated(await coreBridge.loginWithApple());
    } catch (appleError) {
      setError(
        appleError instanceof Error
          ? appleError.message
          : "Apple sign-in could not be completed.",
      );
    } finally {
      setBusy(false);
    }
  };

  if (pendingPasswordAuth) {
    return (
      <RecoveryCodesScreen
        result={pendingPasswordAuth}
        onComplete={() => coreBridge.activateAuthenticatedAccount()}
      />
    );
  }

  return (
    <main className="auth-screen">
      <WindowControls />
      <section
        ref={authCardRef}
        className="auth-card"
        aria-labelledby="auth-title"
      >
        <div className="auth-wordmark" aria-label="Exocord">
        <span className="auth-mark">
            <Sparkles size={16} />
        </span>
          <strong>Exocord</strong>
        </div>
        <div className="auth-card-heading">
          <h1 id="auth-title">
            {setupRequired
              ? "Connect to Exocord"
              : authMode === "register"
                ? "Create account"
                : authMode === "recover"
                  ? "Recover account"
                  : "Welcome back"}
          </h1>
          {setupRequired ? (
            <p>Enter the server URL shared with your test group.</p>
          ) : authMode === "recover" ? (
            <p>Use one saved recovery code.</p>
          ) : null}
        </div>
        {setupRequired ? null : (
          <form className="auth-form" onSubmit={submitPassword}>
            {authMode === "recover" ? (
              <button
                className="auth-recovery-back"
                type="button"
                onClick={() => {
                  setAuthMode("signin");
                  setPassword("");
                  setPasswordConfirmation("");
                  setRecoveryCode("");
                  setError(null);
                }}
              >
                <ChevronLeft size={13} />
                Back to sign in
              </button>
            ) : (
              <div
                className="auth-mode-tabs"
                role="tablist"
                aria-label="Account access"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={authMode === "signin"}
                  className={authMode === "signin" ? "is-active" : ""}
                  onClick={() => {
                    setAuthMode("signin");
                    setPassword("");
                    setPasswordConfirmation("");
                    setRecoveryCode("");
                    setError(null);
                  }}
                >
                  Sign in
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={authMode === "register"}
                  className={authMode === "register" ? "is-active" : ""}
                  onClick={() => {
                    setAuthMode("register");
                    setPassword("");
                    setPasswordConfirmation("");
                    setRecoveryCode("");
                    setError(null);
                  }}
                >
                  Create account
                </button>
              </div>
            )}
            {authMode === "register" ? (
              <>
                <label htmlFor="register-username">Username</label>
                <div className="auth-input-wrap">
                  <AtSign size={16} />
                  <input
                    id="register-username"
                    value={username}
                    autoFocus
                    autoCapitalize="none"
                    autoComplete="username"
                    spellCheck={false}
                    maxLength={32}
                    placeholder="your_username"
                    onChange={(event) =>
                      setUsername(event.target.value.toLowerCase())
                    }
                  />
                </div>
              </>
            ) : null}
            <label htmlFor="login-email">Email address</label>
            <div className="auth-input-wrap">
              <Mail size={16} />
              <input
                id="login-email"
                type="email"
                value={email}
                autoFocus={authMode !== "register"}
                autoComplete="username"
                placeholder="you@example.com"
                onChange={(event) => setEmail(event.target.value)}
              />
            </div>
            {authMode === "recover" ? (
              <>
                <label htmlFor="recovery-code">Recovery code</label>
                <div className="auth-input-wrap">
                  <ShieldCheck size={16} />
                  <input
                    id="recovery-code"
                    value={recoveryCode}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="exo_rc_…"
                    onChange={(event) => setRecoveryCode(event.target.value)}
                  />
                </div>
              </>
            ) : null}
            <label htmlFor="login-password">
              {authMode === "recover" ? "New password" : "Password"}
            </label>
            <div className="auth-input-wrap">
              <LockKeyhole size={16} />
              <input
                id="login-password"
                type="password"
                value={password}
                autoComplete={
                  authMode === "register" || authMode === "recover"
                    ? "new-password"
                    : "current-password"
                }
                maxLength={128}
                placeholder={
                  authMode === "register" || authMode === "recover"
                    ? "10 characters or more"
                    : "Your password"
                }
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            {authMode === "register" || authMode === "recover" ? (
              <>
                <label htmlFor="confirm-password">
                  Confirm {authMode === "recover" ? "new " : ""}password
                </label>
                <div className="auth-input-wrap">
                  <LockKeyhole size={16} />
                  <input
                    id="confirm-password"
                    type="password"
                    value={passwordConfirmation}
                    autoComplete="new-password"
                    maxLength={128}
                    placeholder="Repeat your password"
                    onChange={(event) =>
                      setPasswordConfirmation(event.target.value)
                    }
                  />
                </div>
                {password && passwordCharacterCount < 10 ? (
                  <span className="auth-password-hint" role="status">
                    {10 - passwordCharacterCount} more character
                    {10 - passwordCharacterCount === 1 ? "" : "s"}
                  </span>
                ) : passwordConfirmation &&
                  password !== passwordConfirmation ? (
                  <span className="auth-password-hint auth-password-error" role="status">
                    Passwords do not match
                  </span>
                ) : authMode === "recover" ? (
                  <span className="auth-password-hint">
                    Resetting your password signs every old session out.
                  </span>
                ) : null}
              </>
            ) : null}
            <button
              className="auth-primary"
              type="submit"
              disabled={
                busy ||
                !auth.passwordAvailable ||
                (authMode === "register" &&
                  !/^[a-z0-9][a-z0-9_-]{2,31}$/.test(username)) ||
                !email.includes("@") ||
                !password ||
                (authMode === "recover" && !recoveryCode.trim()) ||
                ((authMode === "register" || authMode === "recover") &&
                  !passwordConfirmation)
              }
            >
              {busy ? <LoaderCircle className="connection-spinner" /> : null}
              {authMode === "register"
                ? "Create account"
                : authMode === "recover"
                  ? "Reset password"
                  : "Sign in"}
            </button>
            {authMode === "signin" ? (
              <button
                className="auth-recovery-link"
                type="button"
                disabled={busy}
                onClick={() => {
                  setAuthMode("recover");
                  setPassword("");
                  setPasswordConfirmation("");
                  setError(null);
                }}
              >
                Use a recovery code
              </button>
            ) : null}
            {authMode === "signin" && auth.appleAvailable ? (
              <>
                <div className="auth-divider">
                  <span>or</span>
                </div>
                <button
                  className="apple-button"
                  type="button"
                  disabled={busy || !auth.appleAvailable}
                  onClick={() => void submitApple()}
                  title={
                    auth.appleAvailable
                      ? "Continue securely in your browser"
                      : "Connect Apple Services ID credentials on the server"
                  }
                >
                  <Apple size={16} />
                  {busy && auth.appleAvailable
                    ? "Waiting for Apple…"
                    : "Continue with Apple"}
                </button>
              </>
            ) : null}
          </form>
        )}
        {!setupRequired && error ? (
          <p className="auth-error" role="alert">
            {error}
          </p>
        ) : null}
        {!setupRequired && auth.deletionScheduledFor ? (
          <div className="auth-deletion-notice" role="status">
            <Trash2 size={14} />
            <span>
              <strong>Account deletion is scheduled.</strong>
              Sign in again before the deadline to review, export, or cancel it.
            </span>
          </div>
        ) : null}
        {showNetworkSettings ? (
          <div className={`auth-network ${networkOpen ? "is-open" : ""}`}>
          <button
            className="auth-network-toggle"
            type="button"
            aria-expanded={networkOpen}
            aria-disabled={setupRequired}
            onClick={() => {
              if (!setupRequired) setNetworkOpen((open) => !open);
            }}
          >
            <span className="auth-network-icon">
              <Server size={14} />
            </span>
            <span>
              <strong>Alpha network</strong>
              <small>
                {networkHost} · {network.secure ? "HTTPS" : "local"}
              </small>
            </span>
            {network.source === "local_default" ? (
              <em>Setup needed</em>
            ) : null}
            {!setupRequired ? <ChevronDown size={14} /> : null}
          </button>
          {networkOpen ? (
            <div className="auth-network-panel">
              <p>
                {setupRequired
                  ? "Ask the alpha owner for the exact HTTPS address. Every friend in the group uses the same one."
                  : "Your test group shares one Exocord server. Enter its URL once; session secrets remain in the Windows credential vault."}
              </p>
              <label htmlFor="alpha-network-url">Server URL</label>
              <div className="auth-network-input">
                <LockKeyhole size={14} />
                <input
                  id="alpha-network-url"
                  value={networkUrl}
                  disabled={network.managed || networkBusy !== null}
                  spellCheck={false}
                  inputMode="url"
                  placeholder="https://alpha.example.com"
                  onChange={(event) => {
                    setNetworkUrl(event.target.value);
                    setNetworkProbe(null);
                    setNetworkSaved(false);
                  }}
                />
              </div>
              <span className="auth-network-hint">
                Remote networks require HTTPS. Changing networks restarts the
                app.
              </span>
              {networkProbe ? (
                <div className="auth-network-result" role="status">
                  <Check size={14} />
                  <span>
                    <strong>Compatible server reached</strong>
                    {networkProbe.storage} storage ·{" "}
                    {networkProbe.attachments} attachments ·{" "}
                    {networkProbe.nativeVoice === "not_configured"
                      ? "voice unavailable"
                      : "voice ready"}
                  </span>
                </div>
              ) : null}
              {networkError ? (
                <p className="auth-network-error" role="alert">
                  {networkError}
                </p>
              ) : null}
              {networkSaved ? (
                <p className="auth-network-saved" role="status">
                  Preview network saved. The native app restarts automatically.
                </p>
              ) : null}
              <div className="auth-network-actions">
                <button
                  type="button"
                  disabled={networkBusy !== null || !networkUrl.trim()}
                  onClick={() => void testNetwork()}
                >
                  {networkBusy === "probe" ? (
                    <LoaderCircle className="connection-spinner" />
                  ) : (
                    <RefreshCw size={13} />
                  )}
                  Test connection
                </button>
                <button
                  type="button"
                  disabled={
                    network.managed ||
                    networkBusy !== null ||
                    !networkUrl.trim()
                  }
                  onClick={() => void saveNetwork()}
                >
                  {networkBusy === "save" ? (
                    <LoaderCircle className="connection-spinner" />
                  ) : (
                    <Check size={13} />
                  )}
                  Use & restart
                </button>
              </div>
              {network.managed ? (
                <span className="auth-network-hint">
                  This installation is managed by EXOCORD_API_URL.
                </span>
              ) : null}
            </div>
          ) : null}
          </div>
        ) : null}
        {operatorInfo ? (
          <div className="auth-operator">
            <span>
              Operated by <strong>{operatorInfo.name}</strong>
            </span>
            <div>
              {operatorInfo.privacyUrl ? (
                <button
                  type="button"
                  onClick={() => void openOperatorResource("privacy")}
                >
                  Privacy
                </button>
              ) : null}
              {operatorInfo.termsUrl ? (
                <button
                  type="button"
                  onClick={() => void openOperatorResource("terms")}
                >
                  Terms
                </button>
              ) : null}
              {operatorInfo.supportEmail ? (
                <button
                  type="button"
                  onClick={() => void openOperatorResource("support")}
                >
                  Support
                </button>
              ) : null}
              {operatorInfo.abuseEmail ? (
                <button
                  type="button"
                  onClick={() => void openOperatorResource("abuse")}
                >
                  Report abuse
                </button>
              ) : null}
            </div>
          </div>
        ) : null}
      </section>
    </main>
  );
}

function RecoveryCodesScreen({
  result,
  onComplete,
}: {
  result: PasswordAuthenticationView;
  onComplete: () => Promise<void>;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <main className="auth-screen">
      <WindowControls />
      <section
        className="auth-card recovery-codes-card"
        aria-labelledby="recovery-codes-title"
      >
        <div className="auth-wordmark" aria-label="Exocord">
          <span className="auth-mark">
            <Sparkles size={16} />
          </span>
          <strong>Exocord</strong>
        </div>
        <div className="auth-card-heading">
          <h1 id="recovery-codes-title">Save your recovery codes</h1>
          <p>
            Each code resets your password once. Exocord stores only their
            hashes, so nobody can show these exact codes again.
          </p>
        </div>
        <div className="recovery-code-grid">
          {result.recoveryCodes.map((code, index) => (
            <code key={code}>
              <span>{index + 1}</span>
              {code}
            </code>
          ))}
        </div>
        <button
          className="recovery-copy"
          type="button"
          onClick={() => {
            void navigator.clipboard
              .writeText(result.recoveryCodes.join("\n"))
              .then(() => {
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1800);
              })
              .catch(() => {
                setCopied(false);
                setError("The recovery codes could not be copied.");
              });
          }}
        >
          {copied ? <Check size={14} /> : <Copy size={14} />}
          {copied ? "Copied" : "Copy all codes"}
        </button>
        <label className="recovery-saved-check">
          <input
            type="checkbox"
            checked={saved}
            onChange={(event) => setSaved(event.target.checked)}
          />
          <span>
            <strong>I saved these somewhere private</strong>
            <small>
              A password manager or encrypted offline note is best. Anyone
              with a code and your email can reset the account.
            </small>
          </span>
        </label>
        <button
          className="auth-primary"
          type="button"
          disabled={!saved || busy}
          onClick={() => {
            setBusy(true);
            setError(null);
            void onComplete().catch((activationError) => {
              setBusy(false);
              setError(
                activationError instanceof Error
                  ? activationError.message
                  : "The account could not be opened.",
              );
            });
          }}
        >
          {busy ? <LoaderCircle className="connection-spinner" /> : null}
          {busy ? "Opening account" : "Continue setup"}
        </button>
        {error ? (
          <p className="auth-error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </main>
  );
}

function formatDeletionDeadline(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "long",
    timeStyle: "short",
  }).format(date);
}

function messageDate(value: string): Date | null {
  const clock = /^(\d{1,2}):(\d{2})$/.exec(value);
  if (clock) {
    const date = new Date();
    date.setHours(Number(clock[1]), Number(clock[2]), 0, 0);
    return date;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatMessageTime(value: string): string {
  const date = messageDate(value);
  if (!date) return value || "now";
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function messageDay(value: string): { key: string; label: string } {
  const date = messageDate(value);
  if (!date) return { key: `unknown-${value}`, label: "Earlier" };
  const today = new Date();
  const startToday = new Date(
    today.getFullYear(),
    today.getMonth(),
    today.getDate(),
  );
  const startDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  const dayDelta = Math.round(
    (startToday.getTime() - startDate.getTime()) / 86_400_000,
  );
  const label =
    dayDelta === 0
      ? "Today"
      : dayDelta === 1
        ? "Yesterday"
        : new Intl.DateTimeFormat(undefined, {
            weekday: "short",
            month: "short",
            day: "numeric",
            year:
              date.getFullYear() === today.getFullYear()
                ? undefined
                : "numeric",
          }).format(date);
  return {
    key: `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`,
    label,
  };
}

function groupMessagesByHour(messages: ChatMessage[]) {
  const groups: Array<{
    key: string;
    label: string;
    messages: ChatMessage[];
  }> = [];
  for (const message of messages) {
    const hour = messageDay(message.sentAt);
    const current = groups.at(-1);
    if (current?.key === hour.key) {
      current.messages.push(message);
    } else {
      groups.push({ ...hour, messages: [message] });
    }
  }
  return groups;
}

function DeletionPendingScreen({
  auth,
  onCancel,
  onExport,
  onLogout,
}: {
  auth: AuthView;
  onCancel: () => Promise<void>;
  onExport: () => Promise<string>;
  onLogout: () => Promise<void>;
}) {
  const [busy, setBusy] = useState<"cancel" | "export" | "logout" | null>(
    null,
  );
  const [exportPath, setExportPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const deadline = auth.deletionScheduledFor ?? "";

  const run = async (
    action: "cancel" | "export" | "logout",
    operation: () => Promise<void>,
  ) => {
    if (busy) return;
    setBusy(action);
    setError(null);
    try {
      await operation();
    } catch (actionError) {
      setError(
        actionError instanceof Error
          ? actionError.message
          : "That account action could not be completed.",
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="deletion-pending-screen">
      <WindowControls />
      <section className="deletion-pending-card" aria-labelledby="deletion-title">
        <div className="deletion-pending-mark">
          <Trash2 size={20} />
        </div>
        <span className="deletion-kicker">30-DAY RECOVERY WINDOW</span>
        <h1 id="deletion-title">Your account is queued for deletion.</h1>
        <p className="deletion-deadline">
          Scheduled for <strong>{formatDeletionDeadline(deadline)}</strong>
        </p>
        <p className="deletion-summary">
          Normal account access is paused. Cancel now to restore the account, or
          download a machine-readable copy of your data first.
        </p>
        <div className="deletion-facts">
          <div>
            <ShieldCheck size={15} />
            <span>
              <strong>You can still reverse this</strong>
              Cancellation is immediate during the grace period.
            </span>
          </div>
          <div>
            <MessageCircle size={15} />
            <span>
              <strong>Shared conversations stay coherent</strong>
              After the deadline, retained messages show an anonymized Deleted
              User identity.
            </span>
          </div>
          <div>
            <LockKeyhole size={15} />
            <span>
              <strong>Local data is separate</strong>
              This request does not silently erase the encrypted cache on this
              device.
            </span>
          </div>
        </div>
        <div className="deletion-pending-actions">
          <button
            className="deletion-cancel"
            type="button"
            disabled={busy !== null}
            onClick={() => void run("cancel", onCancel)}
          >
            {busy === "cancel" ? (
              <LoaderCircle className="spin" size={15} />
            ) : (
              <ShieldCheck size={15} />
            )}
            Cancel deletion
          </button>
          <button
            type="button"
            disabled={busy !== null}
            onClick={() =>
              void run("export", async () => {
                setExportPath(await onExport());
              })
            }
          >
            {busy === "export" ? (
              <LoaderCircle className="spin" size={14} />
            ) : (
              <Download size={14} />
            )}
            Download my data
          </button>
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => void run("logout", onLogout)}
          >
            {busy === "logout" ? (
              <LoaderCircle className="spin" size={14} />
            ) : (
              <LogOut size={14} />
            )}
            Sign out
          </button>
        </div>
        {exportPath ? (
          <p className="deletion-export-path" role="status">
            Saved securely to <code>{exportPath}</code>
          </p>
        ) : null}
        {error ? (
          <p className="deletion-pending-error" role="alert">
            {error}
          </p>
        ) : null}
        <footer>{auth.email ?? "Authenticated Exocord account"}</footer>
      </section>
    </main>
  );
}

function ConnectionBanner({
  state,
  pending,
  onRetry,
}: {
  state: BootstrapViewModel["connectionState"];
  pending: number;
  onRetry: () => void;
}) {
  if (state === "connected" && pending === 0) return null;
  const label =
    state === "offline"
      ? pending > 0
        ? `Offline — ${pending} message${pending === 1 ? "" : "s"} safely queued`
        : "Offline — local channels remain available"
      : state === "catching_up"
        ? "Catching up and delivering queued messages…"
        : state === "connecting"
          ? "Connecting to your Exocord network…"
          : `Delivering ${pending} queued message${pending === 1 ? "" : "s"}…`;
  return (
    <div
      className={`connection-banner connection-${state}`}
      role="status"
      aria-live="polite"
    >
      {state === "offline" ? (
        <CloudOff size={12} />
      ) : (
        <LoaderCircle className="connection-spinner" size={12} />
      )}
      <span>{label}</span>
      {state === "offline" || (state === "connected" && pending > 0) ? (
        <button type="button" onClick={onRetry}>
          <RefreshCw size={11} /> Retry
        </button>
      ) : null}
    </div>
  );
}

function Avatar({
  member,
  size = "medium",
  showPresence = false,
}: {
  member: Member;
  size?: "small" | "medium" | "large";
  showPresence?: boolean;
}) {
  return (
    <span
      className={`avatar avatar-${size}`}
      style={{ "--avatar-color": member.color } as React.CSSProperties}
      aria-label={member.name}
      title={member.name}
    >
      {member.avatarUrl ? (
        <img src={member.avatarUrl} alt="" draggable={false} />
      ) : (
        member.initials
      )}
      {showPresence && (
        <span className={`presence presence-${member.presence}`} />
      )}
    </span>
  );
}

function presenceLabel(presence: Member["presence"]): string {
  return presence === "online"
    ? "Online"
    : presence === "away"
      ? "Away"
      : "Offline";
}

function WindowControls() {
  return (
    <div className="window-controls">
      <button
        className="window-control"
        type="button"
        aria-label="Minimize"
        onClick={() => void coreBridge.windowAction("minimize")}
      >
        <Minus size={14} strokeWidth={1.7} />
      </button>
      <button
        className="window-control"
        type="button"
        aria-label="Maximize"
        onClick={() => void coreBridge.windowAction("toggle_maximize")}
      >
        <Maximize2 size={12} strokeWidth={1.7} />
      </button>
      <button
        className="window-control window-close"
        type="button"
        aria-label="Close"
        onClick={() => void coreBridge.windowAction("close")}
      >
        <X size={14} strokeWidth={1.7} />
      </button>
    </div>
  );
}

function TopNavigation({
  workspaces,
  workspace,
  currentUser,
  members,
  currentUserId,
  activeWorkspaceId,
  activeChannelId,
  activeVoiceRoomId,
  voiceSession,
  onSelectWorkspace,
  onSelectChannel,
  onSelectVoice,
  onCreateWorkspace,
  onOpenServerMenu,
  onOpenFriends,
  onOpenSearch,
  onOpenSettings,
  onLogout,
  onOpenMemberProfile,
}: {
  workspaces: Workspace[];
  workspace?: Workspace;
  currentUser?: Member;
  members: Member[];
  currentUserId: string;
  activeWorkspaceId: string;
  activeChannelId: string;
  activeVoiceRoomId: string | null;
  voiceSession: VoiceSessionSnapshot;
  onSelectWorkspace: (workspace: Workspace) => void;
  onSelectChannel: (channelId: string) => void;
  onSelectVoice: (roomId: string) => void;
  onCreateWorkspace: () => void;
  onOpenServerMenu: () => void;
  onOpenFriends: () => void;
  onOpenSearch: () => void;
  onOpenSettings: () => void;
  onLogout: () => Promise<void>;
  onOpenMemberProfile: (member: Member) => void;
}) {
  const channelTabsRef = useRef<HTMLElement>(null);
  const [openMenu, setOpenMenu] = useState<
    "profile" | "workspace" | "members" | null
  >(null);
  const visibleWorkspaces = workspaces.filter(
    (candidate) => !candidate.localOnly,
  );
  const unreadWorkspaces = visibleWorkspaces.filter(
    (candidate) => (candidate.unreadCount ?? 0) > 0,
  );
  const unreadTotal = unreadWorkspaces.reduce(
    (total, candidate) => total + (candidate.unreadCount ?? 0),
    0,
  );
  const workspaceMembers = (workspace?.memberIds ?? [])
    .map((memberId) => members.find((member) => member.id === memberId))
    .filter((member): member is Member => Boolean(member));
  const onlineMembers = workspaceMembers.filter(
    (member) => member.presence === "online",
  );
  const offlineMembers = workspaceMembers.filter(
    (member) => member.presence !== "online",
  );
  const compactSelection =
    workspace?.voiceRooms.some((room) => room.id === activeVoiceRoomId)
      ? `voice:${activeVoiceRoomId}`
      : activeChannelId;
  const chooseWorkspace = (candidate: Workspace) => {
    setOpenMenu(null);
    onSelectWorkspace(candidate);
  };
  const closeAnd = (action: () => void) => {
    setOpenMenu(null);
    action();
  };
  useEffect(() => {
    channelTabsRef.current
      ?.querySelector<HTMLElement>(".channel-tab.is-active")
      ?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [activeChannelId, activeWorkspaceId]);

  return (
    <GlassSurface
      as="header"
      variant="regular"
      className={`top-navigation ${openMenu ? "is-menu-open" : ""}`}
      data-tauri-drag-region
      onMouseDown={startWindowDrag}
      onDoubleClick={(event) => {
        const target = event.target as HTMLElement | null;
        if (target?.closest("button, a, input, textarea, select, [role='button']")) {
          return;
        }
        void coreBridge.windowAction("toggle_maximize");
      }}
    >
      {openMenu ? (
        <button
          className="chrome-popover-scrim"
          type="button"
          aria-label="Close navigation menu"
          onClick={() => setOpenMenu(null)}
        />
      ) : null}

      <button
        className={`profile-identity ${
          openMenu === "profile" ? "is-open" : ""
        }`}
        type="button"
        aria-label="Open your messages and settings"
        aria-expanded={openMenu === "profile"}
        onClick={(event) => {
          event.stopPropagation();
          setOpenMenu((current) =>
            current === "profile" ? null : "profile",
          );
        }}
      >
        <span className="profile-orb-wrap">
          {currentUser ? (
            <Avatar member={currentUser} showPresence />
          ) : (
            <span className="profile-fallback">EX</span>
          )}
          {unreadTotal > 0 ? (
            <span className="profile-unread-badge">
              {unreadTotal > 99 ? "99+" : unreadTotal}
            </span>
          ) : null}
        </span>
        <ChevronDown size={13} />
      </button>

      <div className="nav-divider nav-divider-spaced" />

      <button
        className={`server-identity ${
          openMenu === "workspace" ? "is-open" : ""
        }`}
        type="button"
        title="Switch space"
        aria-label={`Switch from ${workspace?.name ?? "Exocord"}`}
        aria-expanded={openMenu === "workspace"}
        onClick={(event) => {
          event.stopPropagation();
          setOpenMenu((current) =>
            current === "workspace" ? null : "workspace",
          );
        }}
      >
        <strong>{workspace?.name ?? "Exocord"}</strong>
        <ChevronDown size={13} />
      </button>

      <div className="nav-divider nav-divider-spaced" />
      <nav ref={channelTabsRef} className="channel-tabs" aria-label="Channels">
        {workspace?.channels.map((channel) => (
          <button
            className={`channel-tab ${
              channel.id === activeChannelId ? "is-active" : ""
            }`}
            type="button"
            key={channel.id}
            aria-pressed={channel.id === activeChannelId}
            onClick={(event) => {
              event.stopPropagation();
              onSelectChannel(channel.id);
            }}
          >
            {workspace.directMessages ? (
              <AtSign size={14} strokeWidth={1.7} />
            ) : (
              <Hash size={14} strokeWidth={1.7} />
            )}
            <span>{channel.name}</span>
            {channel.unread ? <span className="unread-dot" /> : null}
          </button>
        ))}
        {workspace?.voiceRooms.map((room) => {
          const participants =
            room.id === voiceSession.roomId
              ? voiceSession.participants
              : room.participants;
          return (
            <button
              className={`channel-tab voice-tab ${
                room.id === activeVoiceRoomId ? "is-connected" : ""
              }`}
              type="button"
              key={room.id}
              aria-label={room.name}
              aria-pressed={room.id === activeVoiceRoomId}
              onClick={(event) => {
                event.stopPropagation();
                onSelectVoice(room.id);
              }}
            >
              <Volume2 size={14} strokeWidth={1.7} />
              <span>{room.name}</span>
              {participants.length > 0 ? (
                <span className="voice-count" aria-label={`${participants.length} in voice`}>
                  {participants.length}
                </span>
              ) : null}
            </button>
          );
        })}
      </nav>

      <label className="channel-compact-control">
        <span className="visually-hidden">Current channel</span>
        <select
          className="channel-compact-select"
          aria-label="Current channel"
          value={compactSelection}
          onChange={(event) => {
            const value = event.target.value;
            if (value.startsWith("voice:")) {
              onSelectVoice(value.slice("voice:".length));
            } else {
              onSelectChannel(value);
            }
          }}
        >
          {workspace?.directMessages ? (
            <option value="">Messages</option>
          ) : null}
          {workspace?.channels.map((channel) => (
            <option value={channel.id} key={channel.id}>
              {workspace.directMessages ? "@" : "#"}{channel.name}
            </option>
          ))}
          {workspace && !workspace.directMessages && workspace.voiceRooms.length > 0 ? (
            <optgroup label="Voice">
              {workspace.voiceRooms.map((room) => (
                <option value={`voice:${room.id}`} key={room.id}>
                  {room.name}
                </option>
              ))}
            </optgroup>
          ) : null}
        </select>
      </label>

      {workspace?.directMessages && activeChannelId ? (
        <button
          className={`dm-call-button ${
            voiceSession.roomId === activeChannelId &&
            voiceSession.status !== "idle"
              ? "is-active"
              : ""
          }`}
          type="button"
          aria-label="Start or open voice call"
          title="Voice call"
          onClick={(event) => {
            event.stopPropagation();
            onSelectVoice(activeChannelId);
          }}
        >
          <Headphones size={15} />
          <span>Call</span>
        </button>
      ) : null}

      {workspace && !workspace.directMessages ? (
        <>
          <button
            className={`members-quick-control ${
              openMenu === "members" ? "is-open" : ""
            }`}
            type="button"
            aria-label={`${onlineMembers.length} members online`}
            aria-expanded={openMenu === "members"}
            onClick={(event) => {
              event.stopPropagation();
              setOpenMenu((current) =>
                current === "members" ? null : "members",
              );
            }}
          >
            <Users size={14} />
            <span>{onlineMembers.length} online</span>
            <ChevronDown size={13} />
          </button>
          {openMenu === "members" ? (
            <GlassSurface
              as="section"
              variant="regular"
              className="chrome-popover member-popover"
              aria-label="Server members"
            >
              <div className="member-popover-heading">
                <span>Members</span>
                <strong>{workspaceMembers.length}</strong>
              </div>
              <div className="member-popover-group">
                <div className="member-popover-group-heading">
                  <span>Online</span>
                  <small>{onlineMembers.length}</small>
                </div>
                {onlineMembers.length === 0 ? (
                  <p className="member-popover-empty">No one else is online.</p>
                ) : (
                  onlineMembers.map((member) => (
                    <button
                      type="button"
                      className="member-popover-row"
                      key={member.id}
                      onClick={() => {
                        setOpenMenu(null);
                        onOpenMemberProfile(member);
                      }}
                    >
                      <Avatar member={member} size="small" showPresence />
                      <span>
                        <strong>{member.name}</strong>
                        <small>
                          {presenceLabel(member.presence)}
                        </small>
                      </span>
                    </button>
                  ))
                )}
              </div>
              {offlineMembers.length > 0 ? (
                <div className="member-popover-group is-offline">
                  <div className="member-popover-group-heading">
                    <span>Offline</span>
                    <small>{offlineMembers.length}</small>
                  </div>
                  {offlineMembers.map((member) => (
                    <button
                      type="button"
                      className="member-popover-row"
                      key={member.id}
                      onClick={() => {
                        setOpenMenu(null);
                        onOpenMemberProfile(member);
                      }}
                    >
                      <Avatar member={member} size="small" />
                      <span>
                        <strong>{member.name}</strong>
                        <small>Offline</small>
                      </span>
                    </button>
                  ))}
                </div>
              ) : null}
            </GlassSurface>
          ) : null}
        </>
      ) : null}

      <WindowControls />

      {openMenu === "profile" ? (
        <GlassSurface
          as="section"
          variant="regular"
          className="chrome-popover profile-popover"
          aria-label="Your messages and settings"
        >
          <div className="profile-popover-heading">
            {currentUser ? (
              <Avatar member={currentUser} size="large" showPresence />
            ) : (
              <span className="profile-fallback profile-fallback-large">EX</span>
            )}
            <span>
              <strong>{currentUser?.name ?? "Exocord user"}</strong>
              <small>@{currentUser?.handle ?? "account"}</small>
            </span>
            <i
              className={`profile-presence-dot presence-${currentUser?.presence ?? "offline"}`}
              title={presenceLabel(currentUser?.presence ?? "offline")}
              aria-label={presenceLabel(currentUser?.presence ?? "offline")}
            />
          </div>
          <div className="popover-divider" />
          <div className="popover-actions">
            <button type="button" onClick={() => closeAnd(onOpenSearch)}>
              <Search size={15} /> Search
            </button>
            <button type="button" onClick={() => closeAnd(onOpenSettings)}>
              <Settings2 size={15} /> Settings
            </button>
            <button
              className="is-danger"
              type="button"
              onClick={() => {
                setOpenMenu(null);
                void onLogout();
              }}
            >
              <LogOut size={15} /> Sign out
            </button>
          </div>
        </GlassSurface>
      ) : null}

      {openMenu === "workspace" ? (
        <GlassSurface
          as="section"
          variant="regular"
          className="chrome-popover workspace-popover"
          aria-label="Switch space"
        >
          <div className="popover-kicker">
            <span>SPACES</span>
            <small>{visibleWorkspaces.length}</small>
          </div>
          <div className="workspace-popover-list">
            {visibleWorkspaces.map((candidate) => (
              <button
                className={
                  candidate.id === activeWorkspaceId ? "is-active" : ""
                }
                type="button"
                key={candidate.id}
                aria-pressed={candidate.id === activeWorkspaceId}
                onClick={() => chooseWorkspace(candidate)}
              >
                <span
                  className="popover-orb"
                  style={
                    {
                      "--workspace-accent": candidate.accent,
                    } as React.CSSProperties
                  }
                >
                  {candidate.directMessages ? (
                    <MessageCircle size={14} />
                  ) : (
                    candidate.initials
                  )}
                </span>
                <span>
                  <strong>{candidate.name}</strong>
                  <small>
                    {candidate.directMessages
                      ? "Friends and direct messages"
                      : `${candidate.channels.length} text · ${candidate.voiceRooms.length} voice`}
                  </small>
                </span>
                {(candidate.unreadCount ?? 0) > 0 ? (
                  <i>
                    {(candidate.unreadCount ?? 0) > 99
                      ? "99+"
                      : (candidate.unreadCount ?? 0)}
                  </i>
                ) : candidate.id === activeWorkspaceId ? (
                  <Check size={14} />
                ) : null}
              </button>
            ))}
          </div>
          <div className="popover-divider" />
          <div className="popover-actions">
            <button
              type="button"
              onClick={() =>
                closeAnd(
                  workspace?.directMessages
                    ? onOpenFriends
                    : onOpenServerMenu,
                )
              }
            >
              {workspace?.directMessages ? (
                <Users size={15} />
              ) : (
                <Server size={15} />
              )}
              {workspace?.directMessages ? "Friends" : "Server controls"}
            </button>
            <button
              type="button"
              onClick={() => closeAnd(onCreateWorkspace)}
            >
              <Plus size={15} /> Create or join a server
            </button>
          </div>
        </GlassSurface>
      ) : null}
    </GlassSurface>
  );
}

function EmojiPicker({
  anchor,
  onSelect,
  onClose,
}: {
  anchor: HTMLElement;
  onSelect: (emoji: string) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const pickerRef = useRef<HTMLDivElement>(null);
  const rect = anchor.getBoundingClientRect();
  const width = 316;
  const height = 338;
  const left = Math.max(10, Math.min(window.innerWidth - width - 10, rect.right - width));
  const top =
    rect.top > height + 14
      ? rect.top - height - 8
      : Math.min(window.innerHeight - height - 10, rect.bottom + 8);
  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (
        !pickerRef.current?.contains(event.target as Node) &&
        !anchor.contains(event.target as Node)
      ) {
        onClose();
      }
    };
    const escape = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", escape);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", escape);
    };
  }, [anchor, onClose]);
  const normalized = query.trim().toLocaleLowerCase();
  return createPortal(
    <div
      ref={pickerRef}
      className="emoji-picker"
      role="dialog"
      aria-label="Choose an emoji"
      style={{ left, top }}
    >
      <div className="emoji-search">
        <Search size={14} />
        <input
          value={query}
          autoFocus
          aria-label="Search emoji"
          placeholder="Search emoji"
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>
      <div className="emoji-catalog">
        {searchEmojiCatalog(normalized).map(([category, entries]) => {
          return (
            <section key={category}>
              <h3>{category}</h3>
              <div>
                {entries.map(([emoji, name]) => (
                  <button
                    type="button"
                    title={name}
                    aria-label={name}
                    key={`${category}-${emoji}`}
                    onClick={() => onSelect(emoji)}
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </div>,
    document.body,
  );
}

function MessageItem({
  message,
  member,
  replyPreview,
  focused,
  canReport,
  canEdit,
  canDelete,
  canReact,
  editing,
  editValue,
  deleteArmed,
  busy,
  onReport,
  onReply,
  onEdit,
  onEditValue,
  onSaveEdit,
  onCancelEdit,
  onDelete,
  onRetry,
  onReact,
  onOpenMemberProfile,
}: {
  message: ChatMessage;
  member?: Member;
  replyPreview?: { author: string; text: string };
  focused?: boolean;
  canReport: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canReact: boolean;
  editing: boolean;
  editValue: string;
  deleteArmed: boolean;
  busy: boolean;
  onReport: () => void;
  onReply: () => void;
  onEdit: () => void;
  onEditValue: (value: string) => void;
  onSaveEdit: () => void;
  onCancelEdit: () => void;
  onDelete: () => void;
  onRetry: () => void;
  onReact: (emoji: string, added: boolean) => void;
  onOpenMemberProfile: (member: Member) => void;
}) {
  const [emojiOpen, setEmojiOpen] = useState(false);
  const emojiAnchorRef = useRef<HTMLButtonElement>(null);
  if (!member) return null;

  const contentParts = message.content.split(/(@[a-zA-Z0-9_-]+)/g);
  const reply = replyPreview ?? message.reply;
  const actionable = message.deliveryState !== "pending";

  return (
    <article
      id={`message-${message.id}`}
      className={`message-item ${focused ? "is-search-focus" : ""}`}
    >
      {actionable ? (
        <div className="message-actions" aria-label="Message actions">
          <button type="button" title="Reply" onClick={onReply} disabled={busy}>
            <Reply size={13} />
          </button>
          {canReact ? (
            <button
              ref={emojiAnchorRef}
              type="button"
              title="Add reaction"
              aria-expanded={emojiOpen}
              onClick={() => setEmojiOpen((open) => !open)}
              disabled={busy}
            >
              <SmilePlus size={13} />
            </button>
          ) : null}
          {canEdit ? (
            <button type="button" title="Edit" onClick={onEdit} disabled={busy}>
              <Pencil size={12} />
            </button>
          ) : null}
          {canDelete ? (
            <button
              className={deleteArmed ? "is-danger-armed" : ""}
              type="button"
              title={deleteArmed ? "Confirm delete" : "Delete"}
              onClick={onDelete}
              disabled={busy}
            >
              {deleteArmed ? <span>delete?</span> : <Trash2 size={12} />}
            </button>
          ) : null}
        </div>
      ) : null}
      {emojiOpen && emojiAnchorRef.current ? (
        <EmojiPicker
          anchor={emojiAnchorRef.current}
          onClose={() => setEmojiOpen(false)}
          onSelect={(emoji) => {
            const mine = message.reactions?.some(
              (reaction) => reaction.emoji === emoji && reaction.me,
            );
            onReact(emoji, !mine);
            setEmojiOpen(false);
          }}
        />
      ) : null}
      <button
        className="member-avatar-trigger"
        type="button"
        aria-label={`Open ${member.name}'s profile`}
        onClick={() => onOpenMemberProfile(member)}
      >
        <Avatar member={member} />
      </button>
      <div className="message-content">
        {reply ? (
          <div className="reply-preview">
            <span>{reply.author}</span>
            <p>{reply.text}</p>
          </div>
        ) : null}
        <div className="message-meta">
          <button
            className="member-name-trigger"
            type="button"
            onClick={() => onOpenMemberProfile(member)}
          >
            {member.name}
          </button>
          <time
            dateTime={message.sentAt}
            title={
              messageDate(message.sentAt)?.toLocaleString() ?? message.sentAt
            }
          >
            {formatMessageTime(message.sentAt)}
          </time>
          {message.edited ? <span className="message-edited">edited</span> : null}
        </div>
        {editing ? (
          <div className="message-editor">
            <textarea
              value={editValue}
              maxLength={4000}
              autoFocus
              aria-label="Edit message"
              onChange={(event) => onEditValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") onCancelEdit();
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  onSaveEdit();
                }
              }}
            />
          </div>
        ) : (
          <p className="message-copy">
            {contentParts.map((part, index) =>
              part.startsWith("@") ? (
                <mark key={`${part}-${index}`}>{part}</mark>
              ) : (
                part
              ),
            )}
          </p>
        )}
        {(message.attachments ?? []).length > 0 ? (
          <div className="message-attachments">
            {(message.attachments ?? []).map((attachment) => (
              <AttachmentCard
                attachment={attachment}
                channelId={message.channelId}
                key={attachment.id}
              />
            ))}
          </div>
        ) : null}
        <div className="message-footer">
          {message.reactions?.map((reaction) => (
            <button
              className={`reaction ${reaction.me ? "is-mine" : ""}`}
              type="button"
              key={reaction.emoji}
              aria-label={`${reaction.emoji}, ${reaction.count} reactions`}
              aria-pressed={reaction.me ?? false}
              disabled={busy || (!canReact && !reaction.me)}
              onClick={() => onReact(reaction.emoji, !reaction.me)}
            >
              <span>{reaction.emoji}</span>
              <span>{reaction.count}</span>
            </button>
          ))}
          {message.deliveryState === "pending" ? (
            <span className="delivery-pending">
              <LoaderCircle size={11} /> queued
            </span>
          ) : null}
          {message.deliveryState === "failed" ? (
            <button
              className="delivery-failed"
              type="button"
              onClick={onRetry}
              disabled={busy}
              aria-label="Retry delivering this message"
            >
              <RefreshCw size={11} />
              <span>Retry delivery</span>
            </button>
          ) : null}
          {canReport && message.deliveryState !== "pending" ? (
            <button
              className="message-report-button"
              type="button"
              onClick={onReport}
              aria-label={`Report message from ${member.handle}`}
            >
              <Flag size={11} /> report
            </button>
          ) : null}
        </div>
      </div>
    </article>
  );
}

function ReportDialog({
  message,
  member,
  onClose,
}: {
  message: ChatMessage | null;
  member?: Member;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLFormElement>(message !== null, onClose);
  const [category, setCategory] = useState<ReportCategory>("harassment");
  const [detail, setDetail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receiptId, setReceiptId] = useState<string | null>(null);

  useEffect(() => {
    if (!message) return;
    setCategory("harassment");
    setDetail("");
    setSubmitting(false);
    setError(null);
    setReceiptId(null);
  }, [message]);

  if (!message) return null;
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const receipt = await coreBridge.reportMessage({
        messageId: message.id,
        category,
        detail: detail.trim() || undefined,
      });
      setReceiptId(receipt.id);
    } catch (nextError) {
      setError(
        nextError instanceof Error
          ? nextError.message
          : "The report could not be submitted.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <form
        ref={dialogRef}
        className="modal-card report-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label="Report message"
        onSubmit={(event) => void submit(event)}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close report"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="modal-icon report-icon">
          <Flag size={18} />
        </div>
        {receiptId ? (
          <>
            <h2>Report received</h2>
            <p>
              The verified message evidence was submitted. Reference{" "}
              <code>{receiptId}</code>.
            </p>
            <button className="primary-button" type="button" onClick={onClose}>
              Done
            </button>
          </>
        ) : (
          <>
            <h2>Report message</h2>
            <p>
              Report @{member?.handle ?? "member"}. For encrypted messages,
              only this one verified message is revealed to the safety team.
            </p>
            <label className="field-label" htmlFor="report-category">
              Category
            </label>
            <select
              id="report-category"
              value={category}
              onChange={(event) =>
                setCategory(event.target.value as ReportCategory)
              }
            >
              <option value="spam">Spam</option>
              <option value="harassment">Harassment</option>
              <option value="threats_violence">Threats or violence</option>
              <option value="sexual_content_involving_minors">
                Sexual content involving minors
              </option>
              <option value="self_harm">Self-harm</option>
              <option value="illegal_content">Illegal content</option>
              <option value="impersonation">Impersonation</option>
              <option value="other">Other</option>
            </select>
            <label className="field-label" htmlFor="report-detail">
              Optional context
            </label>
            <textarea
              id="report-detail"
              rows={4}
              maxLength={2000}
              value={detail}
              onChange={(event) => setDetail(event.target.value)}
              placeholder="What should the safety team know?"
            />
            {error ? <p className="form-error">{error}</p> : null}
            <button className="primary-button" type="submit" disabled={submitting}>
              {submitting ? <LoaderCircle className="spin" size={14} /> : <Flag size={14} />}
              {submitting ? "Submitting verified evidence" : "Submit report"}
            </button>
          </>
        )}
      </form>
    </div>
  );
}

function AttachmentCard({
  attachment,
  channelId,
}: {
  attachment: MessageAttachment;
  channelId: string;
}) {
  const [decryptedUrl, setDecryptedUrl] = useState<string | null>(
    attachment.encryption ? null : resolveAttachmentUrl(attachment.url),
  );
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const [decryptionError, setDecryptionError] = useState<string | null>(null);
  useEffect(() => {
    const sourceUrl = resolveAttachmentUrl(attachment.url);
    if (!attachment.encryption) {
      setDecryptedUrl(sourceUrl);
      setDecryptionError(null);
      return;
    }
    const encryption = attachment.encryption;
    let active = true;
    let objectUrl: string | null = null;
    void (async () => {
      const response = await fetch(sourceUrl, {
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
      if (!response.ok) {
        throw new Error(`Encrypted attachment download failed (${response.status}).`);
      }
      const ciphertext = await response.arrayBuffer();
      const ciphertextHash = await sha256HexBuffer(ciphertext);
      if (ciphertextHash !== encryption.ciphertextSha256) {
        throw new Error("Encrypted attachment integrity check failed.");
      }
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBase64Url(encryption.nonce),
          additionalData: new TextEncoder().encode(
            attachmentAdditionalData(
              channelId,
              attachment.filename,
              attachment.contentType,
              attachment.size,
            ),
          ),
          tagLength: 128,
        },
        await crypto.subtle.importKey(
          "raw",
          decodeBase64Url(encryption.key),
          "AES-GCM",
          false,
          ["decrypt"],
        ),
        ciphertext,
      );
      if ((await sha256HexBuffer(plaintext)) !== encryption.plaintextSha256) {
        throw new Error("Decrypted attachment integrity check failed.");
      }
      objectUrl = URL.createObjectURL(
        new Blob([plaintext], { type: attachment.contentType }),
      );
      if (active) setDecryptedUrl(objectUrl);
    })().catch((error: unknown) => {
      if (!active) return;
      setDecryptionError(
        error instanceof Error
          ? error.message
          : "This encrypted attachment could not be opened.",
      );
    });
    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [attachment, channelId]);

  const dimensions =
    attachment.width && attachment.height
      ? `${attachment.width} × ${attachment.height}`
      : null;
  const label = `${formatBytes(attachment.size)}${
    dimensions ? ` · ${dimensions}` : ""
  }`;
  if (attachment.encryption && !decryptedUrl) {
    return (
      <div className="attachment-card attachment-encrypted-state">
        {decryptionError ? <CloudOff size={16} /> : <LoaderCircle className="spin" size={16} />}
        <span>
          <strong>{attachment.filename}</strong>
          <small>
            {decryptionError ?? "Decrypting attachment on this device…"}
          </small>
        </span>
      </div>
    );
  }
  const attachmentUrl = resolveAttachmentUrl(decryptedUrl ?? attachment.url);
  if (attachment.contentType.startsWith("image/")) {
    return (
      <>
        <figure className="attachment-image">
          <button
            className="attachment-image-trigger"
            type="button"
            aria-label={`View ${attachment.filename} larger`}
            onClick={() => setLightboxOpen(true)}
          >
          <img
            src={attachmentUrl}
            alt={attachment.filename}
            width={attachment.width ?? undefined}
            height={attachment.height ?? undefined}
            loading="lazy"
            decoding="async"
            referrerPolicy="no-referrer"
          />
          </button>
        </figure>
        {lightboxOpen ? (
          <AttachmentLightbox
            attachment={attachment}
            url={attachmentUrl}
            onClose={() => setLightboxOpen(false)}
          />
        ) : null}
      </>
    );
  }
  if (attachment.contentType.startsWith("video/")) {
    return (
      <figure className="attachment-card attachment-video">
        <video
          src={attachmentUrl}
          controls
          preload="metadata"
          playsInline
          aria-label={attachment.filename}
        />
        <figcaption>
          <Film size={14} />
          <span>{attachment.filename}</span>
          <span>{label}</span>
        </figcaption>
      </figure>
    );
  }
  if (attachment.contentType.startsWith("audio/")) {
    return (
      <div className="attachment-card attachment-audio">
        <div className="attachment-file-heading">
          <Music size={15} />
          <span>
            <strong>{attachment.filename}</strong>
            <small>{label}</small>
          </span>
        </div>
        <audio src={attachmentUrl} controls preload="metadata" />
      </div>
    );
  }
  return (
    <a
      className="attachment-card attachment-file"
      href={attachmentUrl}
      download={attachment.filename}
      target="_blank"
      rel="noreferrer"
    >
      <span className="attachment-file-icon">
        <FileText size={17} />
      </span>
      <span>
        <strong>{attachment.filename}</strong>
        <small>{label}</small>
      </span>
      <Download size={15} />
    </a>
  );
}

function AttachmentLightbox({
  attachment,
  url,
  onClose,
}: {
  attachment: MessageAttachment;
  url: string;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLDivElement>(true, onClose);
  const [viewer, dispatch] = useReducer(
    imageViewerReducer,
    true,
    createImageViewerState,
  );
  const dragRef = useRef<{ pointerId: number; x: number; y: number } | null>(
    null,
  );
  const normalizedUrl = resolveAttachmentUrl(url);
  const panImage = (event: React.PointerEvent<HTMLImageElement>) => {
    if (viewer.zoom <= 1) return;
    if (!dragRef.current || dragRef.current.pointerId !== event.pointerId) return;
    dispatch({
      type: "pan",
      x: viewer.offsetX + event.clientX - dragRef.current.x,
      y: viewer.offsetY + event.clientY - dragRef.current.y,
    });
    dragRef.current = {
      pointerId: event.pointerId,
      x: event.clientX,
      y: event.clientY,
    };
  };
  return createPortal(
    <div
      className="attachment-lightbox-backdrop"
      role="presentation"
      onMouseDown={onClose}
    >
      <div
        ref={dialogRef}
        className="attachment-lightbox"
        role="dialog"
        aria-modal="true"
        aria-label={`Preview ${attachment.filename}`}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <GlassSurface
          as="header"
          variant="clear"
          className="attachment-lightbox-header"
        >
          <div>
            <strong>{attachment.filename}</strong>
            <small>
              {formatBytes(attachment.size)}
              {attachment.width && attachment.height
                ? ` · ${attachment.width} × ${attachment.height}`
                : ""}
            </small>
          </div>
          <div className="attachment-lightbox-actions">
            <a
              href={normalizedUrl}
              target="_blank"
              rel="noreferrer"
              className="attachment-lightbox-action"
            >
              <Link2 size={15} />
              <span>Open original</span>
            </a>
            <a
              href={normalizedUrl}
              download={attachment.filename}
              className="attachment-lightbox-action"
            >
              <Download size={15} />
              <span>Download</span>
            </a>
            <button
              className="attachment-lightbox-action"
              type="button"
              aria-label="Fit image"
              onClick={() => dispatch({ type: "set_zoom", zoom: 1 })}
            >
              <Maximize2 size={14} />
              <span>Fit</span>
            </button>
            <button
              className="attachment-lightbox-action"
              type="button"
              aria-label="Actual image size"
              onClick={() => dispatch({ type: "set_zoom", zoom: 2 })}
            >
              <span className="attachment-lightbox-zoom-label">100%</span>
            </button>
            <button
              className="attachment-lightbox-action"
              type="button"
              aria-label="Zoom out"
              onClick={() => dispatch({ type: "zoom_out" })}
              disabled={viewer.zoom <= 0.5}
            >
              −
            </button>
            <button
              className="attachment-lightbox-action"
              type="button"
              aria-label="Zoom in"
              onClick={() => dispatch({ type: "zoom_in" })}
              disabled={viewer.zoom >= 4}
            >
              +
            </button>
            <button
              className="attachment-lightbox-close"
              type="button"
              aria-label="Close image preview"
              onClick={onClose}
            >
              <X size={17} />
            </button>
          </div>
        </GlassSurface>
        <div
          className={`attachment-lightbox-stage ${viewer.zoom > 1 ? "is-zoomed" : ""}`}
          onWheel={(event) => {
            event.preventDefault();
            dispatch({
              type: "set_zoom",
              zoom: viewer.zoom + (event.deltaY < 0 ? 0.25 : -0.25),
            });
          }}
          onDoubleClick={() =>
            dispatch({ type: "set_zoom", zoom: viewer.zoom > 1 ? 1 : 2 })
          }
        >
          {viewer.loading ? (
            <span className="attachment-lightbox-status">Loading image…</span>
          ) : null}
          {viewer.error ? (
            <div className="attachment-lightbox-status is-error" role="alert">
              <CloudOff size={16} />
              <span>{viewer.error}</span>
            </div>
          ) : null}
          <img
            src={normalizedUrl}
            alt={attachment.filename}
            width={attachment.width ?? undefined}
            height={attachment.height ?? undefined}
            referrerPolicy="no-referrer"
            draggable={false}
            onLoad={() => dispatch({ type: "load" })}
            onError={() => dispatch({ type: "error" })}
            onPointerDown={(event) => {
              if (viewer.zoom <= 1) return;
              event.currentTarget.setPointerCapture(event.pointerId);
              dragRef.current = {
                pointerId: event.pointerId,
                x: event.clientX,
                y: event.clientY,
              };
            }}
            onPointerMove={panImage}
            onPointerUp={(event) => {
              if (dragRef.current?.pointerId === event.pointerId) {
                dragRef.current = null;
              }
            }}
            style={{
              transform: `translate3d(${viewer.offsetX}px, ${viewer.offsetY}px, 0) scale(${viewer.zoom})`,
            }}
          />
        </div>
      </div>
    </div>,
    document.body,
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function attachmentAdditionalData(
  channelId: string,
  filename: string,
  contentType: string,
  size: number,
): string {
  return `exocord-attachment-v1\n${channelId}\n${filename}\n${contentType}\n${size}`;
}

function decodeBase64Url(value: string): ArrayBuffer {
  const padded = `${value.replaceAll("-", "+").replaceAll("_", "/")}${"=".repeat(
    (4 - (value.length % 4)) % 4,
  )}`;
  const binary = atob(padded);
  return Uint8Array.from(
    binary,
    (character) => character.charCodeAt(0),
  ).buffer as ArrayBuffer;
}

async function sha256HexBuffer(value: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function VoicePanel({
  room,
  membersById,
  collapsed,
  session,
  onCollapse,
  onToggleMute,
  onToggleDeafen,
  onToggleShare,
  onResumeAudio,
  onLeave,
  onOpenMemberProfile,
}: {
  room?: VoiceRoom;
  membersById: Map<string, Member>;
  collapsed: boolean;
  session: VoiceSessionSnapshot;
  onCollapse: () => void;
  onToggleMute: () => void;
  onToggleDeafen: () => void;
  onToggleShare: () => void;
  onResumeAudio: () => void;
  onLeave: () => void;
  onOpenMemberProfile: (member: Member) => void;
}) {
  const [devicesOpen, setDevicesOpen] = useState(false);
  const [devices, setDevices] = useState<VoiceDeviceSnapshot | null>(null);
  const [deviceBusy, setDeviceBusy] = useState(false);
  const [deviceError, setDeviceError] = useState<string | null>(null);

  useEffect(() => {
    setDevicesOpen(false);
    setDevices(null);
    setDeviceError(null);
  }, [room?.id]);

  const openDevices = async () => {
    if (devicesOpen) {
      setDevicesOpen(false);
      return;
    }
    setDevicesOpen(true);
    setDeviceBusy(true);
    setDeviceError(null);
    try {
      setDevices(await voiceClient.devices());
    } catch (error: unknown) {
      setDeviceError(
        error instanceof Error
          ? error.message
          : "Media devices could not be listed.",
      );
    } finally {
      setDeviceBusy(false);
    }
  };

  const chooseDevice = async (
    kind: "audioinput" | "audiooutput",
    deviceId: string,
  ) => {
    setDeviceBusy(true);
    setDeviceError(null);
    try {
      await voiceClient.switchDevice(kind, deviceId);
      setDevices((current) =>
        current
          ? {
              ...current,
              activeInputId:
                kind === "audioinput" ? deviceId : current.activeInputId,
              activeOutputId:
                kind === "audiooutput" ? deviceId : current.activeOutputId,
            }
          : current,
      );
    } catch (error: unknown) {
      setDeviceError(
        error instanceof Error ? error.message : "The device could not be selected.",
      );
    } finally {
      setDeviceBusy(false);
    }
  };

  if (!room) {
    return (
      <GlassSurface
        as="aside"
        variant="regular"
        className="voice-panel voice-empty"
      >
        <Volume2 size={18} />
        <strong>Voice is quiet</strong>
        <span>Join a room from the top bar.</span>
      </GlassSurface>
    );
  }

  const screenSharers = room.participants.filter(
    (participant) => participant.screenSharing,
  );
  const connected = session.status === "connected";
  const memberForParticipant = (participant: (typeof room.participants)[number]) => {
    const knownMember = membersById.get(participant.memberId);
    const displayName = resolveVoiceDisplayName(participant, knownMember);
    const member: Member =
      knownMember ?? {
        id: participant.memberId,
        name: displayName,
        handle: "member",
        initials: displayName.slice(0, 2).toUpperCase(),
        color: "#3ecf8e",
        presence: "online",
      };
    return { member, displayName };
  };
  if (collapsed) {
    return (
      <GlassSurface
        as="aside"
        variant="regular"
        className="voice-rail"
        onClick={onResumeAudio}
      >
        <button
          className="voice-rail-open"
          type="button"
          aria-label="Show voice details"
          onClick={onCollapse}
        >
          <Volume2 size={16} />
        </button>
        <div className="voice-rail-summary" aria-label={`${room.name} voice call`}>
          <span className={`voice-live-dot voice-status-${session.status}`} />
          <span>
            <strong>{room.name}</strong>
            <small>
              {session.status === "connecting" || session.status === "reconnecting"
                ? session.status
                : `${room.participants.length} ${
                    room.participants.length === 1 ? "person" : "people"
                  }`}
            </small>
          </span>
        </div>
        <div className="voice-rail-members" aria-label="Call participants">
          {room.participants.slice(0, 6).map((participant) => {
            const { member } = memberForParticipant(participant);
            return (
              <button
                type="button"
                className={`voice-rail-member-trigger ${
                  participant.state === "speaking" ? "is-speaking" : ""
                }`}
                aria-label={`Open ${member.name}'s profile`}
                onClick={(event) => {
                  event.stopPropagation();
                  onOpenMemberProfile(member);
                }}
                key={participant.memberId}
              >
                <Avatar member={member} size="small" />
              </button>
            );
          })}
        </div>
        <div className="voice-rail-actions">
          <button
            className={session.muted ? "control-active" : ""}
            type="button"
            aria-label="Toggle microphone"
            disabled={!connected || !session.canSpeak}
            onClick={onToggleMute}
          >
            {session.muted ? <MicOff size={15} /> : <Mic size={15} />}
          </button>
          <button
            className="leave-call"
            type="button"
            aria-label="Leave the call"
            onClick={onLeave}
          >
            <LogOut size={15} />
          </button>
        </div>
      </GlassSurface>
    );
  }

  return (
    <GlassSurface
      as="aside"
      variant="regular"
      className="voice-panel"
      onClick={onResumeAudio}
    >
      <div className="voice-panel-heading">
        <div className={`voice-live-dot voice-status-${session.status}`} />
        <div className="voice-heading-copy">
          <strong>{room.name}</strong>
          <span>
            {session.status === "connecting"
              ? "connecting"
              : session.status === "reconnecting"
                ? "reconnecting"
                : `${room.participants.length} ${
                    room.participants.length === 1 ? "person" : "people"
                  }`}
          </span>
        </div>
        <button
          type="button"
          aria-label="Collapse voice panel"
          onClick={onCollapse}
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {session.error && !collapsed ? (
        <button
          className="voice-inline-alert"
          type="button"
          onClick={onResumeAudio}
        >
          {session.error}
        </button>
      ) : null}

      {screenSharers.length > 0 && !collapsed ? (
        <div className="voice-screen-grid">
          {screenSharers.map((participant) => (
            <ScreenShareStage
              key={participant.memberId}
              participantId={participant.memberId}
              label={`${resolveVoiceDisplayName(
                participant,
                membersById.get(participant.memberId),
              )}'s screen`}
            />
          ))}
        </div>
      ) : null}

      <div className="voice-participants">
        {room.participants.map((participant) => {
          const { member, displayName } = memberForParticipant(participant);
          return (
            <div
              className={`voice-person voice-${participant.state}`}
              key={participant.memberId}
            >
              <button
                type="button"
                className="voice-member-trigger"
                aria-label={`Open ${displayName}'s profile`}
                onClick={() => onOpenMemberProfile(member)}
              >
                <Avatar member={member} />
                <span className="voice-person-copy">
                  <strong>{displayName}</strong>
                </span>
              </button>
              {participant.state === "speaking" ? (
                <span className="voice-meter" aria-label="Speaking">
                  <i />
                  <i />
                  <i />
                  <i />
                  <i />
                </span>
              ) : participant.state === "muted" ? (
                <MicOff size={14} />
              ) : (
                <Mic size={14} />
              )}
              <i
                className={`voice-quality voice-quality-${
                  participant.connectionQuality ?? "unknown"
                }`}
                title={`${participant.connectionQuality ?? "unknown"} connection`}
              />
            </div>
          );
        })}
      </div>

      {devicesOpen && !collapsed ? (
        <div
          className="voice-device-picker"
          onClick={(event) => event.stopPropagation()}
        >
          <div className="voice-device-picker-heading">
            <strong>Voice devices</strong>
            {deviceBusy ? <LoaderCircle className="spin" size={12} /> : null}
          </div>
          {deviceError ? <p>{deviceError}</p> : null}
          <label>
            <span>Microphone</span>
            <select
              value={devices?.activeInputId ?? ""}
              disabled={deviceBusy || !devices?.inputs.length}
              onChange={(event) =>
                void chooseDevice("audioinput", event.target.value)
              }
            >
              <option value="" disabled>
                Select a microphone
              </option>
              {devices?.inputs.map((device) => (
                <option key={device.deviceId} value={device.deviceId}>
                  {device.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Speakers</span>
            <select
              value={devices?.activeOutputId ?? ""}
              disabled={deviceBusy || !devices?.outputs.length}
              onChange={(event) =>
                void chooseDevice("audiooutput", event.target.value)
              }
            >
              <option value="" disabled>
                System default
              </option>
              {devices?.outputs.map((device) => (
                <option key={device.deviceId} value={device.deviceId}>
                  {device.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      ) : null}

      <div className="voice-controls">
        <button
          className={session.muted ? "control-active" : ""}
          type="button"
          aria-label="Toggle microphone"
          aria-pressed={session.muted}
          disabled={!connected || !session.canSpeak}
          onClick={onToggleMute}
        >
          {session.muted ? <MicOff size={16} /> : <Mic size={16} />}
        </button>
        <button
          className={devicesOpen ? "control-active" : ""}
          type="button"
          aria-label="Choose voice devices"
          aria-expanded={devicesOpen}
          disabled={!connected}
          onClick={(event) => {
            event.stopPropagation();
            void openDevices();
          }}
        >
          <Settings2 size={16} />
        </button>
        <button
          className={session.deafened ? "control-active" : ""}
          type="button"
          aria-label="Toggle deafen"
          aria-pressed={session.deafened}
          disabled={!connected}
          onClick={onToggleDeafen}
        >
          {session.deafened ? (
            <VolumeX size={16} />
          ) : (
            <Headphones size={16} />
          )}
        </button>
        <button
          className={session.sharing ? "control-active" : ""}
          type="button"
          aria-label="Share your screen"
          aria-pressed={session.sharing}
          disabled={!connected || !session.canStream}
          onClick={onToggleShare}
        >
          <MonitorUp size={16} />
        </button>
        <button
          className="leave-call"
          type="button"
          aria-label="Leave the call"
          onClick={onLeave}
        >
          <X size={17} />
        </button>
      </div>
    </GlassSurface>
  );
}

function ScreenShareStage({
  participantId,
  label,
}: {
  participantId: string;
  label: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    return voiceClient.attachScreenShare(container, participantId);
  }, [participantId]);

  return (
    <figure className="voice-screen-stage">
      <div ref={containerRef} />
      <figcaption>
        <MonitorUp size={11} />
        {label}
      </figcaption>
    </figure>
  );
}

function CreateServerDialog({
  open,
  busy,
  onClose,
  onCreate,
  onJoin,
}: {
  open: boolean;
  busy: boolean;
  onClose: () => void;
  onCreate: (name: string) => Promise<void>;
  onJoin: (code: string) => Promise<void>;
}) {
  const dialogRef = useDialogFocus<HTMLFormElement>(open, onClose);
  const [mode, setMode] = useState<"create" | "join">("create");
  const [name, setName] = useState("");
  const [inviteValue, setInviteValue] = useState("");
  const [preview, setPreview] = useState<InvitePreview | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setMode("create");
      setName("");
      setInviteValue("");
      setPreview(null);
      setError(null);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  if (!open) return null;

  const submit = async () => {
    if (mode === "create") {
      if (name.trim().length >= 2) await onCreate(name.trim());
      return;
    }
    if (preview) {
      await onJoin(preview.code);
      return;
    }
    setInspecting(true);
    setError(null);
    try {
      setPreview(await coreBridge.previewServerInvite(inviteValue));
    } catch (previewError) {
      setError(
        previewError instanceof Error
          ? previewError.message
          : "That invite is invalid or has expired.",
      );
    } finally {
      setInspecting(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <form
        ref={dialogRef}
        className="modal-card server-access-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label="Create or join a server"
        onMouseDown={(event) => event.stopPropagation()}
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <div className="modal-icon">
          {mode === "create" ? <Sparkles size={19} /> : <Link2 size={19} />}
        </div>
        <h2>{mode === "create" ? "Create your server" : "Join a server"}</h2>
        <div className="server-access-tabs" role="tablist">
          <button
            className={mode === "create" ? "is-active" : ""}
            type="button"
            role="tab"
            aria-selected={mode === "create"}
            onClick={() => {
              setMode("create");
              setError(null);
              requestAnimationFrame(() => inputRef.current?.focus());
            }}
          >
            <Sparkles size={13} /> Create
          </button>
          <button
            className={mode === "join" ? "is-active" : ""}
            type="button"
            role="tab"
            aria-selected={mode === "join"}
            onClick={() => {
              setMode("join");
              setError(null);
              requestAnimationFrame(() => inputRef.current?.focus());
            }}
          >
            <UserPlus size={13} /> Join
          </button>
        </div>
        {mode === "create" ? (
          <>
            <label htmlFor="server-name">Server name</label>
            <input
              id="server-name"
              ref={inputRef}
              value={name}
              maxLength={64}
              placeholder="Night shift"
              onChange={(event) => setName(event.target.value)}
            />
          </>
        ) : preview ? (
          <div className="invite-preview">
            <span
              className="invite-preview-mark"
              style={
                { "--workspace-accent": preview.accent } as React.CSSProperties
              }
            >
              {preview.name.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <strong>{preview.name}</strong>
              <span>
                <Users size={12} /> {preview.memberCount} member
                {preview.memberCount === 1 ? "" : "s"}
              </span>
            </div>
            <button
              type="button"
              onClick={() => {
                setPreview(null);
                requestAnimationFrame(() => inputRef.current?.focus());
              }}
            >
              Change
            </button>
          </div>
        ) : (
          <>
            <label htmlFor="invite-code">Invite code or link</label>
            <input
              id="invite-code"
              ref={inputRef}
              value={inviteValue}
              maxLength={256}
              autoComplete="off"
              spellCheck={false}
              placeholder="Paste an invite"
              onChange={(event) => {
                setInviteValue(event.target.value);
                setError(null);
              }}
            />
          </>
        )}
        {error ? (
          <p className="modal-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="modal-actions">
          <button className="secondary-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="primary-button"
            type="submit"
            disabled={
              busy ||
              inspecting ||
              (mode === "create"
                ? name.trim().length < 2
                : !preview && inviteValue.trim().length < 8)
            }
          >
            {busy
              ? mode === "create"
                ? "Creating…"
                : "Joining…"
              : inspecting
                ? "Checking…"
                : mode === "create"
                  ? "Create server"
                  : preview
                    ? `Join ${preview.name}`
                    : "Check invite"}
          </button>
        </div>
      </form>
    </div>
  );
}

function InvitePeopleDialog({
  open,
  workspace,
  invite,
  busy,
  canInvite,
  canManageRoles,
  canManageChannels,
  canModerate,
  canManageOwnership,
  onGenerate,
  onManageRoles,
  onManageChannels,
  onModerate,
  onManageOwnership,
  onClose,
}: {
  open: boolean;
  workspace?: Workspace;
  invite: InviteView | null;
  busy: boolean;
  canInvite: boolean;
  canManageRoles: boolean;
  canManageChannels: boolean;
  canModerate: boolean;
  canManageOwnership: boolean;
  onGenerate: () => Promise<void>;
  onManageRoles: () => void;
  onManageChannels: () => void;
  onModerate: () => void;
  onManageOwnership: () => void;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [copied, setCopied] = useState(false);

  useEffect(() => setCopied(false), [open, invite?.code]);
  if (!open || !workspace) return null;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card invite-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`Invite people to ${workspace.name}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close invite dialog"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="modal-icon">
          <UserPlus size={19} />
        </div>
        <h2>Invite & manage</h2>
        {invite ? (
          <>
            <div className="invite-code">
              <span>{invite.code}</span>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard
                    .writeText(invite.code)
                    .then(() => setCopied(true))
                    .catch(() => setCopied(false));
                }}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="invite-facts">
              <span>
                <Users size={12} /> Up to {invite.maxUses ?? "unlimited"} uses
              </span>
              <span>
                Expires{" "}
                {invite.expiresAt
                  ? new Intl.DateTimeFormat(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "numeric",
                      minute: "2-digit",
                    }).format(new Date(invite.expiresAt))
                  : "never"}
              </span>
            </div>
          </>
        ) : (
          <button
            className="invite-generate"
            type="button"
            disabled={busy || !canInvite}
            onClick={() => void onGenerate()}
          >
            <Link2 size={15} />
            {busy ? "Creating secure code…" : "Create 24-hour invite"}
          </button>
        )}
        {workspace.localOnly ? (
          <p className="modal-error">
            This server exists only on this device and cannot accept invites.
          </p>
        ) : !canInvite ? (
          <p className="modal-error">
            Your current roles do not allow creating invites.
          </p>
        ) : null}
        <div className="server-control-links">
          {canManageChannels ? (
            <button type="button" onClick={onManageChannels}>
              <Settings2 size={15} />
              Channels & access
              <ChevronRight size={14} />
            </button>
          ) : null}
          {canManageRoles ? (
            <button type="button" onClick={onManageRoles}>
              <ShieldCheck size={15} />
              Roles & permissions
              <ChevronRight size={14} />
            </button>
          ) : null}
          {canModerate ? (
            <button type="button" onClick={onModerate}>
              <Users size={15} />
              Safety & moderation
              <ChevronRight size={14} />
            </button>
          ) : null}
          {canManageOwnership ? (
            <button type="button" onClick={onManageOwnership}>
              <LockKeyhole size={15} />
              Ownership & deletion
              <ChevronRight size={14} />
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function ServerOwnershipDialog({
  open,
  workspace,
  currentUserId,
  onTransfer,
  onDelete,
  onClose,
}: {
  open: boolean;
  workspace?: Workspace;
  currentUserId: string;
  onTransfer: (memberId: string) => Promise<void>;
  onDelete: (confirmation: string) => Promise<void>;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [ownership, setOwnership] = useState<ServerOwnershipView | null>(null);
  const [selectedMemberId, setSelectedMemberId] = useState("");
  const [transferOpen, setTransferOpen] = useState(false);
  const [transferConfirmation, setTransferConfirmation] = useState("");
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [busy, setBusy] = useState<"transfer" | "delete" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !workspace) {
      setOwnership(null);
      setSelectedMemberId("");
      setTransferOpen(false);
      setTransferConfirmation("");
      setDeleteOpen(false);
      setDeleteConfirmation("");
      setBusy(null);
      setError(null);
      return;
    }
    let active = true;
    setError(null);
    void coreBridge
      .loadServerOwnership(workspace.id)
      .then((next) => {
        if (active) setOwnership(next);
      })
      .catch((loadError: unknown) => {
        if (!active) return;
        setError(
          loadError instanceof Error
            ? loadError.message
            : "Ownership controls could not be loaded.",
        );
      });
    return () => {
      active = false;
    };
  }, [open, workspace]);

  if (!open || !workspace) return null;
  const isOwner = ownership?.ownerId === currentUserId;
  const selectedMember = ownership?.members.find(
    (member) => member.id === selectedMemberId,
  );

  const transfer = async () => {
    if (
      busy ||
      !selectedMember ||
      !serverNameConfirmed(transferConfirmation, workspace.name)
    ) {
      return;
    }
    setBusy("transfer");
    setError(null);
    try {
      await onTransfer(selectedMember.id);
      onClose();
    } catch (transferError: unknown) {
      setError(
        transferError instanceof Error
          ? transferError.message
          : "Ownership could not be transferred.",
      );
      setBusy(null);
    }
  };

  const deleteServer = async () => {
    if (busy || !serverNameConfirmed(deleteConfirmation, workspace.name)) return;
    setBusy("delete");
    setError(null);
    try {
      await onDelete(deleteConfirmation);
      onClose();
    } catch (deleteError: unknown) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : "The server could not be deleted.",
      );
      setBusy(null);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card ownership-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`Ownership controls for ${workspace.name}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close ownership controls"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="modal-icon">
          <LockKeyhole size={19} />
        </div>
        <h2>Ownership & deletion</h2>
        <p>
          The owner is the final authority for <strong>{workspace.name}</strong>.
          These actions cannot be undone from this screen.
        </p>
        {!ownership && !error ? (
          <div className="ownership-loading">
            <LoaderCircle className="spin" size={15} />
            Loading members and ownership…
          </div>
        ) : null}
        {ownership && !isOwner ? (
          <p className="modal-error">
            You no longer own this server. Its controls were refreshed.
          </p>
        ) : null}
        {ownership && isOwner ? (
          <>
            <section className="ownership-section">
              <div>
                <ShieldCheck size={16} />
                <span>
                  <strong>Transfer ownership</strong>
                  <small>
                    You stay as a member, but only the new owner can transfer or
                    delete this server.
                  </small>
                </span>
              </div>
              {ownership.members.length ? (
                <>
                  <label htmlFor="ownership-member">New owner</label>
                  <select
                    id="ownership-member"
                    value={selectedMemberId}
                    disabled={busy !== null}
                    onChange={(event) => {
                      setSelectedMemberId(event.target.value);
                      setTransferOpen(false);
                      setTransferConfirmation("");
                    }}
                  >
                    <option value="">Choose a current member</option>
                    {ownership.members.map((member) => (
                      <option key={member.id} value={member.id}>
                        {member.name} · @{member.handle}
                      </option>
                    ))}
                  </select>
                  {!transferOpen ? (
                    <button
                      type="button"
                      disabled={!selectedMemberId || busy !== null}
                      onClick={() => setTransferOpen(true)}
                    >
                      Review transfer
                    </button>
                  ) : (
                    <div className="ownership-confirm">
                      <p>
                        Transfer <strong>{workspace.name}</strong> to{" "}
                        <strong>{selectedMember?.name}</strong>. Type the server
                        name to confirm.
                      </p>
                      <input
                        value={transferConfirmation}
                        autoComplete="off"
                        spellCheck={false}
                        placeholder={workspace.name}
                        onChange={(event) =>
                          setTransferConfirmation(event.target.value)
                        }
                      />
                      <button
                        type="button"
                        disabled={
                          busy !== null ||
                          !serverNameConfirmed(
                            transferConfirmation,
                            workspace.name,
                          )
                        }
                        onClick={() => void transfer()}
                      >
                        {busy === "transfer" ? (
                          <LoaderCircle className="spin" size={13} />
                        ) : (
                          <ShieldCheck size={13} />
                        )}
                        {busy === "transfer"
                          ? "Transferring"
                          : "Transfer ownership"}
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <small className="ownership-empty">
                  Invite another member before transferring this server.
                </small>
              )}
            </section>
            <section className="ownership-section ownership-danger">
              <div>
                <Trash2 size={16} />
                <span>
                  <strong>Delete server</strong>
                  <small>
                    Immediately removes it from every member and disconnects
                    active voice rooms. Retained records follow the data policy.
                  </small>
                </span>
              </div>
              {!deleteOpen ? (
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => setDeleteOpen(true)}
                >
                  Delete server…
                </button>
              ) : (
                <div className="ownership-confirm">
                  <label htmlFor="delete-server-confirmation">
                    Type <code>{workspace.name}</code>
                  </label>
                  <input
                    id="delete-server-confirmation"
                    value={deleteConfirmation}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={workspace.name}
                    onChange={(event) =>
                      setDeleteConfirmation(event.target.value)
                    }
                  />
                  <div>
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() => {
                        setDeleteOpen(false);
                        setDeleteConfirmation("");
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      className="ownership-delete-final"
                      type="button"
                      disabled={
                        busy !== null ||
                        !serverNameConfirmed(deleteConfirmation, workspace.name)
                      }
                      onClick={() => void deleteServer()}
                    >
                      {busy === "delete" ? (
                        <LoaderCircle className="spin" size={13} />
                      ) : (
                        <Trash2 size={13} />
                      )}
                      {busy === "delete" ? "Deleting" : "Delete server now"}
                    </button>
                  </div>
                </div>
              )}
            </section>
          </>
        ) : null}
        {error ? (
          <p className="modal-error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </div>
  );
}

function RoleManagerDialog({
  open,
  workspace,
  onClose,
}: {
  open: boolean;
  workspace?: Workspace;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [manager, setManager] = useState<RoleManagerView | null>(null);
  const [selectedRoleId, setSelectedRoleId] = useState("");
  const [name, setName] = useState("");
  const [color, setColor] = useState("#3ecf8e");
  const [permissionKeys, setPermissionKeys] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteArmed, setDeleteArmed] = useState(false);

  useEffect(() => {
    if (!open || !workspace || workspace.localOnly) return;
    let cancelled = false;
    setManager(null);
    setError(null);
    setDeleteArmed(false);
    void coreBridge
      .loadServerRoles(workspace.id)
      .then((value) => {
        if (cancelled) return;
        setManager(value);
        setSelectedRoleId(
          value.roles.find((role) => !role.everyone)?.id ??
            value.roles[0]?.id ??
            "",
        );
      })
      .catch((loadError: unknown) => {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Roles could not be loaded.",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [open, workspace]);

  const selectedRole = manager?.roles.find(
    (role) => role.id === selectedRoleId,
  );

  const roleMutationError = (value: unknown, fallback: string) => {
    const message = value instanceof Error ? value.message : "";
    const normalized = message.toLocaleLowerCase();
    if (normalized.includes("no manageable role position")) {
      return "There is no role slot below your highest role yet. Ask a server owner to add a role above yours.";
    }
    if (
      normalized.includes("permission") ||
      normalized.includes("forbidden") ||
      normalized.includes("403")
    ) {
      return "You can only manage roles with permissions you already hold. Ask a server owner for a higher role if needed.";
    }
    return message || fallback;
  };

  useEffect(() => {
    if (!selectedRole) return;
    setName(selectedRole.name);
    setColor(selectedRole.color);
    setPermissionKeys([...selectedRole.permissionKeys]);
    setDeleteArmed(false);
  }, [selectedRole]);

  if (!open || !workspace) return null;

  const createRole = async () => {
    setBusy(true);
    setError(null);
    try {
      const role = await coreBridge.createServerRole({
        workspaceId: workspace.id,
        name: "New role",
        color: "#3ecf8e",
        permissionKeys: [],
      });
      setManager((current) =>
        current
          ? { ...current, roles: [role, ...current.roles] }
          : { roles: [role], members: [] },
      );
      setSelectedRoleId(role.id);
    } catch (createError) {
      setError(roleMutationError(createError, "The role could not be created."));
    } finally {
      setBusy(false);
    }
  };

  const saveRole = async () => {
    if (!selectedRole) return;
    setBusy(true);
    setError(null);
    try {
      const role = await coreBridge.updateServerRole({
        workspaceId: workspace.id,
        roleId: selectedRole.id,
        name,
        color,
        permissionKeys,
      });
      setManager((current) =>
        current
          ? {
              ...current,
              roles: current.roles.map((candidate) =>
                candidate.id === role.id ? role : candidate,
              ),
            }
          : current,
      );
    } catch (saveError) {
      setError(roleMutationError(saveError, "The role could not be saved."));
    } finally {
      setBusy(false);
    }
  };

  const deleteRole = async () => {
    if (!selectedRole || selectedRole.everyone) return;
    if (!deleteArmed) {
      setDeleteArmed(true);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await coreBridge.deleteServerRole(workspace.id, selectedRole.id);
      setManager((current) => {
        if (!current) return current;
        const roles = current.roles.filter(
          (candidate) => candidate.id !== selectedRole.id,
        );
        const members = current.members.map((member) => ({
          ...member,
          roleIds: member.roleIds.filter(
            (roleId) => roleId !== selectedRole.id,
          ),
        }));
        setSelectedRoleId(roles[0]?.id ?? "");
        return { roles, members };
      });
    } catch (deleteError) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : "The role could not be deleted.",
      );
    } finally {
      setBusy(false);
      setDeleteArmed(false);
    }
  };

  const setMemberRole = async (memberId: string, assigned: boolean) => {
    if (!selectedRole || selectedRole.everyone) return;
    setBusy(true);
    setError(null);
    try {
      await coreBridge.setServerMemberRole(
        workspace.id,
        memberId,
        selectedRole.id,
        assigned,
      );
      setManager((current) =>
        current
          ? {
              ...current,
              members: current.members.map((member) =>
                member.id === memberId
                  ? {
                      ...member,
                      roleIds: assigned
                        ? [...new Set([...member.roleIds, selectedRole.id])]
                        : member.roleIds.filter(
                            (roleId) => roleId !== selectedRole.id,
                          ),
                    }
                  : member,
              ),
            }
          : current,
      );
    } catch (assignmentError) {
      setError(
        assignmentError instanceof Error
          ? assignmentError.message
          : "The member assignment could not be changed.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card role-manager-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`Roles and permissions for ${workspace.name}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close role manager"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="role-manager-heading">
          <span className="modal-icon">
            <ShieldCheck size={19} />
          </span>
          <div>
            <h2>Roles & permissions</h2>
            <p>{workspace.name} · changes are enforced by the server.</p>
          </div>
        </div>
        {workspace.localOnly ? (
          <p className="modal-error">
            Remote role enforcement is unavailable for a device-only server.
          </p>
        ) : !manager && !error ? (
          <div className="role-loading">
            <LoaderCircle size={16} /> Loading access rules…
          </div>
        ) : (
          <div className="role-manager-layout">
            <aside className="role-list" aria-label="Server roles">
              <button
                className="role-create"
                type="button"
                disabled={busy}
                onClick={() => void createRole()}
              >
                <Plus size={13} /> New role
              </button>
              {manager?.roles.map((role) => (
                <button
                  className={role.id === selectedRoleId ? "is-active" : ""}
                  type="button"
                  key={role.id}
                  onClick={() => setSelectedRoleId(role.id)}
                >
                  <i style={{ background: role.color }} />
                  <span>{role.name}</span>
                  {role.managed ? <LockKeyhole size={11} /> : null}
                </button>
              ))}
            </aside>
            {selectedRole ? (
              <div className="role-editor">
                <div className="role-basics">
                  <label>
                    <span>Role name</span>
                    <input
                      value={name}
                      disabled={selectedRole.everyone || selectedRole.managed}
                      maxLength={100}
                      onChange={(event) => setName(event.target.value)}
                    />
                  </label>
                  <label className="role-color">
                    <span>Color</span>
                    <input
                      type="color"
                      value={color}
                      disabled={selectedRole.managed}
                      onChange={(event) => setColor(event.target.value)}
                    />
                  </label>
                </div>
                <div className="permission-groups">
                  {ROLE_PERMISSION_GROUPS.map((group) => (
                    <section key={group.label}>
                      <strong>{group.label}</strong>
                      <div>
                        {group.items.map(([key, label]) => (
                          <label
                            className={
                              key === "administrator"
                                ? "permission-toggle permission-danger"
                                : "permission-toggle"
                            }
                            key={key}
                          >
                            <input
                              type="checkbox"
                              checked={permissionKeys.includes(key)}
                              disabled={selectedRole.managed}
                              onChange={(event) =>
                                setPermissionKeys((current) =>
                                  event.target.checked
                                    ? [...new Set([...current, key])]
                                    : current.filter(
                                        (permission) => permission !== key,
                                      ),
                                )
                              }
                            />
                            <i aria-hidden="true" />
                            <span>{label}</span>
                          </label>
                        ))}
                      </div>
                    </section>
                  ))}
                </div>
                {!selectedRole.everyone ? (
                  <section className="role-members">
                    <strong>Members with this role</strong>
                    <div>
                      {manager?.members.map((member) => (
                        <label key={member.id}>
                          <span
                            className="role-member-avatar"
                            style={{ "--avatar-color": member.color } as React.CSSProperties}
                          >
                            {member.initials}
                          </span>
                          <span>
                            <b>{member.name}</b>
                            <small>@{member.handle}</small>
                          </span>
                          <input
                            type="checkbox"
                            checked={member.roleIds.includes(selectedRole.id)}
                            disabled={busy}
                            onChange={(event) =>
                              void setMemberRole(member.id, event.target.checked)
                            }
                          />
                        </label>
                      ))}
                    </div>
                  </section>
                ) : null}
                <div className="role-actions">
                  {!selectedRole.everyone && !selectedRole.managed ? (
                    <button
                      className={deleteArmed ? "role-delete is-armed" : "role-delete"}
                      type="button"
                      disabled={busy}
                      onClick={() => void deleteRole()}
                    >
                      <Trash2 size={13} />
                      {deleteArmed ? "Confirm delete" : "Delete role"}
                    </button>
                  ) : (
                    <span />
                  )}
                  <button
                    className="primary-button"
                    type="button"
                    disabled={busy || selectedRole.managed || name.trim().length < 1}
                    onClick={() => void saveRole()}
                  >
                    {busy ? "Saving…" : "Save changes"}
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        )}
        {error ? (
          <p className="modal-error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </div>
  );
}

type PermissionState = "inherit" | "allow" | "deny";

function ChannelManagerDialog({
  open,
  workspace,
  onClose,
}: {
  open: boolean;
  workspace?: Workspace;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [manager, setManager] = useState<ChannelManagerView | null>(null);
  const [selectedChannelId, setSelectedChannelId] = useState("");
  const [creatingChannel, setCreatingChannel] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"text" | "voice">("text");
  const [overwrites, setOverwrites] = useState<ChannelOverwrite[]>([]);
  const [targetKind, setTargetKind] =
    useState<OverwriteTargetKind>("role");
  const [targetId, setTargetId] = useState("");
  const [permissionStates, setPermissionStates] = useState<
    Record<string, PermissionState>
  >({});
  const [loadingAccess, setLoadingAccess] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !workspace || workspace.localOnly) return;
    let cancelled = false;
    setManager(null);
    setError(null);
    setCreatingChannel(false);
    void coreBridge
      .loadServerChannels(workspace.id)
      .then((value) => {
        if (cancelled) return;
        setManager(value);
        setSelectedChannelId(value.channels[0]?.id ?? "");
        setTargetKind("role");
        setTargetId(
          value.roles.find((role) => role.everyone)?.id ??
            value.roles[0]?.id ??
            "",
        );
      })
      .catch((loadError: unknown) => {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Channels could not be loaded.",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [open, workspace]);

  const selectedChannel = manager?.channels.find(
    (channel) => channel.id === selectedChannelId,
  );

  useEffect(() => {
    if (!selectedChannel || creatingChannel) return;
    setName(selectedChannel.name);
    setKind(selectedChannel.kind);
    setDeleteArmed(false);
  }, [selectedChannel, creatingChannel]);

  useEffect(() => {
    if (!selectedChannelId || creatingChannel) {
      setOverwrites([]);
      return;
    }
    let cancelled = false;
    setLoadingAccess(true);
    void coreBridge
      .loadChannelOverwrites(selectedChannelId)
      .then((value) => {
        if (!cancelled) setOverwrites(value);
      })
      .catch((loadError: unknown) => {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Channel access rules could not be loaded.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingAccess(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedChannelId, creatingChannel]);

  useEffect(() => {
    const overwrite = overwrites.find(
      (candidate) =>
        candidate.targetKind === targetKind &&
        candidate.targetId === targetId,
    );
    const states: Record<string, PermissionState> = {};
    CHANNEL_PERMISSION_ITEMS.forEach(([key]) => {
      states[key] = overwrite?.allowKeys.includes(key)
        ? "allow"
        : overwrite?.denyKeys.includes(key)
          ? "deny"
          : "inherit";
    });
    setPermissionStates(states);
  }, [overwrites, targetKind, targetId]);

  if (!open || !workspace) return null;

  const selectChannel = (channelId: string) => {
    setCreatingChannel(false);
    setSelectedChannelId(channelId);
    setError(null);
  };

  const beginCreate = () => {
    setCreatingChannel(true);
    setSelectedChannelId("");
    setName("new-channel");
    setKind("text");
    setOverwrites([]);
    setDeleteArmed(false);
  };

  const saveChannel = async () => {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      if (creatingChannel) {
        const channel = await coreBridge.createServerChannel({
          workspaceId: workspace.id,
          name,
          kind,
          encrypted: kind === "voice",
        });
        setManager((current) =>
          current
            ? { ...current, channels: [...current.channels, channel] }
            : current,
        );
        setCreatingChannel(false);
        setSelectedChannelId(channel.id);
      } else if (selectedChannel) {
        const channel = await coreBridge.updateServerChannel({
          workspaceId: workspace.id,
          channelId: selectedChannel.id,
          name,
          kind: selectedChannel.kind,
          encrypted: selectedChannel.encrypted,
        });
        setManager((current) =>
          current
            ? {
                ...current,
                channels: current.channels.map((candidate) =>
                  candidate.id === channel.id ? channel : candidate,
                ),
              }
            : current,
        );
      }
    } catch (saveError) {
      setError(
        saveError instanceof Error
          ? saveError.message
          : "The channel could not be saved.",
      );
    } finally {
      setBusy(false);
    }
  };

  const deleteChannel = async () => {
    if (!selectedChannel) return;
    if (!deleteArmed) {
      setDeleteArmed(true);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await coreBridge.deleteServerChannel(selectedChannel.id);
      setManager((current) => {
        if (!current) return current;
        const channels = current.channels.filter(
          (candidate) => candidate.id !== selectedChannel.id,
        );
        setSelectedChannelId(channels[0]?.id ?? "");
        return { ...current, channels };
      });
    } catch (deleteError) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : "The channel could not be deleted.",
      );
    } finally {
      setBusy(false);
      setDeleteArmed(false);
    }
  };

  const saveOverwrite = async () => {
    if (!selectedChannel || !targetId) return;
    const allowKeys = CHANNEL_PERMISSION_ITEMS.flatMap(([key]) =>
      permissionStates[key] === "allow" ? [key] : [],
    );
    const denyKeys = CHANNEL_PERMISSION_ITEMS.flatMap(([key]) =>
      permissionStates[key] === "deny" ? [key] : [],
    );
    const existing = overwrites.find(
      (candidate) =>
        candidate.targetKind === targetKind &&
        candidate.targetId === targetId,
    );
    setBusy(true);
    setError(null);
    try {
      if (allowKeys.length === 0 && denyKeys.length === 0) {
        if (existing) {
          await coreBridge.deleteServerChannelOverwrite(
            selectedChannel.id,
            targetKind,
            targetId,
          );
          setOverwrites((current) =>
            current.filter((candidate) => candidate !== existing),
          );
        }
      } else {
        const overwrite = await coreBridge.setServerChannelOverwrite({
          channelId: selectedChannel.id,
          targetKind,
          targetId,
          allowKeys,
          denyKeys,
        });
        setOverwrites((current) => [
          ...current.filter(
            (candidate) =>
              candidate.targetKind !== targetKind ||
              candidate.targetId !== targetId,
          ),
          overwrite,
        ]);
      }
    } catch (saveError) {
      setError(
        saveError instanceof Error
          ? saveError.message
          : "The access rule could not be saved.",
      );
    } finally {
      setBusy(false);
    }
  };

  const targets =
    targetKind === "role" ? manager?.roles ?? [] : manager?.members ?? [];
  const permissionItems =
    selectedChannel?.kind === "voice"
      ? CHANNEL_PERMISSION_ITEMS.filter(([key]) =>
          ["view_channel", "connect", "speak", "stream"].includes(key),
        )
      : CHANNEL_PERMISSION_ITEMS.filter(
          ([key]) => !["connect", "speak", "stream"].includes(key),
        );

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card channel-manager-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`Channels and access for ${workspace.name}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close channel manager"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="role-manager-heading">
          <span className="modal-icon">
            <Settings2 size={19} />
          </span>
          <div>
            <h2>Channels & access</h2>
            <p>{workspace.name} · explicit allow and deny rules.</p>
          </div>
        </div>
        {workspace.localOnly ? (
          <p className="modal-error">
            Remote channel controls are unavailable for a device-only server.
          </p>
        ) : !manager && !error ? (
          <div className="role-loading">
            <LoaderCircle size={16} /> Loading channels…
          </div>
        ) : (
          <div className="channel-manager-layout">
            <aside className="role-list channel-list" aria-label="Channels">
              <button
                className="role-create"
                type="button"
                disabled={busy}
                onClick={beginCreate}
              >
                <Plus size={13} /> New channel
              </button>
              {manager?.channels.map((channel) => (
                <button
                  className={
                    !creatingChannel && channel.id === selectedChannelId
                      ? "is-active"
                      : ""
                  }
                  type="button"
                  key={channel.id}
                  onClick={() => selectChannel(channel.id)}
                >
                  {channel.kind === "text" ? (
                    <Hash size={13} />
                  ) : (
                    <Headphones size={13} />
                  )}
                  <span>{channel.name}</span>
                  {channel.encrypted ? <LockKeyhole size={11} /> : null}
                </button>
              ))}
            </aside>
            <div className="channel-editor">
              <section className="channel-basics">
                <div>
                  <label>
                    <span>Channel name</span>
                    <input
                      value={name}
                      maxLength={100}
                      onChange={(event) => setName(event.target.value)}
                    />
                  </label>
                  {creatingChannel ? (
                    <label>
                      <span>Type</span>
                      <select
                        value={kind}
                        onChange={(event) =>
                          setKind(event.target.value as "text" | "voice")
                        }
                      >
                        <option value="text">Text</option>
                        <option value="voice">Voice</option>
                      </select>
                    </label>
                  ) : (
                    <span className="status-pill">
                      {selectedChannel?.kind === "voice" ? "Voice" : "Text"}
                    </span>
                  )}
                </div>
                <div className="channel-actions">
                  {!creatingChannel && selectedChannel ? (
                    <button
                      className={
                        deleteArmed ? "role-delete is-armed" : "role-delete"
                      }
                      type="button"
                      disabled={busy}
                      onClick={() => void deleteChannel()}
                    >
                      <Trash2 size={13} />
                      {deleteArmed ? "Confirm delete" : "Delete"}
                    </button>
                  ) : (
                    <span />
                  )}
                  <button
                    className="primary-button"
                    type="button"
                    disabled={busy || name.trim().length < 1}
                    onClick={() => void saveChannel()}
                  >
                    {busy ? "Saving…" : creatingChannel ? "Create" : "Rename"}
                  </button>
                </div>
              </section>
              {!creatingChannel && selectedChannel ? (
                <section className="channel-access-editor">
                  <div className="access-heading">
                    <div>
                      <strong>Access override</strong>
                      <span>Member rules win over role rules.</span>
                    </div>
                    {loadingAccess ? <LoaderCircle size={14} /> : null}
                  </div>
                  <div className="access-target">
                    <select
                      aria-label="Access override target type"
                      value={targetKind}
                      onChange={(event) => {
                        const nextKind = event.target
                          .value as OverwriteTargetKind;
                        setTargetKind(nextKind);
                        const nextTargets =
                          nextKind === "role"
                            ? manager?.roles ?? []
                            : manager?.members ?? [];
                        setTargetId(nextTargets[0]?.id ?? "");
                      }}
                    >
                      <option value="role">Role</option>
                      <option value="member">Member</option>
                    </select>
                    <select
                      aria-label={`${
                        targetKind === "role" ? "Role" : "Member"
                      } receiving this access override`}
                      value={targetId}
                      onChange={(event) => setTargetId(event.target.value)}
                    >
                      {targets.map((target) => (
                        <option value={target.id} key={target.id}>
                          {target.name}
                          {"handle" in target ? ` · @${target.handle}` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="overwrite-grid">
                    {permissionItems.map(([key, label]) => (
                      <div key={key}>
                        <span>{label}</span>
                        <div>
                          {(["inherit", "allow", "deny"] as const).map(
                            (state) => (
                              <button
                                className={
                                  permissionStates[key] === state
                                    ? `is-${state}`
                                    : ""
                                }
                                type="button"
                                key={state}
                                aria-label={`${label}: ${state}`}
                                aria-pressed={permissionStates[key] === state}
                                onClick={() =>
                                  setPermissionStates((current) => ({
                                    ...current,
                                    [key]: state,
                                  }))
                                }
                              >
                                {state}
                              </button>
                            ),
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  <button
                    className="primary-button access-save"
                    type="button"
                    disabled={busy || !targetId}
                    onClick={() => void saveOverwrite()}
                  >
                    {busy ? "Saving…" : "Save access rule"}
                  </button>
                </section>
              ) : null}
            </div>
          </div>
        )}
        {error ? (
          <p className="modal-error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </div>
  );
}

function ModerationDialog({
  open,
  workspace,
  currentUserId,
  canTimeout,
  canKick,
  canBan,
  canManageSafety,
  canViewAudit,
  onClose,
}: {
  open: boolean;
  workspace?: Workspace;
  currentUserId: string;
  canTimeout: boolean;
  canKick: boolean;
  canBan: boolean;
  canManageSafety: boolean;
  canViewAudit: boolean;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [manager, setManager] = useState<ModerationManagerView | null>(null);
  const [tab, setTab] = useState<
    "members" | "bans" | "rules" | "audit"
  >("members");
  const [reason, setReason] = useState("");
  const [banDuration, setBanDuration] = useState(0);
  const [armedAction, setArmedAction] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    if (!workspace || workspace.localOnly) return;
    const value = await coreBridge.loadServerModeration(workspace.id);
    setManager(value);
  };

  useEffect(() => {
    if (!open || !workspace || workspace.localOnly) return;
    let cancelled = false;
    setManager(null);
    setError(null);
    setArmedAction("");
    setReason("");
    setTab(
      canTimeout || canKick || canBan
        ? "members"
        : canManageSafety
          ? "rules"
          : "audit",
    );
    void coreBridge
      .loadServerModeration(workspace.id)
      .then((value) => {
        if (!cancelled) {
          setManager(value);
          if (
            (canTimeout || canKick || canBan) &&
            value.members.length === 0 &&
            value.bans.length > 0
          ) {
            setTab("bans");
          }
        }
      })
      .catch((loadError: unknown) => {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Members could not be loaded.",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [
    canBan,
    canKick,
    canManageSafety,
    canTimeout,
    open,
    workspace,
  ]);

  if (!open || !workspace) return null;

  const moderate = async (
    action: "timeout" | "clear" | "kick" | "ban" | "unban",
    memberId: string,
  ) => {
    const destructive = action === "kick" || action === "ban";
    const actionKey = `${action}:${memberId}`;
    if (destructive && armedAction !== actionKey) {
      setArmedAction(actionKey);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const input = {
        workspaceId: workspace.id,
        memberId,
        reason: reason.trim() || undefined,
      };
      if (action === "timeout") {
        await coreBridge.timeoutServerMember({
          ...input,
          durationSeconds: 60 * 60,
        });
      } else if (action === "clear") {
        await coreBridge.timeoutServerMember(input);
      } else if (action === "kick") {
        await coreBridge.kickServerMember(input);
      } else if (action === "ban") {
        await coreBridge.banServerMember({
          ...input,
          durationSeconds: banDuration || undefined,
        });
      } else {
        await coreBridge.unbanServerMember(input);
      }
      await reload();
      setArmedAction("");
      setReason("");
    } catch (actionError) {
      setError(
        actionError instanceof Error
          ? actionError.message
          : "The moderation action could not be completed.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card moderation-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`Safety and moderation for ${workspace.name}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close moderation"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="role-manager-heading">
          <span className="modal-icon">
            <Users size={19} />
          </span>
          <div>
            <h2>Safety & moderation</h2>
            <p>{workspace.name} · every action is enforced and recorded.</p>
          </div>
        </div>
        {workspace.localOnly ? (
          <p className="modal-error">
            Remote moderation is unavailable for a device-only server.
          </p>
        ) : !manager && !error ? (
          <div className="role-loading">
            <LoaderCircle size={16} /> Loading members…
          </div>
        ) : (
          <>
            <div className="moderation-toolbar">
              <div className="moderation-tabs">
                {canTimeout || canKick || canBan ? (
                  <button
                    className={tab === "members" ? "is-active" : ""}
                    type="button"
                    onClick={() => setTab("members")}
                  >
                    Members
                  </button>
                ) : null}
                {canBan ? (
                  <button
                    className={tab === "bans" ? "is-active" : ""}
                    type="button"
                    onClick={() => setTab("bans")}
                  >
                    Bans · {manager?.bans.length ?? 0}
                  </button>
                ) : null}
                {canManageSafety ? (
                  <button
                    className={tab === "rules" ? "is-active" : ""}
                    type="button"
                    onClick={() => setTab("rules")}
                  >
                    Rules · {manager?.rules.length ?? 0}
                  </button>
                ) : null}
                {canViewAudit ? (
                  <button
                    className={tab === "audit" ? "is-active" : ""}
                    type="button"
                    onClick={() => setTab("audit")}
                  >
                    Audit
                  </button>
                ) : null}
              </div>
              {tab === "members" || tab === "bans" ? (
                <input
                  aria-label="Moderation reason"
                  value={reason}
                  maxLength={512}
                  placeholder="Reason (optional)"
                  onChange={(event) => setReason(event.target.value)}
                />
              ) : (
                <span className="safety-status">
                  {tab === "rules"
                    ? "Compiled before messages are stored"
                    : `${manager?.audit.length ?? 0} recent actions`}
                </span>
              )}
              {canBan && tab === "members" ? (
                <select
                  aria-label="Ban duration"
                  value={banDuration}
                  onChange={(event) =>
                    setBanDuration(Number(event.target.value))
                  }
                >
                  <option value={0}>Permanent ban</option>
                  <option value={86400}>Ban for 1 day</option>
                  <option value={604800}>Ban for 7 days</option>
                  <option value={2592000}>Ban for 30 days</option>
                </select>
              ) : null}
            </div>
            {tab === "members" ? (
              <div className="moderation-list">
                {manager?.members.map((member) => {
                  const protectedMember =
                    member.id === currentUserId ||
                    member.id === workspace.ownerId;
                  const timedOut =
                    !!member.timeoutUntil &&
                    new Date(member.timeoutUntil).getTime() > Date.now();
                  return (
                    <article key={member.id}>
                      <span
                        className="role-member-avatar"
                        style={
                          {
                            "--avatar-color": member.color,
                          } as React.CSSProperties
                        }
                      >
                        {member.initials}
                      </span>
                      <div>
                        <strong>{member.name}</strong>
                        <span>
                          @{member.handle}
                          {timedOut
                            ? ` · timed out until ${new Intl.DateTimeFormat(
                                undefined,
                                {
                                  hour: "numeric",
                                  minute: "2-digit",
                                },
                              ).format(new Date(member.timeoutUntil!))}`
                            : ""}
                        </span>
                      </div>
                      <div className="moderation-actions">
                        {canTimeout && !protectedMember ? (
                          <button
                            type="button"
                            aria-label={`${
                              timedOut ? "Clear timeout for" : "Timeout"
                            } ${member.name}`}
                            disabled={busy}
                            onClick={() =>
                              void moderate(
                                timedOut ? "clear" : "timeout",
                                member.id,
                              )
                            }
                          >
                            {timedOut ? "Clear timeout" : "Timeout 1h"}
                          </button>
                        ) : null}
                        {canKick && !protectedMember ? (
                          <button
                            className={
                              armedAction === `kick:${member.id}`
                                ? "is-armed"
                                : ""
                            }
                            type="button"
                            aria-label={`${
                              armedAction === `kick:${member.id}`
                                ? "Confirm removal of"
                                : "Remove"
                            } ${member.name}`}
                            disabled={busy}
                            onClick={() => void moderate("kick", member.id)}
                          >
                            {armedAction === `kick:${member.id}`
                              ? "Confirm remove"
                              : "Remove"}
                          </button>
                        ) : null}
                        {canBan && !protectedMember ? (
                          <button
                            className={
                              armedAction === `ban:${member.id}`
                                ? "is-armed"
                                : ""
                            }
                            type="button"
                            aria-label={`${
                              armedAction === `ban:${member.id}`
                                ? "Confirm ban for"
                                : "Ban"
                            } ${member.name}`}
                            disabled={busy}
                            onClick={() => void moderate("ban", member.id)}
                          >
                            {armedAction === `ban:${member.id}`
                              ? "Confirm ban"
                              : "Ban"}
                          </button>
                        ) : null}
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : tab === "bans" ? (
              <div className="moderation-list ban-list">
                {manager?.bans.map((ban) => (
                  <article key={ban.id}>
                    <span
                      className="role-member-avatar"
                      style={
                        {
                          "--avatar-color": ban.color,
                        } as React.CSSProperties
                      }
                    >
                      {ban.initials}
                    </span>
                    <div>
                      <strong>{ban.name}</strong>
                      <span>
                        @{ban.handle} · {ban.reason ?? "No reason"}
                        {ban.expiresAt
                          ? ` · ends ${new Intl.DateTimeFormat(undefined, {
                              month: "short",
                              day: "numeric",
                            }).format(new Date(ban.expiresAt))}`
                          : " · permanent"}
                      </span>
                    </div>
                    <div className="moderation-actions">
                      <button
                        type="button"
                        aria-label={`Unban ${ban.name}`}
                        disabled={busy}
                        onClick={() => void moderate("unban", ban.id)}
                      >
                        Unban
                      </button>
                    </div>
                  </article>
                ))}
                {manager?.bans.length === 0 ? (
                  <p className="moderation-empty">No active bans.</p>
                ) : null}
              </div>
            ) : tab === "rules" ? (
              <SafetyRulesPanel
                workspaceId={workspace.id}
                rules={manager?.rules ?? []}
                busy={busy}
                setBusy={setBusy}
                onError={setError}
                onReload={reload}
              />
            ) : (
              <AuditLogPanel
                entries={manager?.audit ?? []}
                members={manager?.members ?? []}
                currentUserId={currentUserId}
              />
            )}
          </>
        )}
        {error ? (
          <p className="modal-error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    </div>
  );
}

function SafetyRulesPanel({
  workspaceId,
  rules,
  busy,
  setBusy,
  onError,
  onReload,
}: {
  workspaceId: string;
  rules: AutomodRule[];
  busy: boolean;
  setBusy: (value: boolean) => void;
  onError: (value: string | null) => void;
  onReload: () => Promise<void>;
}) {
  const [selectedRuleId, setSelectedRuleId] = useState("new");
  const [name, setName] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [triggerType, setTriggerType] =
    useState<AutomodTriggerType>("keyword");
  const [terms, setTerms] = useState("");
  const [mentionLimit, setMentionLimit] = useState(5);
  const [repeatThreshold, setRepeatThreshold] = useState(3);
  const [windowSeconds, setWindowSeconds] = useState(30);
  const [maxAccountAgeDays, setMaxAccountAgeDays] = useState(7);
  const [combiningMarkLimit, setCombiningMarkLimit] = useState(12);
  const [action, setAction] = useState<AutomodAction>("block");
  const [durationSeconds, setDurationSeconds] = useState(3600);
  const [explanation, setExplanation] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);

  const selectedRule = rules.find((rule) => rule.id === selectedRuleId);

  useEffect(() => {
    setSelectedRuleId((current) =>
      current === "new" || rules.some((rule) => rule.id === current)
        ? current
        : (rules[0]?.id ?? "new"),
    );
  }, [rules]);

  useEffect(() => {
    setDeleteArmed(false);
    if (!selectedRule) {
      setName("");
      setEnabled(true);
      setTriggerType("keyword");
      setTerms("");
      setMentionLimit(5);
      setRepeatThreshold(3);
      setWindowSeconds(30);
      setMaxAccountAgeDays(7);
      setCombiningMarkLimit(12);
      setAction("block");
      setDurationSeconds(3600);
      setExplanation("");
      return;
    }
    setName(selectedRule.name);
    setEnabled(selectedRule.enabled);
    setTriggerType(selectedRule.triggerType);
    setTerms(selectedRule.terms.join("\n"));
    setMentionLimit(selectedRule.mentionLimit ?? 5);
    setRepeatThreshold(selectedRule.repeatThreshold ?? 3);
    setWindowSeconds(selectedRule.windowSeconds ?? 30);
    setMaxAccountAgeDays(selectedRule.maxAccountAgeDays ?? 7);
    setCombiningMarkLimit(selectedRule.combiningMarkLimit ?? 12);
    setAction(selectedRule.action);
    setDurationSeconds(selectedRule.durationSeconds ?? 3600);
    setExplanation(selectedRule.explanation);
  }, [selectedRule]);

  const saveRule = async () => {
    const normalizedTerms = terms
      .split("\n")
      .map((term) => term.trim())
      .filter(Boolean);
    if (
      !name.trim() ||
      !explanation.trim() ||
      ((triggerType === "keyword" || triggerType === "regex") &&
        normalizedTerms.length === 0)
    ) {
      onError("Name, explanation, and trigger values are required.");
      return;
    }
    setBusy(true);
    onError(null);
    try {
      const input = {
        workspaceId,
        ruleId: selectedRule?.id,
        name: name.trim(),
        enabled,
        triggerType,
        terms: normalizedTerms,
        mentionLimit,
        repeatThreshold,
        windowSeconds,
        maxAccountAgeDays,
        combiningMarkLimit,
        action,
        durationSeconds:
          action === "timeout" || action === "ban"
            ? durationSeconds
            : undefined,
        explanation: explanation.trim(),
      };
      const saved = selectedRule
        ? await coreBridge.updateAutomodRule(input)
        : await coreBridge.createAutomodRule(input);
      await onReload();
      setSelectedRuleId(saved.id);
    } catch (saveError) {
      onError(
        saveError instanceof Error
          ? saveError.message
          : "The safety rule could not be saved.",
      );
    } finally {
      setBusy(false);
    }
  };

  const deleteRule = async () => {
    if (!selectedRule) return;
    if (!deleteArmed) {
      setDeleteArmed(true);
      return;
    }
    setBusy(true);
    onError(null);
    try {
      await coreBridge.deleteAutomodRule(workspaceId, selectedRule.id);
      setSelectedRuleId("new");
      await onReload();
    } catch (deleteError) {
      onError(
        deleteError instanceof Error
          ? deleteError.message
          : "The safety rule could not be deleted.",
      );
    } finally {
      setBusy(false);
      setDeleteArmed(false);
    }
  };

  return (
    <div className="safety-rules-layout">
      <aside className="safety-rule-list">
        <button
          className={selectedRuleId === "new" ? "is-active" : ""}
          type="button"
          onClick={() => setSelectedRuleId("new")}
        >
          <Plus size={14} />
          New rule
        </button>
        {rules.map((rule) => (
          <button
            className={rule.id === selectedRuleId ? "is-active" : ""}
            key={rule.id}
            type="button"
            onClick={() => setSelectedRuleId(rule.id)}
          >
            <span
              className={`rule-state ${rule.enabled ? "is-enabled" : ""}`}
            />
            <span>
              <strong>{rule.name}</strong>
              <small>{automodActionLabel(rule.action)}</small>
            </span>
          </button>
        ))}
        {rules.length === 0 ? (
          <p>No rules yet. Start with a narrow block rule.</p>
        ) : null}
      </aside>
      <section className="safety-rule-editor">
        <div className="safety-rule-heading">
          <div>
            <strong>{selectedRule ? "Edit rule" : "Create safety rule"}</strong>
            <span>Evaluated in memory before message persistence.</span>
          </div>
          <label className="rule-toggle">
            <input
              checked={enabled}
              type="checkbox"
              onChange={(event) => setEnabled(event.target.checked)}
            />
            <span>{enabled ? "Enabled" : "Paused"}</span>
          </label>
        </div>
        <div className="safety-rule-grid">
          <label className="is-wide">
            <span>Rule name</span>
            <input
              value={name}
              maxLength={64}
              placeholder="Block leaked credentials"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label>
            <span>Detect</span>
            <select
              value={triggerType}
              onChange={(event) =>
                setTriggerType(event.target.value as AutomodTriggerType)
              }
            >
              <option value="keyword">Keywords</option>
              <option value="regex">Regular expressions</option>
              <option value="invite_link">Invite links</option>
              <option value="mass_mention">Mass mentions</option>
              <option value="repeated_content">Repeated content</option>
              <option value="new_account_link">New-account links</option>
              <option value="zalgo">Combining-mark abuse</option>
            </select>
          </label>
          <label>
            <span>Action</span>
            <select
              value={action}
              onChange={(event) =>
                setAction(event.target.value as AutomodAction)
              }
            >
              <option value="flag">Flag and allow</option>
              <option value="block">Block message</option>
              <option value="timeout">Block + timeout</option>
              <option value="kick">Block + remove</option>
              <option value="ban">Block + temporary ban</option>
            </select>
          </label>
          {triggerType === "keyword" || triggerType === "regex" ? (
            <label className="is-wide">
              <span>
                {triggerType === "keyword"
                  ? "One keyword or phrase per line"
                  : "One bounded regex per line"}
              </span>
              <textarea
                value={terms}
                maxLength={4096}
                rows={3}
                placeholder={
                  triggerType === "keyword"
                    ? "private-key\nrecovery phrase"
                    : String.raw`\b[A-Z0-9]{20}\b`
                }
                onChange={(event) => setTerms(event.target.value)}
              />
            </label>
          ) : null}
          {triggerType === "mass_mention" ? (
            <NumberField
              label="Maximum mentions"
              value={mentionLimit}
              min={1}
              max={100}
              onChange={setMentionLimit}
            />
          ) : null}
          {triggerType === "repeated_content" ? (
            <>
              <NumberField
                label="Repeat count"
                value={repeatThreshold}
                min={2}
                max={10}
                onChange={setRepeatThreshold}
              />
              <NumberField
                label="Window (seconds)"
                value={windowSeconds}
                min={5}
                max={600}
                onChange={setWindowSeconds}
              />
            </>
          ) : null}
          {triggerType === "new_account_link" ? (
            <NumberField
              label="Account age (days)"
              value={maxAccountAgeDays}
              min={1}
              max={90}
              onChange={setMaxAccountAgeDays}
            />
          ) : null}
          {triggerType === "zalgo" ? (
            <NumberField
              label="Combining-mark limit"
              value={combiningMarkLimit}
              min={4}
              max={1000}
              onChange={setCombiningMarkLimit}
            />
          ) : null}
          {action === "timeout" || action === "ban" ? (
            <label>
              <span>Duration</span>
              <select
                value={durationSeconds}
                onChange={(event) =>
                  setDurationSeconds(Number(event.target.value))
                }
              >
                <option value={600}>10 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={86400}>1 day</option>
                <option value={604800}>7 days</option>
                <option value={2419200}>28 days</option>
              </select>
            </label>
          ) : null}
          <label className="is-wide">
            <span>Explanation shown to the author</span>
            <input
              value={explanation}
              maxLength={256}
              placeholder="Credentials cannot be posted in this server."
              onChange={(event) => setExplanation(event.target.value)}
            />
          </label>
        </div>
        <div className="safety-rule-actions">
          {selectedRule ? (
            <button
              className={deleteArmed ? "is-armed" : ""}
              type="button"
              disabled={busy}
              onClick={() => void deleteRule()}
            >
              <Trash2 size={14} />
              {deleteArmed ? "Confirm delete" : "Delete"}
            </button>
          ) : (
            <span>Patterns are capped and compiled with linear-time matchers.</span>
          )}
          <button
            className="primary"
            type="button"
            disabled={busy}
            onClick={() => void saveRule()}
          >
            {busy ? <LoaderCircle size={14} /> : <ShieldCheck size={14} />}
            {selectedRule ? "Save rule" : "Create rule"}
          </button>
        </div>
      </section>
    </div>
  );
}

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </label>
  );
}

function AuditLogPanel({
  entries,
  members,
  currentUserId,
}: {
  entries: ModerationManagerView["audit"];
  members: ModerationManagerView["members"];
  currentUserId: string;
}) {
  const membersById = new Map(members.map((member) => [member.id, member]));
  return (
    <div className="moderation-list audit-list">
      {entries.map((entry) => {
        const actor = entry.actorId
          ? membersById.get(entry.actorId)
          : undefined;
        const target = entry.targetId
          ? membersById.get(entry.targetId)
          : undefined;
        const actorName =
          entry.actorId === currentUserId
            ? "You"
            : actor?.name ?? (entry.actorId ? "Former member" : "Exocord");
        return (
          <article key={entry.id}>
            <span className="audit-icon">
              <ShieldCheck size={15} />
            </span>
            <div>
              <strong>{entry.actionLabel}</strong>
              <span>
                {actorName}
                {entry.detail
                  ? ` · ${entry.detail}`
                  : target
                    ? ` · @${target.handle}`
                    : ""}
                {entry.reason ? ` · ${entry.reason}` : ""}
              </span>
            </div>
            <time dateTime={entry.createdAt}>
              {new Intl.DateTimeFormat(undefined, {
                month: "short",
                day: "numeric",
                hour: "numeric",
                minute: "2-digit",
              }).format(new Date(entry.createdAt))}
            </time>
          </article>
        );
      })}
      {entries.length === 0 ? (
        <p className="moderation-empty">No auditable actions yet.</p>
      ) : null}
    </div>
  );
}

function automodActionLabel(action: AutomodAction): string {
  switch (action) {
    case "flag":
      return "Flag";
    case "block":
      return "Block";
    case "timeout":
      return "Timeout";
    case "kick":
      return "Remove";
    case "ban":
      return "Ban";
  }
}

function RelationshipOverflowMenu({
  relationship,
  busy,
  onRemove,
  onBlock,
}: {
  relationship: RelationshipView;
  busy: boolean;
  onRemove: () => void;
  onBlock: () => void;
}) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const rect = triggerRef.current?.getBoundingClientRect();
  const left = rect
    ? Math.max(8, Math.min(window.innerWidth - 164, rect.right - 152))
    : 8;
  const top = rect
    ? rect.top > 108
      ? rect.top - 88
      : rect.bottom + 6
    : 8;
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (
        !menuRef.current?.contains(event.target as Node) &&
        !triggerRef.current?.contains(event.target as Node)
      ) {
        setOpen(false);
      }
    };
    const escape = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", escape);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", escape);
    };
  }, [open]);
  return (
    <>
      <button
        ref={triggerRef}
        className="relationship-overflow-trigger"
        type="button"
        aria-label={`More actions for ${relationship.name}`}
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <MoreHorizontal size={15} />
      </button>
      {open && rect
        ? createPortal(
            <div
              ref={menuRef}
              className="relationship-overflow-menu"
              role="menu"
              style={{ left, top }}
            >
              <button
                type="button"
                role="menuitem"
                disabled={busy}
                onClick={() => {
                  setOpen(false);
                  onRemove();
                }}
              >
                {relationship.kind === "outgoing"
                  ? "Cancel request"
                  : relationship.kind === "incoming"
                    ? "Decline"
                    : "Remove friend"}
              </button>
              <button
                className="relationship-danger"
                type="button"
                role="menuitem"
                disabled={busy}
                onClick={() => {
                  setOpen(false);
                  onBlock();
                }}
              >
                Block
              </button>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}

function FriendsDialog({
  open,
  relationships,
  busyUserId,
  onRequest,
  onAccept,
  onRemove,
  onBlock,
  onMessage,
  onClose,
}: {
  open: boolean;
  relationships: RelationshipView[];
  busyUserId: string | null;
  onRequest: (handle: string) => Promise<void>;
  onAccept: (userId: string) => Promise<void>;
  onRemove: (userId: string) => Promise<void>;
  onBlock: (userId: string) => Promise<void>;
  onMessage: (userId: string) => Promise<void>;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [handle, setHandle] = useState("");
  const [requesting, setRequesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    "friends" | "requests" | "blocked"
  >("friends");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setHandle("");
    setError(null);
    setActiveTab("friends");
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  if (!open) return null;

  const run = async (action: () => Promise<void>) => {
    setError(null);
    try {
      await action();
      return true;
    } catch (actionFailure) {
      setError(
        actionFailure instanceof Error
          ? actionFailure.message
          : "That relationship could not be changed.",
      );
      return false;
    }
  };

  const visibleRelationships = relationships.filter((relationship) =>
    activeTab === "friends"
      ? relationship.kind === "friend"
      : activeTab === "requests"
        ? relationship.kind === "incoming" || relationship.kind === "outgoing"
        : relationship.kind === "blocked",
  );
  const requestCount = relationships.filter(
    (relationship) => relationship.kind === "incoming",
  ).length;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card friends-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label="Friends and direct messages"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close friends"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="modal-icon">
          <Users size={19} />
        </div>
        <h2>Friends</h2>
        <form
          className="friend-request-form"
          onSubmit={(event) => {
            event.preventDefault();
            const value = handle.trim();
            if (!value) return;
            setRequesting(true);
            void run(() => onRequest(value))
              .then((succeeded) => {
                if (succeeded) setHandle("");
              })
              .finally(() => setRequesting(false));
          }}
        >
          <AtSign size={14} />
          <input
            ref={inputRef}
            value={handle}
            maxLength={32}
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
            aria-label="Exact account handle"
            placeholder="exact-handle"
            onChange={(event) => setHandle(event.target.value)}
          />
          <button
            type="submit"
            disabled={requesting || handle.trim().length < 2}
          >
            {requesting ? <LoaderCircle className="spin" size={13} /> : <UserPlus size={13} />}
            Add
          </button>
        </form>
        {error ? (
          <p className="modal-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="relationship-tabs" role="tablist" aria-label="Friend lists">
          {([
            ["friends", "Friends"],
            ["requests", "Requests"],
            ["blocked", "Blocked"],
          ] as const).map(([tab, label]) => (
            <button
              className={activeTab === tab ? "is-active" : ""}
              type="button"
              role="tab"
              aria-selected={activeTab === tab}
              key={tab}
              onClick={() => setActiveTab(tab)}
            >
              {label}
              {tab === "requests" && requestCount > 0 ? (
                <span>{requestCount}</span>
              ) : null}
            </button>
          ))}
        </div>
        <div className="relationship-groups">
          <section className="relationship-group">
            {visibleRelationships.length === 0 ? (
              <p>
                {activeTab === "friends"
                  ? "No friends yet."
                  : activeTab === "requests"
                    ? "No pending requests."
                    : "No blocked accounts."}
              </p>
            ) : (
              visibleRelationships.map((relationship) => {
                    const busy = busyUserId === relationship.userId;
                    return (
                      <article
                        className="relationship-row"
                        key={`${relationship.kind}:${relationship.userId}`}
                      >
                        <span
                          className="relationship-avatar"
                          style={{ background: relationship.color }}
                          aria-hidden="true"
                        >
                          {relationship.initials}
                        </span>
                        <span className="relationship-identity">
                          <strong>{relationship.name}</strong>
                          <small>@{relationship.handle}</small>
                        </span>
                        <span className="relationship-actions">
                          {relationship.kind === "incoming" ? (
                            <button
                              className="relationship-primary"
                              type="button"
                              disabled={busy}
                              onClick={() =>
                                void run(() => onAccept(relationship.userId))
                              }
                            >
                              Accept
                            </button>
                          ) : null}
                          {relationship.kind === "friend" ? (
                            <button
                              className="relationship-primary"
                              type="button"
                              disabled={busy}
                              onClick={() =>
                                void run(() => onMessage(relationship.userId))
                              }
                            >
                              <MessageCircle size={12} /> Message
                            </button>
                          ) : null}
                          {relationship.kind === "blocked" ? (
                            <button
                              className="relationship-primary"
                              type="button"
                              disabled={busy}
                              onClick={() =>
                                void run(() => onRemove(relationship.userId))
                              }
                            >
                              Unblock
                            </button>
                          ) : null}
                          {relationship.kind === "outgoing" ? (
                            <span className="relationship-pending">Pending</span>
                          ) : null}
                          {relationship.kind !== "blocked" ? (
                          <RelationshipOverflowMenu
                            relationship={relationship}
                            busy={busy}
                            onRemove={() =>
                              void run(() => onRemove(relationship.userId))
                            }
                            onBlock={() =>
                              void run(() => onBlock(relationship.userId))
                            }
                          />
                          ) : null}
                          {busy ? (
                            <LoaderCircle className="spin" size={12} />
                          ) : null}
                        </span>
                      </article>
                    );
              })
            )}
          </section>
        </div>
      </section>
    </div>
  );
}

function DirectMessageHome({
  workspace,
  relationships,
  membersById,
  onSelectChannel,
  onOpenFriend,
  onOpenFriends,
  onOpenSearch,
}: {
  workspace: Workspace;
  relationships: RelationshipView[];
  membersById: Map<string, Member>;
  onSelectChannel: (channelId: string) => void;
  onOpenFriend: (userId: string) => Promise<void>;
  onOpenFriends: () => void;
  onOpenSearch: () => void;
}) {
  const friends = relationships.filter(
    (relationship) => relationship.kind === "friend",
  );
  const requests = relationships.filter(
    (relationship) => relationship.kind === "incoming",
  );
  const conversationNames = new Set(
    workspace.channels.map((channel) => channel.name.toLocaleLowerCase()),
  );
  const availableFriends = friends.filter(
    (friend) =>
      !conversationNames.has(friend.name.toLocaleLowerCase()) &&
      !conversationNames.has(friend.handle.toLocaleLowerCase()),
  );
  const onlineFriends = friends
    .map((friend) => membersById.get(friend.userId))
    .filter(
      (member): member is Member =>
        Boolean(member) && member?.presence === "online",
    );

  return (
    <div className="dm-home">
      <header className="dm-home-heading">
        <h1>Messages</h1>
        <div className="dm-home-actions">
          <button type="button" aria-label="Search messages" onClick={onOpenSearch}>
            <Search size={15} />
          </button>
          <button type="button" onClick={onOpenFriends}>
            <UserPlus size={14} />
            New
          </button>
        </div>
      </header>

      {onlineFriends.length > 0 ? (
        <section className="dm-home-section dm-online-section" aria-labelledby="online-friends">
          <div className="dm-home-section-heading">
            <h2 id="online-friends">Online</h2>
            <span>{onlineFriends.length}</span>
          </div>
          <div className="dm-online-list">
            {onlineFriends.map((member) => (
              <button
                type="button"
                key={member.id}
                title={`Message ${member.name}`}
                onClick={() => void onOpenFriend(member.id)}
              >
                <Avatar member={member} size="large" showPresence />
                <span>{member.name}</span>
              </button>
            ))}
          </div>
        </section>
      ) : null}

      <section className="dm-home-section" aria-labelledby="recent-messages">
        <div className="dm-home-section-heading">
          <h2 id="recent-messages">Recent</h2>
          <span>{workspace.channels.length}</span>
        </div>
        {workspace.channels.length > 0 ? (
          <div className="dm-conversation-grid">
            {workspace.channels.map((channel) => {
              const member = [...membersById.values()].find(
                (candidate) =>
                  candidate.name.toLocaleLowerCase() ===
                    channel.name.toLocaleLowerCase() ||
                  candidate.handle.toLocaleLowerCase() ===
                    channel.name.toLocaleLowerCase(),
              );
              return (
                <button
                  type="button"
                  className="dm-conversation-card"
                  key={channel.id}
                  onClick={() => onSelectChannel(channel.id)}
                >
                  {member ? (
                    <Avatar member={member} size="large" showPresence />
                  ) : (
                    <span className="dm-conversation-fallback">
                      {channel.name.slice(0, 2).toUpperCase()}
                    </span>
                  )}
                  <span>
                    <strong>{channel.name}</strong>
                    <small>{channel.unread ? "New messages" : "No unread messages"}</small>
                  </span>
                  {channel.unread ? <i aria-label="Unread" /> : <ChevronRight size={15} />}
                </button>
              );
            })}
          </div>
        ) : (
          <button
            type="button"
            className="dm-empty-card"
            onClick={onOpenFriends}
          >
            <span>
              <MessageCircle size={19} />
            </span>
            <strong>Your inbox is ready</strong>
            <small>Add a friend by their exact handle to start talking.</small>
            <ChevronRight size={16} />
          </button>
        )}
      </section>

      {availableFriends.length > 0 || requests.length > 0 ? (
      <section className="dm-home-section" aria-labelledby="friends-to-message">
        <div className="dm-home-section-heading">
          <h2 id="friends-to-message">
            {availableFriends.length > 0 ? "Friends" : "Requests"}
          </h2>
          <button type="button" onClick={onOpenFriends}>
            {requests.length > 0
              ? `${requests.length} request${requests.length === 1 ? "" : "s"}`
              : `${friends.length} total`}
          </button>
        </div>
        {availableFriends.length > 0 ? (
          <div className="dm-friend-list">
            {availableFriends.slice(0, 5).map((friend) => {
              const member = membersById.get(friend.userId) ?? {
                id: friend.userId,
                name: friend.name,
                handle: friend.handle,
                initials: friend.initials,
                color: friend.color,
                presence: "offline" as const,
              };
              return (
                <button
                  type="button"
                  key={friend.userId}
                  onClick={() => void onOpenFriend(friend.userId)}
                >
                  <Avatar member={member} />
                  <span>
                    <strong>{friend.name}</strong>
                    <small>@{friend.handle}</small>
                  </span>
                  <MessageCircle size={15} />
                </button>
              );
            })}
          </div>
        ) : requests.length > 0 ? (
          <button
            className="dm-request-row"
            type="button"
            onClick={onOpenFriends}
          >
            <Users size={15} />
            <span>
              {requests.length} pending request
              {requests.length === 1 ? "" : "s"}
            </span>
            <ChevronRight size={15} />
          </button>
        ) : null}
      </section>
      ) : null}
    </div>
  );
}

function PresencePanel({
  workspace,
  membersById,
  currentUserId,
}: {
  workspace: Workspace;
  membersById: Map<string, Member>;
  currentUserId: string;
}) {
  const members = (workspace.memberIds ?? [])
    .map((id) => membersById.get(id))
    .filter((member): member is Member => Boolean(member))
    .sort((left, right) => {
      if (left.presence !== right.presence) {
        return left.presence === "online" ? -1 : 1;
      }
      return left.name.localeCompare(right.name);
    });
  const online = members.filter((member) => member.presence === "online");
  const offline = members.filter((member) => member.presence !== "online");
  return (
    <aside className="presence-panel" aria-label="Server members">
      <header>
        <span>Online</span>
        <strong>{online.length}</strong>
      </header>
      <div className="presence-list">
        {online.map((member) => (
          <div className="presence-person" key={member.id}>
            <Avatar member={member} showPresence />
            <span>
              <strong>{member.name}</strong>
              <small>{presenceLabel(member.presence)}</small>
            </span>
          </div>
        ))}
        {online.length === 0 ? <p>No one else is online.</p> : null}
      </div>
      {offline.length > 0 ? (
        <>
          <header className="presence-offline-heading">
            <span>Offline</span>
            <strong>{offline.length}</strong>
          </header>
          <div className="presence-list is-offline">
            {offline.map((member) => (
              <div className="presence-person" key={member.id}>
                <Avatar member={member} />
                <span>
                  <strong>{member.name}</strong>
                  <small>{presenceLabel(member.presence)}</small>
                </span>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </aside>
  );
}

function AvatarOriginalLightbox({
  member,
  onClose,
}: {
  member: Member;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLDivElement>(true, onClose);
  if (!member.avatarUrl) return null;
  return createPortal(
    <div
      className="attachment-lightbox-backdrop"
      role="presentation"
      onMouseDown={onClose}
    >
      <div
        ref={dialogRef}
        className="attachment-lightbox avatar-lightbox"
        role="dialog"
        aria-modal="true"
        aria-label={`${member.name}'s original avatar`}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <GlassSurface
          as="header"
          variant="clear"
          className="attachment-lightbox-header"
        >
          <div>
            <strong>{member.name}'s avatar</strong>
            <small>Original profile image</small>
          </div>
          <div className="attachment-lightbox-actions">
            <a
              href={member.avatarUrl}
              target="_blank"
              rel="noreferrer"
              className="attachment-lightbox-action"
            >
              <Link2 size={15} />
              <span>Open original</span>
            </a>
            <a
              href={member.avatarUrl}
              download="exocord-avatar"
              className="attachment-lightbox-action"
            >
              <Download size={15} />
              <span>Download</span>
            </a>
            <button
              className="attachment-lightbox-close"
              type="button"
              aria-label="Close avatar preview"
              onClick={onClose}
            >
              <X size={17} />
            </button>
          </div>
        </GlassSurface>
        <div className="attachment-lightbox-stage">
          <img
            src={member.avatarUrl}
            alt={`${member.name}'s avatar`}
            referrerPolicy="no-referrer"
          />
        </div>
      </div>
    </div>,
    document.body,
  );
}

function MemberProfileDialog({
  member,
  isCurrentUser,
  onClose,
  onMessage,
  onOpenSettings,
}: {
  member: Member | null;
  isCurrentUser: boolean;
  onClose: () => void;
  onMessage?: (memberId: string) => void;
  onOpenSettings?: () => void;
}) {
  const [avatarOpen, setAvatarOpen] = useState(false);
  const dialogRef = useDialogFocus<HTMLElement>(
    member !== null && !avatarOpen,
    onClose,
  );
  useEffect(() => {
    setAvatarOpen(false);
  }, [member?.id]);
  if (!member) return null;
  return createPortal(
    <div className="modal-backdrop member-profile-backdrop" role="presentation" onMouseDown={onClose}>
      <GlassSurface
        as="section"
        variant="regular"
        ref={dialogRef}
        className="modal-card member-profile-card"
        role="dialog"
        aria-modal="true"
        aria-label={`${member.name}'s profile`}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close profile"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <div className="member-profile-hero">
          {member.avatarUrl ? (
            <button
              className="avatar-profile-trigger"
              type="button"
              aria-label={`View ${member.name}'s original avatar`}
              onClick={() => setAvatarOpen(true)}
            >
              <Avatar member={member} size="large" showPresence />
            </button>
          ) : (
            <Avatar member={member} size="large" showPresence />
          )}
          <div>
            <h2>{member.name}</h2>
            <p>@{member.handle}</p>
          </div>
        </div>
        <div className={`member-profile-presence presence-${member.presence}`}>
          <i aria-hidden="true" />
          {presenceLabel(member.presence)}
        </div>
        <div className="member-profile-actions">
          {isCurrentUser ? (
            <button type="button" className="primary-button" onClick={onOpenSettings}>
              <Settings2 size={14} />
              Edit profile
            </button>
          ) : onMessage ? (
            <button
              type="button"
              className="primary-button"
              onClick={() => onMessage(member.id)}
            >
              <MessageCircle size={14} />
              Message
            </button>
          ) : null}
          <button type="button" className="secondary-button" onClick={onClose}>
            Done
          </button>
        </div>
      </GlassSurface>
      {avatarOpen && member.avatarUrl ? (
        <AvatarOriginalLightbox
          member={member}
          onClose={() => setAvatarOpen(false)}
        />
      ) : null}
    </div>,
    document.body,
  );
}

function SettingsDialog({
  open,
  currentUser,
  compact,
  minimizeToTray,
  windowSettingsBusy,
  notificationMode,
  notificationBusy,
  refractiveGlassMode,
  cacheProtection,
  email,
  passwordAvailable,
  appleAvailable,
  signingOut,
  onCompactChange,
  onUpdateProfile,
  onMinimizeToTrayChange,
  onNotificationModeChange,
  onRefractiveGlassModeChange,
  onClose,
  onLogout,
  onChangePassword,
  onRegenerateRecoveryCodes,
  onExportData,
  onDeleteAccount,
  onResolveOwnership,
}: {
  open: boolean;
  currentUser: Member;
  compact: boolean;
  minimizeToTray: boolean;
  windowSettingsBusy: boolean;
  notificationMode: NotificationMode;
  notificationBusy: boolean;
  refractiveGlassMode: RefractiveGlassMode;
  cacheProtection: BootstrapViewModel["cacheProtection"];
  email: string | null;
  passwordAvailable: boolean;
  appleAvailable: boolean;
  signingOut: boolean;
  onCompactChange: (value: boolean) => void;
  onUpdateProfile: (input: {
    handle: string;
    displayName: string;
    avatarContentType?: string;
    avatarBase64?: string;
    removeAvatar: boolean;
  }) => Promise<void>;
  onMinimizeToTrayChange: (value: boolean) => Promise<void>;
  onNotificationModeChange: (value: NotificationMode) => Promise<void>;
  onRefractiveGlassModeChange: (value: RefractiveGlassMode) => void;
  onClose: () => void;
  onLogout: () => void;
  onChangePassword: (
    currentPassword: string,
    newPassword: string,
  ) => Promise<void>;
  onRegenerateRecoveryCodes: (currentPassword: string) => Promise<string[]>;
  onExportData: () => Promise<string>;
  onDeleteAccount: (confirmation: string) => Promise<AccountDeletionView>;
  onResolveOwnership: (workspaceId: string) => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [security, setSecurity] = useState<DeviceSecurityView | null>(null);
  const [securityError, setSecurityError] = useState<string | null>(null);
  const [fingerprintCopied, setFingerprintCopied] = useState(false);
  const [securityRefresh, setSecurityRefresh] = useState(0);
  const [confirmingDevice, setConfirmingDevice] = useState<string | null>(null);
  const [revokingDevice, setRevokingDevice] = useState<string | null>(null);
  const [accountAction, setAccountAction] = useState<
    "export" | "delete" | null
  >(null);
  const [exportPath, setExportPath] = useState<string | null>(null);
  const [accountError, setAccountError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [deletionStatus, setDeletionStatus] =
    useState<AccountDeletionStatusView | null>(null);
  const [operatorInfo, setOperatorInfo] = useState<OperatorInfoView | null>(null);
  const [operatorError, setOperatorError] = useState<string | null>(null);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordChanged, setPasswordChanged] = useState(false);
  const [recoveryCodesOpen, setRecoveryCodesOpen] = useState(false);
  const [recoveryCodesPassword, setRecoveryCodesPassword] = useState("");
  const [recoveryCodesBusy, setRecoveryCodesBusy] = useState(false);
  const [recoveryCodesError, setRecoveryCodesError] = useState<string | null>(
    null,
  );
  const [replacementRecoveryCodes, setReplacementRecoveryCodes] = useState<
    string[]
  >([]);
  const [replacementCodesCopied, setReplacementCodesCopied] = useState(false);
  const [authMethods, setAuthMethods] =
    useState<AccountAuthMethodsView | null>(null);
  const [authMethodsError, setAuthMethodsError] = useState<string | null>(null);
  const [appleAction, setAppleAction] = useState<"link" | "unlink" | null>(
    null,
  );
  const [applePassword, setApplePassword] = useState("");
  const [appleBusy, setAppleBusy] = useState(false);
  const [appleError, setAppleError] = useState<string | null>(null);
  const [appleChanged, setAppleChanged] = useState<string | null>(null);
  const [profileName, setProfileName] = useState(currentUser.name);
  const [profileHandle, setProfileHandle] = useState(currentUser.handle);
  const [profileAvatarType, setProfileAvatarType] = useState<string | undefined>();
  const [profileAvatarBase64, setProfileAvatarBase64] = useState<
    string | undefined
  >();
  const [profileRemoveAvatar, setProfileRemoveAvatar] = useState(false);
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [profileSaved, setProfileSaved] = useState(false);
  const [settingsSection, setSettingsSection] = useState<
    "account" | "appearance" | "privacy"
  >("account");
  const profileAvatarInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setSecurityError(null);
    void coreBridge
      .deviceSecurityStatus()
      .then((next) => {
        if (active) setSecurity(next);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setSecurityError(
          error instanceof Error
            ? error.message
            : "Device encryption status is unavailable.",
        );
      });
    return () => {
      active = false;
    };
  }, [open, securityRefresh]);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setDeletionStatus(null);
    void coreBridge
      .accountDeletionStatus()
      .then((status) => {
        if (active) setDeletionStatus(status);
      })
      .catch(() => {
        if (active) setDeletionStatus(null);
      });
    return () => {
      active = false;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setOperatorError(null);
    void coreBridge
      .operatorInfo()
      .then((operator) => {
        if (active) setOperatorInfo(operator);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setOperatorError(
          error instanceof Error
            ? error.message
            : "Operator information is unavailable.",
        );
      });
    return () => {
      active = false;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setAuthMethods(null);
    setAuthMethodsError(null);
    void coreBridge
      .accountAuthMethods()
      .then((methods) => {
        if (active) setAuthMethods(methods);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setAuthMethodsError(
          error instanceof Error
            ? error.message
            : "Your sign-in methods are unavailable.",
        );
      });
    return () => {
      active = false;
    };
  }, [open]);

  useEffect(() => {
    if (open) return;
    setAccountAction(null);
    setExportPath(null);
    setAccountError(null);
    setDeleteOpen(false);
    setDeleteConfirmation("");
    setDeletionStatus(null);
    setOperatorInfo(null);
    setOperatorError(null);
    setPasswordOpen(false);
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setPasswordBusy(false);
    setPasswordError(null);
    setPasswordChanged(false);
    setRecoveryCodesOpen(false);
    setRecoveryCodesPassword("");
    setRecoveryCodesBusy(false);
    setRecoveryCodesError(null);
    setReplacementRecoveryCodes([]);
    setReplacementCodesCopied(false);
    setAuthMethods(null);
    setAuthMethodsError(null);
    setAppleAction(null);
    setApplePassword("");
    setAppleBusy(false);
    setAppleError(null);
    setAppleChanged(null);
    setSettingsSection("account");
  }, [open]);

  useEffect(() => {
    if (!open) return;
    setProfileName(currentUser.name);
    setProfileHandle(currentUser.handle);
    setProfileAvatarType(undefined);
    setProfileAvatarBase64(undefined);
    setProfileRemoveAvatar(false);
    setProfileError(null);
    setProfileSaved(false);
  }, [currentUser, open]);

  const revokeDevice = async (deviceId: string) => {
    if (confirmingDevice !== deviceId) {
      setConfirmingDevice(deviceId);
      return;
    }
    setRevokingDevice(deviceId);
    setSecurityError(null);
    try {
      await coreBridge.revokeDevice(deviceId);
      setConfirmingDevice(null);
      setSecurityRefresh((value) => value + 1);
    } catch (error: unknown) {
      setSecurityError(
        error instanceof Error ? error.message : "That device could not be revoked.",
      );
    } finally {
      setRevokingDevice(null);
    }
  };

  const exportData = async () => {
    if (accountAction) return;
    setAccountAction("export");
    setAccountError(null);
    try {
      setExportPath(await onExportData());
    } catch (error: unknown) {
      setAccountError(
        error instanceof Error
          ? error.message
          : "Your account export could not be saved.",
      );
    } finally {
      setAccountAction(null);
    }
  };

  const deleteAccount = async () => {
    if (accountAction || !accountDeleteConfirmed(deleteConfirmation)) return;
    setAccountAction("delete");
    setAccountError(null);
    try {
      await onDeleteAccount(deleteConfirmation);
    } catch (error: unknown) {
      setAccountError(
        error instanceof Error
          ? error.message
          : "Account deletion could not be scheduled.",
      );
      setAccountAction(null);
    }
  };

  const changePassword = async () => {
    if (
      passwordBusy ||
      newPassword.length < 10 ||
      newPassword.length > 128 ||
      newPassword !== confirmPassword
    ) {
      return;
    }
    setPasswordBusy(true);
    setPasswordError(null);
    setPasswordChanged(false);
    try {
      await onChangePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordOpen(false);
      setPasswordChanged(true);
    } catch (error: unknown) {
      setPasswordError(
        error instanceof Error
          ? error.message
          : "Your password could not be changed.",
      );
    } finally {
      setPasswordBusy(false);
    }
  };

  const regenerateRecoveryCodes = async () => {
    if (recoveryCodesBusy || !recoveryCodesPassword) return;
    setRecoveryCodesBusy(true);
    setRecoveryCodesError(null);
    setReplacementRecoveryCodes([]);
    try {
      setReplacementRecoveryCodes(
        await onRegenerateRecoveryCodes(recoveryCodesPassword),
      );
      setRecoveryCodesPassword("");
    } catch (error: unknown) {
      setRecoveryCodesError(
        error instanceof Error
          ? error.message
          : "New recovery codes could not be created.",
      );
    } finally {
      setRecoveryCodesBusy(false);
    }
  };

  const updateAppleConnection = async () => {
    if (!appleAction || appleBusy || !applePassword) return;
    const action = appleAction;
    setAppleBusy(true);
    setAppleError(null);
    setAppleChanged(null);
    try {
      const methods =
        action === "link"
          ? await coreBridge.linkApple(applePassword)
          : await coreBridge.unlinkApple(applePassword);
      setAuthMethods(methods);
      setApplePassword("");
      setAppleAction(null);
      setAppleChanged(
        action === "link"
          ? "Apple is connected. You can use either sign-in method."
          : "Apple was disconnected. Your email and password still work.",
      );
    } catch (error: unknown) {
      setAppleError(
        error instanceof Error
          ? error.message
          : action === "link"
            ? "Apple could not be connected."
            : "Apple could not be disconnected.",
      );
    } finally {
      setAppleBusy(false);
    }
  };

  const saveProfile = async () => {
    const displayName = profileName.trim();
    if (displayName.length < 1 || [...displayName].length > 32) {
      setProfileError("Display names must contain 1–32 characters.");
      return;
    }
    setProfileBusy(true);
    setProfileError(null);
    setProfileSaved(false);
    try {
      await onUpdateProfile({
        handle: profileHandle,
        displayName,
        avatarContentType: profileAvatarType,
        avatarBase64: profileAvatarBase64,
        removeAvatar: profileRemoveAvatar,
      });
      setProfileSaved(true);
      setProfileAvatarType(undefined);
      setProfileAvatarBase64(undefined);
      setProfileRemoveAvatar(false);
    } catch (error: unknown) {
      setProfileError(
        error instanceof Error ? error.message : "Your profile could not be saved.",
      );
    } finally {
      setProfileBusy(false);
    }
  };

  if (!open) return null;
  const ownershipBlockers =
    deletionStatus?.ownedServers.filter((server) => server.memberCount > 1) ??
    [];
  const retiringServers =
    deletionStatus?.ownedServers.filter((server) => server.memberCount <= 1) ??
    [];

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className="modal-card settings-card"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label="Privacy and interface controls"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          type="button"
          aria-label="Close settings"
          onClick={onClose}
        >
          <X size={15} />
        </button>
        <header className="settings-titlebar">
          <div className="modal-icon">
            <Settings2 size={18} />
          </div>
          <span>
            <h2>Settings</h2>
          </span>
        </header>
        <div className="settings-layout">
          <div className="settings-section-strip-wrap">
            <div className="settings-identity">
              <Avatar member={currentUser} size="large" />
              <span>
                <strong>{currentUser.name}</strong>
                <small>@{currentUser.handle}</small>
              </span>
            </div>
            <nav className="settings-section-strip" aria-label="Settings sections">
            {[
              ["account", "Account"],
              ["appearance", "Appearance & notifications"],
              ["privacy", "Privacy & security"],
            ].map(([id, label]) => (
              <button
                className={settingsSection === id ? "is-active" : ""}
                type="button"
                key={id}
                aria-pressed={settingsSection === id}
                onClick={() =>
                  setSettingsSection(
                    id as "account" | "appearance" | "privacy",
                  )
                }
              >
                {label}
              </button>
            ))}
            </nav>
          </div>
          <div className="settings-content" data-section={settingsSection}>
            <div
              className="settings-view settings-view-account"
              hidden={settingsSection !== "account"}
            >
            <section className="profile-settings-panel">
              <div className="settings-section-heading">
                <span>PROFILE</span>
                <h3>Profile</h3>
              </div>
              <div className="profile-editor">
                <div className="profile-avatar-editor">
                  <span className="profile-avatar-preview">
                    {profileAvatarBase64 && profileAvatarType ? (
                      <img
                        src={`data:${profileAvatarType};base64,${profileAvatarBase64}`}
                        alt=""
                      />
                    ) : !profileRemoveAvatar && currentUser.avatarUrl ? (
                      <img src={currentUser.avatarUrl} alt="" />
                    ) : (
                      currentUser.initials
                    )}
                  </span>
                  <input
                    ref={profileAvatarInputRef}
                    className="visually-hidden"
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    tabIndex={-1}
                    onChange={(event) => {
                      const file = event.target.files?.[0];
                      event.currentTarget.value = "";
                      if (!file) return;
                      if (file.size > 512 * 1024) {
                        setProfileError("Profile pictures must be 512 KiB or smaller.");
                        return;
                      }
                      const reader = new FileReader();
                      reader.onload = () => {
                        const result =
                          typeof reader.result === "string" ? reader.result : "";
                        const comma = result.indexOf(",");
                        if (comma < 0) {
                          setProfileError("That image could not be read.");
                          return;
                        }
                        setProfileAvatarType(file.type);
                        setProfileAvatarBase64(result.slice(comma + 1));
                        setProfileRemoveAvatar(false);
                        setProfileError(null);
                        setProfileSaved(false);
                      };
                      reader.onerror = () =>
                        setProfileError("That image could not be read.");
                      reader.readAsDataURL(file);
                    }}
                  />
                  <span>
                    <button
                      type="button"
                      onClick={() => profileAvatarInputRef.current?.click()}
                    >
                      <Paperclip size={12} />
                      Choose image
                    </button>
                    {(currentUser.avatarUrl || profileAvatarBase64) &&
                    !profileRemoveAvatar ? (
                      <button
                        type="button"
                        onClick={() => {
                          setProfileAvatarBase64(undefined);
                          setProfileAvatarType(undefined);
                          setProfileRemoveAvatar(true);
                          setProfileSaved(false);
                        }}
                      >
                        Remove
                      </button>
                    ) : null}
                  </span>
                  <small>PNG, JPEG, or WebP · up to 512 KiB</small>
                </div>
                <label>
                  Display name
                  <input
                    value={profileName}
                    maxLength={32}
                    onChange={(event) => {
                      setProfileName(event.target.value);
                      setProfileSaved(false);
                    }}
                  />
                </label>
                <label>
                  Username
                  <span className="profile-handle-input is-readonly">
                    <AtSign size={13} />
                    <input
                      value={profileHandle}
                      readOnly
                      aria-readonly="true"
                    />
                  </span>
                </label>
                <div className="profile-save-row">
                  <span>
                    {profileError ? (
                      <small role="alert">{profileError}</small>
                    ) : profileSaved ? (
                      <small className="profile-save-success">
                        <Check size={11} /> Saved
                      </small>
                    ) : (
                      <small>Your username is permanent.</small>
                    )}
                  </span>
                  <button
                    type="button"
                    disabled={profileBusy}
                    onClick={() => void saveProfile()}
                  >
                    {profileBusy ? <LoaderCircle className="spin" size={12} /> : null}
                    {profileBusy ? "Saving" : "Save profile"}
                  </button>
                </div>
              </div>
            </section>
            </div>
        <div
          className="settings-view settings-view-appearance"
          hidden={settingsSection !== "appearance"}
        >
        <div className="settings-view-heading">
          <h3>Appearance & notifications</h3>
        </div>
        <details className="settings-appearance-details">
          <summary>
            <span>
              <strong>Glass appearance</strong>
              <small>
                {refractiveGlassMode === "refractive"
                  ? "Refractive"
                  : refractiveGlassMode === "solid"
                    ? "Solid"
                    : "System"}
              </small>
            </span>
            <ChevronDown size={14} />
          </summary>
          <div className="settings-appearance-panel">
            <label className="setting-row setting-choice">
              <span>
                <strong>Surface style</strong>
                <span>Choose whether Exocord uses the refractive glass layer.</span>
              </span>
              <select
                aria-label="Glass appearance"
                value={refractiveGlassMode}
                onChange={(event) =>
                  onRefractiveGlassModeChange(
                    event.target.value as RefractiveGlassMode,
                  )
                }
              >
                <option value="system">System</option>
                <option value="refractive">Refractive</option>
                <option value="solid">Solid</option>
              </select>
            </label>
            <p className="settings-appearance-note">
              Refractive uses more GPU. Windows Forced Colors always overrides this setting.
            </p>
          </div>
        </details>
        <label className="setting-row setting-choice">
          <span>
            <strong>Windows notifications</strong>
            <span>
              Private hides all names. Names shows sender and conversation,
              never message text.
            </span>
          </span>
          <select
            aria-label="Windows notification privacy"
            value={notificationMode}
            disabled={notificationBusy}
            onChange={(event) =>
              void onNotificationModeChange(
                event.target.value as NotificationMode,
              )
            }
          >
            <option value="private">Private</option>
            <option value="names">Names</option>
            <option value="off">Off</option>
          </select>
        </label>
        <label className="setting-row setting-toggle">
          <span>
            <strong>Compact conversation</strong>
            <span>Reduce message spacing without shrinking text.</span>
          </span>
          <input
            type="checkbox"
            checked={compact}
            onChange={(event) => onCompactChange(event.target.checked)}
          />
          <i aria-hidden="true" />
        </label>
        <label className="setting-row setting-toggle">
          <span>
            <strong>Keep Exocord in the tray</strong>
            <span>
              Closing the window hides it in Windows hidden icons. Use the tray
              menu to quit.
            </span>
          </span>
          <input
            type="checkbox"
            checked={minimizeToTray}
            disabled={windowSettingsBusy}
            onChange={(event) =>
              void onMinimizeToTrayChange(event.target.checked)
            }
          />
          <i aria-hidden="true" />
        </label>
        </div>
        <div
          className="settings-view settings-view-privacy"
          hidden={settingsSection !== "privacy"}
        >
        <div className="settings-view-heading">
          <h3>Privacy & security</h3>
        </div>
        <div className="setting-row setting-security-summary">
          <div>
            <strong>Encryption</strong>
            <span>Messages and local account data are protected.</span>
          </div>
          <span
            className={`status-pill ${
              cacheProtection.encrypted && security?.ready
                ? ""
                : "status-warning"
            }`}
          >
            {cacheProtection.encrypted && security?.ready
              ? "Protected"
              : "Checking"}
          </span>
        </div>
        <details className="settings-security-details">
          <summary>
            Security details
            <ChevronDown size={14} />
          </summary>
        <div className="setting-row setting-security-heading">
          <div>
            <strong>Local cache protection</strong>
            <span>
              {cacheProtection.cipher} · Key in{" "}
              {cacheProtection.keyStorage.toLowerCase()}
            </span>
          </div>
          <span
            className={`status-pill ${
              cacheProtection.encrypted ? "" : "status-warning"
            }`}
          >
            {cacheProtection.encrypted ? "Encrypted" : "Unavailable"}
          </span>
        </div>
        <div className="setting-row setting-security-heading">
          <div>
            <strong>End-to-end encrypted messages</strong>
            <span>
              {security?.ready
                ? security.cipherSuite
                : "Preparing this device's private MLS identity…"}
            </span>
          </div>
          <span
            className={`status-pill ${
              security?.ready ? "" : "status-warning"
            }`}
          >
            {security?.ready ? "MLS active" : "Checking"}
          </span>
        </div>
        {security?.fingerprint ? (
          <section className="device-security-panel" aria-label="Device verification">
            <div className="device-security-title">
              <span>
                <strong>This device fingerprint</strong>
                <small>
                  Compare this in person or over another trusted channel.
                </small>
              </span>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard
                    .writeText(security.fingerprint ?? "")
                    .then(() => {
                      setFingerprintCopied(true);
                      window.setTimeout(() => setFingerprintCopied(false), 1800);
                    })
                    .catch(() => {
                      setFingerprintCopied(false);
                      setSecurityError("The device fingerprint could not be copied.");
                    });
                }}
              >
                {fingerprintCopied ? <Check size={13} /> : <Copy size={13} />}
                {fingerprintCopied ? "Copied" : "Copy"}
              </button>
            </div>
            <code>{security.fingerprint}</code>
            <div className="device-security-list">
              {security.devices.map((device) => (
                <div key={device.deviceId}>
                  <span>
                    <strong>{device.name}</strong>
                    <small>{device.current ? "This device" : device.fingerprint}</small>
                  </span>
                  <span className="device-security-actions">
                    <span
                      className={`status-pill ${
                        device.revoked ? "status-warning" : ""
                      }`}
                    >
                      {device.revoked ? "Revoked" : "Active"}
                    </span>
                    {!device.current && !device.revoked ? (
                      <button
                        className={
                          confirmingDevice === device.deviceId
                            ? "device-revoke-confirm"
                            : ""
                        }
                        type="button"
                        disabled={revokingDevice !== null}
                        onBlur={() => {
                          if (revokingDevice !== device.deviceId) {
                            setConfirmingDevice(null);
                          }
                        }}
                        onClick={() => void revokeDevice(device.deviceId)}
                        aria-label={`Revoke ${device.name}`}
                      >
                        {revokingDevice === device.deviceId ? (
                          <LoaderCircle className="spin" size={11} />
                        ) : (
                          <Trash2 size={11} />
                        )}
                        {revokingDevice === device.deviceId
                          ? "Revoking"
                          : confirmingDevice === device.deviceId
                            ? "Confirm"
                            : "Revoke"}
                      </button>
                    ) : null}
                  </span>
                </div>
              ))}
            </div>
          </section>
        ) : null}
        <div className="device-recovery-notice">
          <LockKeyhole size={15} />
          <span>
            <strong>Private history recovery</strong>
            <small>
              {security?.historyNotice ??
                "Sign in after reinstalling to restore account data and client-encrypted direct-message history. Exocord never receives the recovery key or archived plaintext."}
            </small>
          </span>
        </div>
        {security?.error || securityError ? (
          <div className="device-security-error" role="status">
            <CloudOff size={13} />
            {security?.error ?? securityError}
          </div>
        ) : null}
        </details>
        {operatorInfo ? (
          <section className="operator-panel" aria-label="Alpha operator">
            <div>
              <ShieldCheck size={15} />
              <span>
                <strong>{operatorInfo.name}</strong>
                <small>
                  This organization operates your selected Exocord alpha.
                </small>
              </span>
            </div>
            <div className="operator-actions">
              {operatorInfo.privacyUrl ? (
                <button
                  type="button"
                  onClick={() =>
                    void coreBridge.openOperatorResource("privacy").catch(
                      (error: unknown) =>
                        setOperatorError(
                          error instanceof Error
                            ? error.message
                            : "The privacy notice could not be opened.",
                        ),
                    )
                  }
                >
                  <FileText size={12} />
                  Privacy
                </button>
              ) : null}
              {operatorInfo.termsUrl ? (
                <button
                  type="button"
                  onClick={() =>
                    void coreBridge.openOperatorResource("terms").catch(
                      (error: unknown) =>
                        setOperatorError(
                          error instanceof Error
                            ? error.message
                            : "The terms could not be opened.",
                        ),
                    )
                  }
                >
                  <FileText size={12} />
                  Terms
                </button>
              ) : null}
              {operatorInfo.supportEmail ? (
                <button
                  type="button"
                  onClick={() =>
                    void coreBridge.openOperatorResource("support").catch(
                      (error: unknown) =>
                        setOperatorError(
                          error instanceof Error
                            ? error.message
                            : "The support contact could not be opened.",
                        ),
                    )
                  }
                >
                  <Mail size={12} />
                  Support
                </button>
              ) : null}
              {operatorInfo.abuseEmail ? (
                <button
                  type="button"
                  onClick={() =>
                    void coreBridge.openOperatorResource("abuse").catch(
                      (error: unknown) =>
                        setOperatorError(
                          error instanceof Error
                            ? error.message
                            : "The abuse contact could not be opened.",
                        ),
                    )
                  }
                >
                  <Flag size={12} />
                  Report abuse
                </button>
              ) : null}
            </div>
            {operatorError ? <p role="alert">{operatorError}</p> : null}
          </section>
        ) : null}
        </div>
        <div
          className="settings-view settings-view-account"
          hidden={settingsSection !== "account"}
        >
        {appleAvailable || authMethods?.appleLinked ? (
        <section className="identity-panel" aria-label="Sign-in methods">
          <div className="identity-panel-heading">
            <span>
              <strong>Sign-in methods</strong>
              <small>
                Connections stay visible and removable. Apple never changes
                your Exocord email or display name.
              </small>
            </span>
          </div>
          <div className="identity-provider-row">
            <span className="identity-provider-icon" aria-hidden="true">
              <Apple size={14} />
            </span>
            <span className="identity-provider-copy">
              <strong>Apple</strong>
              <small>
                {authMethods?.appleLinked
                    ? authMethods.appleEmail ??
                      "Connected with a private Apple identity."
                    : !appleAvailable
                      ? "Not configured by this Exocord operator."
                    : authMethods
                      ? authMethods.passwordSet
                        ? "Connect it as an additional way to sign in."
                        : "A password is required before Apple can be connected."
                      : "Checking this account…"}
              </small>
            </span>
            <span
              className={`status-pill ${
                !appleAvailable && !authMethods?.appleLinked
                  ? "status-warning"
                  : ""
              }`}
            >
              {authMethods?.appleLinked
                ? "Connected"
                : !appleAvailable
                  ? "Unavailable"
                  : !authMethods
                  ? "Checking"
                  : "Not connected"}
            </span>
            {authMethods?.passwordSet &&
            (authMethods.appleLinked || appleAvailable) &&
            appleAction === null ? (
              <button
                type="button"
                onClick={() => {
                  setAppleAction(
                    authMethods.appleLinked ? "unlink" : "link",
                  );
                  setApplePassword("");
                  setAppleError(null);
                  setAppleChanged(null);
                }}
              >
                <Link2 size={12} />
                {authMethods.appleLinked ? "Disconnect" : "Connect"}
              </button>
            ) : null}
          </div>
          {authMethods?.appleLinked && !authMethods.passwordSet ? (
            <p className="identity-method-notice">
              Apple is your only durable sign-in method, so it cannot be
              disconnected.
            </p>
          ) : null}
          {appleAction ? (
            <form
              className="password-change-form identity-apple-form"
              onSubmit={(event) => {
                event.preventDefault();
                void updateAppleConnection();
              }}
            >
              <p className="identity-method-notice">
                {appleAction === "link"
                  ? "Confirm your password, then finish in the secure Apple page that opens in your browser."
                  : "Disconnecting Apple removes it as a sign-in method. Your email and password continue to work."}
              </p>
              <label>
                Current password
                <input
                  type="password"
                  value={applePassword}
                  autoComplete="current-password"
                  autoFocus
                  maxLength={128}
                  required
                  onChange={(event) => setApplePassword(event.target.value)}
                />
              </label>
              {appleError ? <p role="alert">{appleError}</p> : null}
              <div className="password-change-actions">
                <button
                  type="button"
                  disabled={appleBusy}
                  onClick={() => {
                    setAppleAction(null);
                    setApplePassword("");
                    setAppleError(null);
                  }}
                >
                  Cancel
                </button>
                <button
                  className={
                    appleAction === "unlink"
                      ? "identity-disconnect-submit"
                      : "password-change-submit"
                  }
                  type="submit"
                  disabled={appleBusy || !applePassword}
                >
                  {appleBusy ? (
                    <LoaderCircle className="spin" size={12} />
                  ) : appleAction === "link" ? (
                    <Apple size={12} />
                  ) : (
                    <Link2 size={12} />
                  )}
                  {appleBusy
                    ? appleAction === "link"
                      ? "Waiting for Apple"
                      : "Disconnecting"
                    : appleAction === "link"
                      ? "Continue with Apple"
                      : "Disconnect Apple"}
                </button>
              </div>
            </form>
          ) : null}
          {appleChanged ? (
            <p className="password-change-success" role="status">
              <Check size={12} />
              {appleChanged}
            </p>
          ) : null}
          {authMethodsError ? (
            <p className="identity-method-error" role="alert">
              {authMethodsError}
            </p>
          ) : null}
        </section>
        ) : null}
        {passwordAvailable && (authMethods?.passwordSet ?? true) ? (
          <section className="password-panel" aria-label="Password security">
            <div className="password-panel-heading">
              <span>
                <strong>Password</strong>
                <small>
                  Changing it signs every other session out of your account.
                </small>
              </span>
              <div className="password-panel-heading-actions">
                {!passwordOpen ? (
                  <button
                    type="button"
                    onClick={() => {
                      setPasswordOpen(true);
                      setRecoveryCodesOpen(false);
                      setReplacementRecoveryCodes([]);
                      setPasswordChanged(false);
                      setPasswordError(null);
                    }}
                  >
                    <LockKeyhole size={12} />
                    Change
                  </button>
                ) : null}
                {!recoveryCodesOpen ? (
                  <button
                    type="button"
                    onClick={() => {
                      setRecoveryCodesOpen(true);
                      setPasswordOpen(false);
                      setCurrentPassword("");
                      setNewPassword("");
                      setConfirmPassword("");
                      setPasswordError(null);
                      setRecoveryCodesError(null);
                      setReplacementRecoveryCodes([]);
                    }}
                  >
                    <RefreshCw size={12} />
                    Recovery codes
                  </button>
                ) : null}
              </div>
            </div>
            {passwordOpen ? (
              <form
                className="password-change-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void changePassword();
                }}
              >
                <label>
                  Current password
                  <input
                    type="password"
                    value={currentPassword}
                    autoComplete="current-password"
                    autoFocus
                    maxLength={128}
                    required
                    onChange={(event) =>
                      setCurrentPassword(event.target.value)
                    }
                  />
                </label>
                <label>
                  New password
                  <input
                    type="password"
                    value={newPassword}
                    autoComplete="new-password"
                    minLength={10}
                    maxLength={128}
                    required
                    onChange={(event) => setNewPassword(event.target.value)}
                  />
                </label>
                <label>
                  Confirm new password
                  <input
                    type="password"
                    value={confirmPassword}
                    autoComplete="new-password"
                    minLength={10}
                    maxLength={128}
                    required
                    onChange={(event) =>
                      setConfirmPassword(event.target.value)
                    }
                  />
                </label>
                <small className="password-change-hint">
                  Use 10–128 characters.
                </small>
                {confirmPassword && newPassword !== confirmPassword ? (
                  <p role="alert">The new passwords do not match.</p>
                ) : null}
                {passwordError ? <p role="alert">{passwordError}</p> : null}
                <div className="password-change-actions">
                  <button
                    type="button"
                    disabled={passwordBusy}
                    onClick={() => {
                      setPasswordOpen(false);
                      setCurrentPassword("");
                      setNewPassword("");
                      setConfirmPassword("");
                      setPasswordError(null);
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    className="password-change-submit"
                    type="submit"
                    disabled={
                      passwordBusy ||
                      currentPassword.length === 0 ||
                      newPassword.length < 10 ||
                      newPassword.length > 128 ||
                      newPassword !== confirmPassword
                    }
                  >
                    {passwordBusy ? (
                      <LoaderCircle className="spin" size={12} />
                    ) : (
                      <Check size={12} />
                    )}
                    {passwordBusy ? "Changing" : "Change password"}
                  </button>
                </div>
              </form>
            ) : null}
            {passwordChanged ? (
              <p className="password-change-success" role="status">
                <Check size={12} />
                Password changed. Other sessions were signed out.
              </p>
            ) : null}
            {recoveryCodesOpen ? (
              <form
                className="password-change-form recovery-code-replace-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void regenerateRecoveryCodes();
                }}
              >
                {replacementRecoveryCodes.length === 0 ? (
                  <>
                    <p className="recovery-code-warning">
                      This immediately invalidates every recovery code you
                      saved before.
                    </p>
                    <label>
                      Current password
                      <input
                        type="password"
                        value={recoveryCodesPassword}
                        autoComplete="current-password"
                        autoFocus
                        maxLength={128}
                        required
                        onChange={(event) =>
                          setRecoveryCodesPassword(event.target.value)
                        }
                      />
                    </label>
                    {recoveryCodesError ? (
                      <p role="alert">{recoveryCodesError}</p>
                    ) : null}
                    <div className="password-change-actions">
                      <button
                        type="button"
                        disabled={recoveryCodesBusy}
                        onClick={() => {
                          setRecoveryCodesOpen(false);
                          setRecoveryCodesPassword("");
                          setRecoveryCodesError(null);
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        className="password-change-submit"
                        type="submit"
                        disabled={
                          recoveryCodesBusy || !recoveryCodesPassword
                        }
                      >
                        {recoveryCodesBusy ? (
                          <LoaderCircle className="spin" size={12} />
                        ) : (
                          <RefreshCw size={12} />
                        )}
                        {recoveryCodesBusy ? "Replacing" : "Replace codes"}
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="recovery-code-warning recovery-code-ready">
                      Save these now. They will not be shown again.
                    </p>
                    <div className="recovery-code-grid settings-recovery-code-grid">
                      {replacementRecoveryCodes.map((code, index) => (
                        <code key={code}>
                          <span>{index + 1}</span>
                          {code}
                        </code>
                      ))}
                    </div>
                    <div className="password-change-actions">
                      <button
                        type="button"
                        onClick={() => {
                          void navigator.clipboard
                            .writeText(replacementRecoveryCodes.join("\n"))
                            .then(() => {
                              setReplacementCodesCopied(true);
                              window.setTimeout(
                                () => setReplacementCodesCopied(false),
                                1800,
                              );
                            })
                            .catch(() => {
                              setReplacementCodesCopied(false);
                              setRecoveryCodesError(
                                "The recovery codes could not be copied.",
                              );
                            });
                        }}
                      >
                        {replacementCodesCopied ? (
                          <Check size={12} />
                        ) : (
                          <Copy size={12} />
                        )}
                        {replacementCodesCopied ? "Copied" : "Copy all"}
                      </button>
                      <button
                        className="password-change-submit"
                        type="button"
                        onClick={() => {
                          setRecoveryCodesOpen(false);
                          setReplacementRecoveryCodes([]);
                          setReplacementCodesCopied(false);
                        }}
                      >
                        <Check size={12} />
                        Done
                      </button>
                    </div>
                  </>
                )}
              </form>
            ) : null}
          </section>
        ) : null}
        <section className="account-data-panel" aria-label="Account and data">
          <div className="account-data-heading">
            <span>
              <strong>Your data</strong>
              <small>
                Export a machine-readable JSON copy without session secrets.
              </small>
            </span>
            <button
              type="button"
              disabled={accountAction !== null}
              onClick={() => void exportData()}
            >
              {accountAction === "export" ? (
                <LoaderCircle className="spin" size={13} />
              ) : (
                <Download size={13} />
              )}
              {accountAction === "export" ? "Exporting" : "Download"}
            </button>
          </div>
          {exportPath ? (
            <p className="account-export-path" role="status">
              Saved to <code>{exportPath}</code>
            </p>
          ) : null}
          {!deleteOpen ? (
            <button
              className="account-delete-open"
              type="button"
              disabled={accountAction !== null}
              onClick={() => {
                setDeleteOpen(true);
                setAccountError(null);
              }}
            >
              <Trash2 size={12} />
              Delete account…
            </button>
          ) : (
            <div className="account-delete-confirm">
              <div>
                <Trash2 size={15} />
                <span>
                  <strong>Schedule permanent deletion</strong>
                  <small>
                    You will be signed out now and have 30 days to cancel.
                    Profile data, relationships, login identities, and device
                    access are removed after the deadline. Shared messages stay
                    under an anonymized Deleted User identity. This does not
                    erase the encrypted cache on this device.
                  </small>
                </span>
              </div>
              {ownershipBlockers.length ? (
                <section className="account-ownership-blockers">
                  <strong>Resolve server ownership first</strong>
                  <small>
                    A server with other members cannot be left without an
                    owner. Transfer it or delete it before deleting your
                    account.
                  </small>
                  {ownershipBlockers.map((server) => (
                    <button
                      key={server.id}
                      type="button"
                      onClick={() => onResolveOwnership(server.id)}
                    >
                      <span>
                        {server.name}
                        <small>{server.memberCount} members</small>
                      </span>
                      <ChevronRight size={13} />
                    </button>
                  ))}
                </section>
              ) : null}
              {retiringServers.length ? (
                <p className="account-server-retirement">
                  {retiringServers.length === 1
                    ? `${retiringServers[0].name} has no other members and will be retired when deletion completes.`
                    : `${retiringServers.length} servers with no other members will be retired when deletion completes.`}
                </p>
              ) : null}
              <label htmlFor="delete-account-confirmation">
                Type <code>{ACCOUNT_DELETE_CONFIRMATION}</code>
              </label>
              <input
                id="delete-account-confirmation"
                value={deleteConfirmation}
                autoFocus
                autoComplete="off"
                spellCheck={false}
                placeholder={ACCOUNT_DELETE_CONFIRMATION}
                onChange={(event) =>
                  setDeleteConfirmation(event.target.value)
                }
              />
              <div className="account-delete-actions">
                <button
                  type="button"
                  disabled={accountAction !== null}
                  onClick={() => {
                    setDeleteOpen(false);
                    setDeleteConfirmation("");
                    setAccountError(null);
                  }}
                >
                  Keep account
                </button>
                <button
                  className="account-delete-final"
                  type="button"
                  disabled={
                    accountAction !== null ||
                    ownershipBlockers.length > 0 ||
                    !accountDeleteConfirmed(deleteConfirmation)
                  }
                  onClick={() => void deleteAccount()}
                >
                  {accountAction === "delete" ? (
                    <LoaderCircle className="spin" size={13} />
                  ) : (
                    <Trash2 size={13} />
                  )}
                  {accountAction === "delete"
                    ? "Scheduling deletion"
                    : ownershipBlockers.length
                      ? "Resolve ownership first"
                      : "Schedule deletion"}
                </button>
              </div>
            </div>
          )}
          {accountError ? (
            <p className="account-data-error" role="alert">
              {accountError}
            </p>
          ) : null}
        </section>
        <div className="setting-row">
          <div>
            <strong>Account</strong>
            <span>{email ?? "Signed in on this device"}</span>
          </div>
          <button
            className="settings-signout"
            type="button"
            disabled={signingOut}
            onClick={onLogout}
          >
            {signingOut ? (
              <LoaderCircle className="spin" size={14} />
            ) : (
              <LogOut size={14} />
            )}
            {signingOut ? "Signing out" : "Sign out"}
          </button>
        </div>
        </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function SearchDialog({
  open,
  workspace,
  membersById,
  onOpenHit,
  onClose,
}: {
  open: boolean;
  workspace?: Workspace;
  membersById: Map<string, Member>;
  onOpenHit: (hit: SearchHit) => void;
  onClose: () => void;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<SearchView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) {
      setQuery("");
      setResult(null);
      setError(null);
      return;
    }
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, [open, workspace?.id]);

  useEffect(() => {
    if (!open || !workspace || query.trim().length < 2) {
      setResult(null);
      setBusy(false);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setBusy(true);
      setError(null);
      void coreBridge
        .searchMessages({
          workspaceId: workspace.id,
          query: query.trim(),
        })
        .then((next) => {
          if (!cancelled) setResult(next);
        })
        .catch((searchError: unknown) => {
          if (!cancelled) {
            setError(
              searchError instanceof Error
                ? searchError.message
                : "Search is temporarily unavailable.",
            );
          }
        })
        .finally(() => {
          if (!cancelled) setBusy(false);
        });
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [open, query, workspace]);

  if (!open) return null;
  return (
    <div className="modal-backdrop search-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className={`search-dialog ${
          query.trim().length < 2 ? "is-idle" : ""
        }`}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`Search ${workspace?.name ?? "messages"}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="search-heading">
          <Search size={17} />
          <input
            ref={inputRef}
            value={query}
            maxLength={256}
            placeholder={
              workspace?.directMessages
                ? "Search private messages on this device"
                : `Search ${workspace?.name ?? "this server"}`
            }
            aria-label="Search messages"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") onClose();
            }}
          />
          {busy ? <LoaderCircle className="spin" size={15} /> : null}
        </header>
        <div className="search-results" aria-live="polite">
          {error ? <p className="search-state search-error">{error}</p> : null}
          {!error && result && result.hits.length === 0 ? (
            <div className="search-empty">
              <span className="search-empty-mark">0</span>
              <strong>No matching messages</strong>
              <span>Try fewer or more specific words.</span>
            </div>
          ) : null}
          {result?.hits.map((hit) => {
            const author = membersById.get(hit.message.authorId);
            return (
              <button
                className="search-hit"
                type="button"
                key={`${hit.localOnly ? "local" : "server"}-${hit.message.id}`}
                onClick={() => onOpenHit(hit)}
              >
                <span className="search-hit-route">
                  {workspace?.directMessages ? (
                    <AtSign size={11} />
                  ) : (
                    <Hash size={11} />
                  )}
                  {hit.channelName}
                  {hit.localOnly ? <em>this device</em> : null}
                  <time>{hit.message.sentAt}</time>
                </span>
                <span className="search-hit-copy">
                  <strong>{author?.handle ?? "member"}</strong>
                  <span>{hit.message.content || "Attachment"}</span>
                </span>
              </button>
            );
          })}
        </div>
        {result ? (
          <footer className="search-footer">
            <span>
              {result.total} {result.total === 1 ? "match" : "matches"}
            </span>
            {result.encryptedChannelCount > 0 ? (
              <span>
                {result.encryptedChannelCount} encrypted{" "}
                {result.encryptedChannelCount === 1 ? "channel was" : "channels were"} searched
                only from history on this device.
              </span>
            ) : null}
            {result.permissionExcludedCount > 0 ? (
              <span>
                {result.permissionExcludedCount} inaccessible{" "}
                {result.permissionExcludedCount === 1 ? "channel was" : "channels were"} excluded.
              </span>
            ) : null}
          </footer>
        ) : null}
      </section>
    </div>
  );
}

function CacheRecoveryScreen({
  recovery,
}: {
  recovery: CacheRecoveryView;
}) {
  const [resetOpen, setResetOpen] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState<"retry" | "folder" | "reset" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const perform = async (
    action: "retry" | "folder" | "reset",
    task: () => Promise<void>,
  ) => {
    setBusy(action);
    setError(null);
    try {
      await task();
    } catch (actionError) {
      setError(
        actionError instanceof Error
          ? actionError.message
          : "The recovery action could not be completed.",
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="cache-recovery-screen">
      <WindowControls />
      <section
        className="cache-recovery-card"
        aria-labelledby="cache-recovery-title"
      >
        <header className="cache-recovery-heading">
          <span className="cache-recovery-mark">
            <LockKeyhole size={22} />
          </span>
          <div>
            <span>LOCAL DATA PROTECTED</span>
            <h1 id="cache-recovery-title">{recovery.title}</h1>
            <p>{recovery.message}</p>
          </div>
        </header>

        <section className="cache-recovery-status">
          <div>
            <ShieldCheck size={16} />
            <span>
              <strong>No silent reset</strong>
              Synchronization, login restoration, and the outbox are paused.
            </span>
          </div>
          <code>{recovery.cachePath}</code>
          <details>
            <summary>Technical detail</summary>
            <p>
              {recovery.reason} · {recovery.detail}
            </p>
          </details>
        </section>

        <div className="cache-recovery-actions">
          <button
            className="cache-recovery-primary"
            type="button"
            disabled={busy !== null}
            onClick={() =>
              void perform("retry", () => coreBridge.retryLocalCache())
            }
          >
            <RefreshCw
              className={busy === "retry" ? "is-spinning" : undefined}
              size={15}
            />
            Restart and retry
          </button>
          <button
            className="cache-recovery-secondary"
            type="button"
            disabled={busy !== null}
            onClick={() =>
              void perform("folder", () => coreBridge.openLocalCacheFolder())
            }
          >
            <FolderOpen size={15} />
            Show cache folder
          </button>
          {recovery.canReset ? (
            <button
              className="cache-recovery-reset"
              type="button"
              disabled={busy !== null}
              onClick={() => {
                setResetOpen(true);
                setError(null);
              }}
            >
              Start with a fresh cache
            </button>
          ) : null}
        </div>

        {resetOpen && recovery.canReset ? (
          <section
            className="cache-reset-confirmation"
            aria-labelledby="cache-reset-title"
          >
            <div>
              <Trash2 size={17} />
              <span>
                <strong id="cache-reset-title">Preserve, then reset</strong>
                The unreadable database and every sidecar will be moved into a
                dated recovery folder. Server-retained data can synchronize
                again, but unsent messages and device-only history may remain
                inaccessible.
              </span>
            </div>
            <label htmlFor="cache-reset-confirmation">
              Type <code>{CACHE_RESET_CONFIRMATION}</code>
            </label>
            <input
              id="cache-reset-confirmation"
              autoComplete="off"
              spellCheck={false}
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
            />
            <div>
              <button
                type="button"
                disabled={busy !== null}
                onClick={() => {
                  setResetOpen(false);
                  setConfirmation("");
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={
                  busy !== null || !cacheResetConfirmed(confirmation)
                }
                onClick={() =>
                  void perform("reset", () =>
                    coreBridge.resetLocalCache(confirmation),
                  )
                }
              >
                {busy === "reset" ? (
                  <LoaderCircle className="is-spinning" size={14} />
                ) : (
                  <Trash2 size={14} />
                )}
                Preserve files and reset
              </button>
            </div>
          </section>
        ) : null}

        {!recovery.canReset ? (
          <p className="cache-recovery-boundary">
            Starting fresh is disabled because it cannot repair this condition.
            Restore the operating-system vault or reinstall a verified build,
            then retry.
          </p>
        ) : null}
        {error ? (
          <p className="cache-recovery-error" role="alert">
            {error}
          </p>
        ) : null}
        <footer>
          Nothing has been deleted. Exocord will not open this cache as
          plaintext.
        </footer>
      </section>
    </main>
  );
}

function UpdatePrompt({
  update,
  onDismiss,
}: {
  update: UpdateManifest;
  onDismiss: () => void;
}) {
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <aside className="update-prompt" role="status" aria-label="Exocord update available">
      <span className="update-prompt-icon"><Download size={17} /></span>
      <div>
        <strong>Exocord {update.version}</strong>
        <p>{update.notes.trim() || "A new alpha build is ready."}</p>
        {error ? <small>{error}</small> : null}
        <span>
          <button type="button" disabled={installing} onClick={onDismiss}>
            Later
          </button>
          <button
            className="is-primary"
            type="button"
            disabled={installing}
            onClick={() => {
              setInstalling(true);
              setError(null);
              void coreBridge.installAvailableUpdate().catch((nextError: unknown) => {
                setInstalling(false);
                setError(
                  nextError instanceof Error
                    ? nextError.message
                    : "The update could not be installed.",
                );
              });
            }}
          >
            {installing ? <LoaderCircle className="spin" size={12} /> : null}
            {installing ? "Installing" : "Update now"}
          </button>
        </span>
      </div>
      <button type="button" aria-label="Dismiss update" onClick={onDismiss}>
        <X size={13} />
      </button>
    </aside>
  );
}

export default function App() {
  const [auth, setAuth] = useState<AuthView | null>(null);
  const [network, setNetwork] = useState<NetworkConfigurationView | null>(
    null,
  );
  const [model, setModel] = useState<BootstrapViewModel>(EMPTY_MODEL);
  const [loading, setLoading] = useState(true);
  const [permissionSetupComplete, setPermissionSetupComplete] = useState(
    () => isFirstRunSetupComplete(),
  );
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState("");
  const [activeChannelId, setActiveChannelId] = useState("");
  const [activeVoiceRoomId, setActiveVoiceRoomId] = useState<string | null>(
    null,
  );
  const [draft, setDraft] = useState("");
  const [composerAttachments, setComposerAttachments] = useState<
    MessageAttachment[]
  >([]);
  const [uploadingAttachments, setUploadingAttachments] = useState(false);
  const [uploadingAttachmentStatus, setUploadingAttachmentStatus] = useState<{
    filename: string;
    index: number;
    total: number;
  } | null>(null);
  const [focusedMessageId, setFocusedMessageId] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [replyingTo, setReplyingTo] = useState<ChatMessage | null>(null);
  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState("");
  const [armedDeleteMessageId, setArmedDeleteMessageId] = useState<
    string | null
  >(null);
  const [messageActionBusy, setMessageActionBusy] = useState<string | null>(
    null,
  );
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [joining, setJoining] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteBusy, setInviteBusy] = useState(false);
  const [createdInvite, setCreatedInvite] = useState<InviteView | null>(null);
  const [rolesOpen, setRolesOpen] = useState(false);
  const [channelsOpen, setChannelsOpen] = useState(false);
  const [moderationOpen, setModerationOpen] = useState(false);
  const [ownershipOpen, setOwnershipOpen] = useState(false);
  const [friendsOpen, setFriendsOpen] = useState(false);
  const [relationshipBusy, setRelationshipBusy] = useState<string | null>(
    null,
  );
  const [searchOpen, setSearchOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [reportingMessage, setReportingMessage] = useState<ChatMessage | null>(
    null,
  );
  const [profileMemberId, setProfileMemberId] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  // Keep active calls out of the reading flow. The compact dock is the
  // default; opening the details is an explicit user action.
  const [voiceCollapsed, setVoiceCollapsed] = useState(true);
  const [messageScrolled, setMessageScrolled] = useState(false);
  const [voiceSession, setVoiceSession] = useState<VoiceSessionSnapshot>(
    EMPTY_VOICE_SESSION,
  );
  const [compact, setCompact] = useState(
    () =>
      typeof window !== "undefined" &&
      window.localStorage.getItem("exocord.compact-conversations") === "1",
  );
  const [refractiveGlassMode, setRefractiveGlassMode] =
    useState<RefractiveGlassMode>(() => readRefractiveGlassMode());
  const [notificationMode, setNotificationMode] =
    useState<NotificationMode>("private");
  const [notificationBusy, setNotificationBusy] = useState(false);
  const [minimizeToTray, setMinimizeToTray] = useState(true);
  const [windowSettingsBusy, setWindowSettingsBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [availableUpdate, setAvailableUpdate] =
    useState<UpdateManifest | null>(null);
  const messageEndRef = useRef<HTMLDivElement>(null);
  const messageListRef = useRef<HTMLElement>(null);
  const attachmentInputRef = useRef<HTMLInputElement>(null);
  const composerInputRef = useRef<HTMLTextAreaElement>(null);
  const acknowledgedReadRef = useRef(new Set<string>());
  const lastTypingAtRef = useRef(0);
  const composerEpochRef = useRef(0);
  const activeChannelIdRef = useRef("");
  const shouldStickToBottomRef = useRef(true);
  const scrolledChannelRef = useRef("");
  const modelRevisionRef = useRef(0);
  const modelReadyRef = useRef(false);
  const modelResyncingRef = useRef(false);
  const modelRef = useRef<BootstrapViewModel>(EMPTY_MODEL);
  const navigationContextRef = useRef<NavigationContext | null>(null);
  const notificationModeRef = useRef<NotificationMode>("private");
  const notificationDeduperRef = useRef(new NotificationDeduper());
  const [windowActive, setWindowActive] = useState(
    () =>
      typeof document !== "undefined" &&
      document.visibilityState === "visible" &&
      document.hasFocus(),
  );
  activeChannelIdRef.current = activeChannelId;

  useEffect(() => {
    let cancelled = false;
    let unsubscribe: (() => void) | undefined;
    let deltaFrame: number | null = null;
    let pendingDeltas: CoreDelta[] = [];
    const cancelPendingDeltas = () => {
      pendingDeltas = [];
      if (deltaFrame !== null) {
        window.cancelAnimationFrame(deltaFrame);
        deltaFrame = null;
      }
    };
    const acceptSnapshot = (nextModel: BootstrapViewModel) => {
      if (cancelled || nextModel.revision < modelRevisionRef.current) return;
      cancelPendingDeltas();
      const context = resolveNavigationContext(
        nextModel,
        navigationContextRef.current,
      );
      navigationContextRef.current = context;
      modelRevisionRef.current = nextModel.revision;
      modelReadyRef.current = true;
      modelRef.current = nextModel;
      setModel(nextModel);
      setActiveWorkspaceId(context.workspaceId);
      setActiveChannelId(context.channelId);
    };
    const resynchronize = () => {
      if (cancelled || modelResyncingRef.current) return;
      cancelPendingDeltas();
      modelResyncingRef.current = true;
      void coreBridge
        .bootstrap()
        .then(acceptSnapshot)
        .catch((error: unknown) => {
          setActionError(
            error instanceof Error
              ? error.message
              : "The app could not resynchronize its local state.",
          );
        })
        .finally(() => {
          modelResyncingRef.current = false;
        });
    };
    const acceptDelta = (delta: CoreDelta) => {
      if (
        cancelled ||
        delta.version !== 1 ||
        !modelReadyRef.current ||
        delta.revision !== modelRevisionRef.current + 1
      ) {
        resynchronize();
        return;
      }
      modelRevisionRef.current = delta.revision;
      const intent = notificationIntent({
        delta,
        mode: notificationModeRef.current,
        model: modelRef.current,
        windowFocused:
          document.visibilityState === "visible" && document.hasFocus(),
      });
      if (
        intent &&
        delta.type === "message_upsert" &&
        notificationDeduperRef.current.accept(delta.message.id)
      ) {
        void showNativeNotification(intent).catch(() => undefined);
      }
      pendingDeltas.push(delta);
      if (deltaFrame === null) {
        deltaFrame = window.requestAnimationFrame(() => {
          const batch = pendingDeltas;
          pendingDeltas = [];
          deltaFrame = null;
          setModel((current) => {
            const next = batch.reduce(
              (next, change) =>
                change.revision > next.revision
                  ? applyCoreDelta(next, change)
                  : next,
              current,
            );
            modelRef.current = next;
            return next;
          });
        });
      }
    };
    void coreBridge
      .subscribe(acceptSnapshot, acceptDelta)
      .then((nextUnsubscribe) => {
      if (cancelled) nextUnsubscribe();
      else unsubscribe = nextUnsubscribe;
      });
    Promise.all([
      coreBridge.bootstrap(),
      coreBridge.authStatus(),
      coreBridge.networkConfiguration(),
      coreBridge.notificationSettings(),
      coreBridge.windowSettings(),
    ])
      .then(
        ([
          snapshot,
          authState,
          networkState,
          notificationSettings,
          windowSettings,
        ]) => {
        acceptSnapshot(snapshot);
        if (!cancelled) {
          setAuth(authState);
          setNetwork(networkState);
          notificationModeRef.current = notificationSettings.mode;
          setNotificationMode(notificationSettings.mode);
          setMinimizeToTray(windowSettings.minimizeToTray);
        }
        },
      )
      .catch((error: unknown) => {
        if (!cancelled) {
          setFatalError(
            error instanceof Error ? error.message : "The local core did not start.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      cancelPendingDeltas();
      unsubscribe?.();
    };
  }, []);

  useEffect(
    () =>
      voiceClient.subscribe((snapshot) => {
        setVoiceSession(snapshot);
        setActiveVoiceRoomId(snapshot.roomId);
      }),
    [],
  );

  useEffect(() => {
    const preload = () => {
      void voiceClient.preload().catch(() => undefined);
    };
    const idle = window.requestIdleCallback(preload, { timeout: 3_000 });
    return () => window.cancelIdleCallback(idle);
  }, []);

  useEffect(() => {
    const updateWindowActive = () =>
      setWindowActive(
        document.visibilityState === "visible" && document.hasFocus(),
      );
    window.addEventListener("focus", updateWindowActive);
    window.addEventListener("blur", updateWindowActive);
    document.addEventListener("visibilitychange", updateWindowActive);
    return () => {
      window.removeEventListener("focus", updateWindowActive);
      window.removeEventListener("blur", updateWindowActive);
      document.removeEventListener("visibilitychange", updateWindowActive);
    };
  }, []);

  useEffect(() => {
    window.localStorage.setItem(
      "exocord.compact-conversations",
      compact ? "1" : "0",
    );
  }, [compact]);

  useEffect(() => {
    try {
      window.localStorage.setItem(
        REFRACTIVE_GLASS_STORAGE_KEY,
        refractiveGlassMode,
      );
    } catch {
      // A locked-down WebView can reject storage; the live React state still
      // applies the setting for this session.
    }
  }, [refractiveGlassMode]);

  useEffect(() => {
    if (!auth?.signedIn) return undefined;
    let active = true;
    const check = () => {
      void coreBridge
        .checkForUpdate()
        .then((status) => {
          if (
            active &&
            status.update &&
            window.sessionStorage.getItem("exocord.dismissed-update") !==
              status.update.version
          ) {
            setAvailableUpdate(status.update);
          }
        })
        .catch(() => undefined);
    };
    const initial = window.setTimeout(check, 3_000);
    const interval = window.setInterval(check, 30 * 60_000);
    return () => {
      active = false;
      window.clearTimeout(initial);
      window.clearInterval(interval);
    };
  }, [auth?.signedIn]);

  useEffect(() => {
    let cancelled = false;
    let unsubscribe: (() => void) | undefined;
    void coreBridge
      .subscribeAuthorizationChanged(() => {
        const current = voiceClient.current();
        if (!current.roomId || current.status === "idle") return;
        void coreBridge
          .createVoiceGrant(current.roomId)
          .then((grant) => voiceClient.reauthorize(grant))
          .catch(() => {
            void voiceClient.leave();
            setActionError(
              "Your access to that voice room changed, so the call was closed.",
            );
          });
      })
      .then((nextUnsubscribe) => {
        if (cancelled) nextUnsubscribe();
        else unsubscribe = nextUnsubscribe;
      });
    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, []);

  useEffect(() => {
    if (focusedMessageId) {
      const target = document.getElementById(`message-${focusedMessageId}`);
      if (target) {
        target.scrollIntoView({ block: "center", behavior: "smooth" });
        const timer = window.setTimeout(() => setFocusedMessageId(null), 2400);
        return () => window.clearTimeout(timer);
      }
    }
    const changedChannel = scrolledChannelRef.current !== activeChannelId;
    if (changedChannel || shouldStickToBottomRef.current) {
      messageEndRef.current?.scrollIntoView({ block: "end" });
      shouldStickToBottomRef.current = true;
      scrolledChannelRef.current = activeChannelId;
    }
    return undefined;
  }, [activeChannelId, focusedMessageId, model.messages]);

  const membersById = useMemo(
    () => new Map(model.members.map((member) => [member.id, member])),
    [model.members],
  );
  const activeWorkspace = model.workspaces.find(
    (workspace) => workspace.id === activeWorkspaceId,
  );
  const activeChannel = activeWorkspace?.channels.find(
    (channel) => channel.id === activeChannelId,
  );
  const activeVoiceRoomBase = model.workspaces
    .flatMap((workspace) => workspace.voiceRooms)
    .find((room) => room.id === activeVoiceRoomId);
  const directVoiceChannel = model.workspaces
    .find((workspace) => workspace.directMessages)
    ?.channels.find((channel) => channel.id === activeVoiceRoomId);
  const activeVoiceRoom =
    activeVoiceRoomBase || directVoiceChannel
      ? {
          ...(activeVoiceRoomBase ?? {
            id: directVoiceChannel?.id ?? activeVoiceRoomId ?? "",
            name: directVoiceChannel?.name ?? "Direct call",
            latencyMs: 0,
            encrypted: true,
            participants: [],
          }),
          participants: voiceSession.participants,
        }
      : undefined;
  const visibleMessages = model.messages.filter(
    (message) => message.channelId === activeChannelId,
  );
  const visibleMessageBlocks = groupMessagesByHour(visibleMessages);
  const currentUser: Member = membersById.get(model.currentUserId) ?? {
    id: model.currentUserId || "local-user",
    name: "Member",
    handle: "member",
    initials: "ME",
    color: "#6e7685",
    presence: "offline",
  };
  const profileMember = profileMemberId
    ? membersById.get(profileMemberId) ??
      (profileMemberId === currentUser.id ? currentUser : null)
    : null;
  const memberForMessage = (message: ChatMessage): Member =>
    membersById.get(message.authorId) ??
    (message.authorId === model.currentUserId
      ? currentUser
      : {
          id: message.authorId,
          name: "Member",
          handle: "member",
          initials: "?",
          color: "#4d5259",
          presence: "offline",
        });
  const showVoicePanel = Boolean(activeVoiceRoom);
  const activeTypers = model.typing
    .filter(
      (typing) =>
        typing.channelId === activeChannelId &&
        typing.userId !== model.currentUserId &&
        new Date(typing.expiresAt).getTime() > Date.now(),
    )
    .map((typing) => membersById.get(typing.userId)?.name)
    .filter((name): name is string => Boolean(name));
  const isWorkspaceOwner =
    activeWorkspace?.ownerId === model.currentUserId;
  const isAdministrator =
    activeWorkspace?.permissionKeys.includes("administrator") || false;
  const canInvite =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("create_invite") ||
    false;
  const canManageRoles =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("manage_roles") ||
    false;
  const canManageChannels =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("manage_channels") ||
    false;
  const canManageMessages =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("manage_messages") ||
    false;
  const canAddReactions =
    activeWorkspace?.directMessages === true ||
    activeWorkspace?.localOnly === true ||
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("add_reactions") ||
    false;
  const canTimeoutMembers =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("moderate_members") ||
    false;
  const canKickMembers =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("kick_members") ||
    false;
  const canBanMembers =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("ban_members") ||
    false;
  const canManageSafety =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("manage_guild") ||
    false;
  const canViewAudit =
    isWorkspaceOwner ||
    isAdministrator ||
    activeWorkspace?.permissionKeys.includes("view_audit_log") ||
    false;
  const canModerate =
    canTimeoutMembers ||
    canKickMembers ||
    canBanMembers ||
    canManageSafety ||
    canViewAudit;

  useEffect(() => {
    setReplyingTo(null);
    setEditingMessageId(null);
    setEditDraft("");
    setArmedDeleteMessageId(null);
  }, [activeChannelId]);

  useEffect(() => {
    if (
      !windowActive ||
      !activeWorkspace?.directMessages ||
      !activeChannel?.unread ||
      visibleMessages.length === 0
    ) {
      return;
    }
    const latest = visibleMessages.at(-1);
    if (!latest) return;
    const key = `${activeChannel.id}:${latest.id}`;
    if (acknowledgedReadRef.current.has(key)) return;
    acknowledgedReadRef.current.add(key);
    void coreBridge
      .acknowledgeReadState(activeChannel.id, latest.id)
      .then(() => {
        setModel((current) => ({
          ...current,
          workspaces: current.workspaces.map((workspace) =>
            workspace.id !== activeWorkspace.id
              ? workspace
              : {
                  ...workspace,
                  channels: workspace.channels.map((channel) =>
                    channel.id === activeChannel.id
                      ? { ...channel, unread: false }
                      : channel,
                  ),
                  unreadCount: workspace.channels.filter(
                    (channel) =>
                      channel.id !== activeChannel.id && channel.unread,
                  ).length,
                },
          ),
        }));
      })
      .catch(() => acknowledgedReadRef.current.delete(key));
  }, [
    activeChannel,
    activeWorkspace,
    visibleMessages,
    windowActive,
  ]);

  const clearComposerAttachments = () => {
    composerEpochRef.current += 1;
    setUploadingAttachments(false);
    setUploadingAttachmentStatus(null);
    composerAttachments.forEach((attachment) => {
      if (attachment.url.startsWith("blob:")) URL.revokeObjectURL(attachment.url);
    });
    setComposerAttachments([]);
  };

  const selectWorkspace = (workspace: Workspace) => {
    clearComposerAttachments();
    setInviteOpen(false);
    const channelId = workspace.directMessages
      ? ""
      : (workspace.channels[0]?.id ?? "");
    navigationContextRef.current = {
      workspaceId: workspace.id,
      channelId,
    };
    setActiveWorkspaceId(workspace.id);
    setActiveChannelId(channelId);
    void coreBridge.setActiveContext({
      workspaceId: workspace.id,
      channelId,
      voiceRoomId: activeVoiceRoomId,
    }).catch((error: unknown) => {
      setActionError(
        error instanceof Error
          ? error.message
          : "The selected server could not be saved.",
      );
    });
  };

  const adoptModel = (
    nextModel: BootstrapViewModel,
    requestedContext?: NavigationContext,
  ) => {
    if (nextModel.revision < modelRevisionRef.current) return;
    const context = resolveNavigationContext(
      nextModel,
      requestedContext ?? navigationContextRef.current,
    );
    navigationContextRef.current = context;
    modelRevisionRef.current = nextModel.revision;
    modelReadyRef.current = true;
    modelRef.current = nextModel;
    setModel(nextModel);
    setActiveWorkspaceId(context.workspaceId);
    setActiveChannelId(context.channelId);
  };

  const changeNotificationMode = async (mode: NotificationMode) => {
    if (notificationBusy || mode === notificationModeRef.current) return;
    setNotificationBusy(true);
    setActionError(null);
    try {
      if (mode !== "off" && !(await requestNotificationAccess())) {
        throw new Error(
          "Windows blocked notifications. Allow Exocord in Windows notification settings, then try again.",
        );
      }
      const saved = await coreBridge.saveNotificationSettings(mode);
      notificationModeRef.current = saved.mode;
      setNotificationMode(saved.mode);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "Notification privacy could not be changed.",
      );
    } finally {
      setNotificationBusy(false);
    }
  };

  const changeMinimizeToTray = async (value: boolean) => {
    if (windowSettingsBusy) return;
    setWindowSettingsBusy(true);
    setActionError(null);
    try {
      const saved = await coreBridge.saveWindowSettings(value);
      setMinimizeToTray(saved.minimizeToTray);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "The tray setting could not be saved.",
      );
    } finally {
      setWindowSettingsBusy(false);
    }
  };

  const relationshipAction = async (
    userId: string,
    action: () => Promise<BootstrapViewModel>,
  ) => {
    setRelationshipBusy(userId);
    try {
      adoptModel(await action());
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "That friend action could not be completed.",
      );
      throw error;
    } finally {
      setRelationshipBusy(null);
    }
  };

  const openFriendConversation = async (userId: string) => {
    try {
      await relationshipAction(userId, async () => {
        const nextModel = await coreBridge.openDirectMessage(userId);
        setFriendsOpen(false);
        // Opening a friend is an explicit navigation action. The returned
        // snapshot carries the newly-created DM channel, so let it replace a
        // previous DM-home target instead of preserving that home target.
        adoptModel(nextModel, preferredNavigationContext(nextModel));
        return nextModel;
      });
    } catch {
      // relationshipAction reports the failure in the shared action banner.
    }
  };

  const selectChannel = (channelId: string) => {
    if (channelId !== activeChannelId) clearComposerAttachments();
    navigationContextRef.current = {
      workspaceId: activeWorkspaceId,
      channelId,
    };
    setActiveChannelId(channelId);
    if (activeWorkspaceId) {
      void coreBridge.setActiveContext({
        workspaceId: activeWorkspaceId,
        channelId,
        voiceRoomId: activeVoiceRoomId,
      }).catch((error: unknown) => {
        setActionError(
          error instanceof Error
            ? error.message
            : "The selected conversation could not be saved.",
        );
      });
    }
  };

  const selectVoice = async (voiceRoomId: string) => {
    if (
      voiceSession.roomId === voiceRoomId &&
      (voiceSession.status === "connected" ||
        voiceSession.status === "connecting" ||
        voiceSession.status === "reconnecting")
    ) {
      setVoiceCollapsed(false);
      return;
    }
    setActionError(null);
    try {
      const grant = await coreBridge.createVoiceGrant(voiceRoomId);
      await voiceClient.join(grant, { startMuted: false });
      if (activeWorkspaceId && activeChannelId) {
        await coreBridge.setActiveContext({
          workspaceId: activeWorkspaceId,
          channelId: activeChannelId,
          voiceRoomId,
        });
      }
    } catch (error: unknown) {
      setActionError(
        error instanceof Error ? error.message : "Voice could not connect.",
      );
    }
  };

  const createWorkspace = async (name: string) => {
    setCreating(true);
    try {
      const workspace = await coreBridge.createWorkspace({ name });
      setModel((current) => ({
        ...current,
        workspaces: current.workspaces.some(
          (existing) => existing.id === workspace.id,
        )
          ? current.workspaces.map((existing) =>
              existing.id === workspace.id ? workspace : existing,
            )
          : [...current.workspaces, workspace],
      }));
      selectWorkspace(workspace);
      setCreateOpen(false);
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "The server could not be created while offline.",
      );
    } finally {
      setCreating(false);
    }
  };

  const joinWorkspace = async (code: string) => {
    setJoining(true);
    try {
      const workspace = await coreBridge.acceptServerInvite(code);
      setModel((current) => ({
        ...current,
        workspaces: current.workspaces.some(
          (existing) => existing.id === workspace.id,
        )
          ? current.workspaces.map((existing) =>
              existing.id === workspace.id ? workspace : existing,
            )
          : [...current.workspaces, workspace],
      }));
      selectWorkspace(workspace);
      setCreateOpen(false);
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "The invite could not be accepted.",
      );
    } finally {
      setJoining(false);
    }
  };

  const generateInvite = async () => {
    if (!activeWorkspace) return;
    setInviteBusy(true);
    try {
      setCreatedInvite(
        await coreBridge.createWorkspaceInvite(activeWorkspace.id),
      );
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "A secure invite could not be created.",
      );
    } finally {
      setInviteBusy(false);
    }
  };

  const uploadFiles = async (files: FileList | null) => {
    if (!files || files.length === 0 || !activeChannelId) return;
    if (activeWorkspace?.localOnly) {
      setActionError("Attachments require a connected server channel.");
      return;
    }
    const available = 10 - composerAttachments.length;
    if (available <= 0) {
      setActionError("A message can contain at most 10 attachments.");
      return;
    }
    const selected = [...files].slice(0, available);
    const uploadChannelId = activeChannelId;
    const uploadEpoch = composerEpochRef.current;
    if (files.length > available) {
      setActionError(`Only the first ${available} files were added.`);
    } else {
      setActionError(null);
    }
    setUploadingAttachments(true);
    setUploadingAttachmentStatus({
      filename: selected[0]?.name ?? "attachment",
      index: 1,
      total: selected.length,
    });
    try {
      for (const [index, file] of selected.entries()) {
        if (uploadEpoch !== composerEpochRef.current) break;
        setUploadingAttachmentStatus({
          filename: file.name,
          index: index + 1,
          total: selected.length,
        });
        try {
          const attachment = await coreBridge.uploadAttachment(
            uploadChannelId,
            file,
          );
          if (
            uploadEpoch === composerEpochRef.current &&
            uploadChannelId === activeChannelIdRef.current
          ) {
            setComposerAttachments((current) => [...current, attachment]);
          }
        } catch (uploadError: unknown) {
          if (uploadEpoch === composerEpochRef.current) {
            setActionError(
              uploadError instanceof Error
                ? `${file.name}: ${uploadError.message}`
                : `${file.name} could not be uploaded.`,
            );
          }
        }
      }
    } finally {
      if (uploadEpoch === composerEpochRef.current) {
        setUploadingAttachments(false);
        setUploadingAttachmentStatus(null);
      }
      if (attachmentInputRef.current) attachmentInputRef.current.value = "";
    }
  };

  const cancelAttachmentUpload = () => {
    if (!uploadingAttachments) return;
    // Uploads are intentionally epoch-scoped: an in-flight native transfer may
    // finish, but it cannot mutate a composer after the user cancels the row.
    composerEpochRef.current += 1;
    setUploadingAttachments(false);
    setUploadingAttachmentStatus(null);
    if (attachmentInputRef.current) attachmentInputRef.current.value = "";
  };

  const retryMessageDelivery = async (message: ChatMessage) => {
    if (message.deliveryState !== "failed") return;
    setMessageActionBusy(`retry:${message.id}`);
    try {
      await coreBridge.retryOutbox();
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "This message could not be retried.",
      );
    } finally {
      setMessageActionBusy(null);
    }
  };

  const upsertConversationMessage = (
    message: ChatMessage,
    options?: MessageReconcileOptions & {
      /** Snapshot taken before a reaction command started (null means none). */
      reactionBaseline?: ChatMessage["reactions"] | null;
    },
  ) => {
    setModel((current) => {
      const existing = current.messages.find(
        (candidate) =>
          (candidate.clientKey ?? candidate.id) ===
          (message.clientKey ?? message.id),
      );
      const reactionChangedDuringCommand =
        options?.reactionBaseline !== undefined &&
        !reactionsEqual(
          existing?.reactions,
          options.reactionBaseline ?? undefined,
        );
      const next = {
        ...current,
        messages: reconcileMessageResult(current.messages, message, {
          preserveReactions:
            options?.preserveReactions || reactionChangedDuringCommand,
        }),
      };
      modelRef.current = next;
      return next;
    });
  };

  const saveMessageEdit = async () => {
    if (!editingMessageId || !activeChannelId) return;
    const content = editDraft.trim();
    if (!content) {
      setActionError("A message cannot be empty.");
      return;
    }
    setMessageActionBusy(`edit:${editingMessageId}`);
    try {
      const message = await coreBridge.editMessage({
        channelId: activeChannelId,
        messageId: editingMessageId,
        content,
      });
      upsertConversationMessage(message);
      setEditingMessageId(null);
      setEditDraft("");
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error ? error.message : "The edit could not be saved.",
      );
    } finally {
      setMessageActionBusy(null);
    }
  };

  const removeMessage = async (message: ChatMessage) => {
    if (armedDeleteMessageId !== message.id) {
      setArmedDeleteMessageId(message.id);
      return;
    }
    setMessageActionBusy(`delete:${message.id}`);
    try {
      await coreBridge.deleteMessage(message.channelId, message.id);
      setModel((current) => ({
        ...current,
        messages: current.messages.filter(
          (candidate) =>
            candidate.id !== message.id ||
            candidate.channelId !== message.channelId,
        ),
      }));
      if (replyingTo?.id === message.id) setReplyingTo(null);
      setArmedDeleteMessageId(null);
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "The message could not be deleted.",
      );
    } finally {
      setMessageActionBusy(null);
    }
  };

  const updateReaction = async (
    message: ChatMessage,
    emoji: string,
    added: boolean,
  ) => {
    const reactionBaseline = message.reactions
      ? message.reactions.map((reaction) => ({ ...reaction }))
      : null;
    setMessageActionBusy(`reaction:${message.id}:${emoji}`);
    try {
      upsertConversationMessage(
        await coreBridge.updateMessageReaction({
          channelId: message.channelId,
          messageId: message.id,
          emoji,
          added,
        }),
        { reactionBaseline },
      );
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error
          ? error.message
          : "The reaction could not be updated.",
      );
    } finally {
      setMessageActionBusy(null);
    }
  };

  const sendMessage = async () => {
    const content = draft.trim();
    if (
      (!content && composerAttachments.length === 0) ||
      !activeChannelId ||
      sending ||
      uploadingAttachments
    ) {
      return;
    }
    const attachments = composerAttachments;
    const reply = replyingTo;
    setSending(true);
    setDraft("");
    setComposerAttachments([]);
    setReplyingTo(null);
    try {
      const message = await coreBridge.sendMessage({
        channelId: activeChannelId,
        content,
        replyToId: reply?.id,
        attachments,
      });
      setModel((current) => {
        const key = message.clientKey ?? message.id;
        const hadMessage = current.messages.some(
          (existing) => (existing.clientKey ?? existing.id) === key,
        );
        const next = {
          ...current,
          messages: reconcileMessageResult(current.messages, message),
          pendingOutbox:
            !hadMessage && message.deliveryState === "pending"
              ? current.pendingOutbox + 1
              : current.pendingOutbox,
        };
        modelRef.current = next;
        return next;
      });
    } catch (error: unknown) {
      setDraft(content);
      setComposerAttachments(attachments);
      setReplyingTo(reply);
      setActionError(
        error instanceof Error
          ? error.message
          : "The message could not be queued.",
      );
    } finally {
      setSending(false);
    }
  };

  const logout = async () => {
    if (signingOut) return;
    setSigningOut(true);
    try {
      await voiceClient.leave();
      const nextAuth = await coreBridge.logout();
      setAuth(nextAuth);
      setModel(EMPTY_MODEL);
      modelRevisionRef.current = 0;
      modelReadyRef.current = false;
      navigationContextRef.current = null;
      setActiveWorkspaceId("");
      setActiveChannelId("");
      clearComposerAttachments();
      setSettingsOpen(false);
      setActionError(null);
    } catch (error: unknown) {
      setActionError(
        error instanceof Error ? error.message : "Sign out could not finish.",
      );
    } finally {
      setSigningOut(false);
    }
  };

  const scheduleAccountDeletion = async (
    confirmation: string,
  ): Promise<AccountDeletionView> => {
    await voiceClient.leave();
    const deletion = await coreBridge.scheduleAccountDeletion(confirmation);
    setAuth((current) => ({
      signedIn: false,
      email: null,
      deletionScheduledFor: deletion.scheduledFor,
      passwordAvailable: current?.passwordAvailable ?? true,
      appleAvailable: current?.appleAvailable ?? true,
      developmentCodePreview: current?.developmentCodePreview ?? false,
    }));
    setModel(EMPTY_MODEL);
    modelRevisionRef.current = 0;
    modelReadyRef.current = false;
    navigationContextRef.current = null;
    setActiveWorkspaceId("");
    setActiveChannelId("");
    clearComposerAttachments();
    setSettingsOpen(false);
    setActionError(null);
    return deletion;
  };

  const cancelAccountDeletion = async () => {
    await coreBridge.cancelAccountDeletion();
    setAuth((current) =>
      current ? { ...current, deletionScheduledFor: null } : current,
    );
    try {
      adoptModel(await coreBridge.bootstrap());
    } catch {
      // The native core emits a fresh snapshot after cancellation. A temporary
      // local read failure must not misrepresent a successfully restored account.
    }
  };

  const onComposerKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendMessage();
    }
  };

  if (loading) {
    return (
      <main className="loading-screen">
        <span className="loading-mark">
          <Sparkles size={18} />
        </span>
        <span>Starting the local core</span>
      </main>
    );
  }

  if (fatalError) {
    return (
      <main className="error-screen">
        <Sparkles size={20} />
        <h1>Exocord could not start</h1>
        <p>{fatalError}</p>
        <button type="button" onClick={() => window.location.reload()}>
          Try again
        </button>
      </main>
    );
  }

  if (model.cacheRecovery) {
    return <CacheRecoveryScreen recovery={model.cacheRecovery} />;
  }

  if (auth && !auth.signedIn && network) {
    return (
      <AuthScreen
        auth={auth}
        network={network}
        onAuthenticated={setAuth}
      />
    );
  }

  if (auth?.signedIn && auth.deletionScheduledFor) {
    return (
      <DeletionPendingScreen
        auth={auth}
        onCancel={cancelAccountDeletion}
        onExport={() => coreBridge.exportAccountData()}
        onLogout={logout}
      />
    );
  }

  if (auth?.signedIn && !permissionSetupComplete) {
    const setupUser =
      model.members.find((member) => member.id === model.currentUserId) ?? {
        id: model.currentUserId || "you",
        name: "You",
        handle: "you",
        initials: "YO",
        color: "#3ecf8e",
        presence: "online" as const,
      };
    return (
      <FirstRunSetup
        currentUser={setupUser}
        onProfileSaved={(member) => {
          setModel((current) => ({
            ...current,
            members: current.members.map((candidate) =>
              candidate.id === member.id ? member : candidate,
            ),
          }));
        }}
        onComplete={() => {
          markFirstRunSetupComplete();
          setPermissionSetupComplete(true);
          void coreBridge.notificationSettings().then((settings) => {
            notificationModeRef.current = settings.mode;
            setNotificationMode(settings.mode);
          });
        }}
      />
    );
  }

  return (
    <div
      className={`app-shell ${compact ? "is-compact" : ""} ${
        messageScrolled ? "is-message-scrolled" : ""
      }`}
    >
      <RefractiveBackdrop mode={refractiveGlassMode} />
      <TopNavigation
        workspaces={model.workspaces}
        workspace={activeWorkspace}
        currentUser={currentUser}
        members={model.members}
        currentUserId={model.currentUserId}
        activeWorkspaceId={activeWorkspaceId}
        activeChannelId={activeChannelId}
        activeVoiceRoomId={activeVoiceRoomId}
        voiceSession={voiceSession}
        onSelectWorkspace={selectWorkspace}
        onSelectChannel={selectChannel}
        onSelectVoice={selectVoice}
        onCreateWorkspace={() => setCreateOpen(true)}
        onOpenServerMenu={() => {
          if (!activeWorkspace) return;
          setCreatedInvite(null);
          setInviteOpen(true);
        }}
        onOpenFriends={() => setFriendsOpen(true)}
        onOpenSearch={() => {
          if (!activeWorkspace) return;
          if (activeWorkspace.localOnly && !activeWorkspace.directMessages) {
            setActionError("Server search is available in connected servers.");
            return;
          }
          setSearchOpen(true);
        }}
        onOpenSettings={() => setSettingsOpen(true)}
        onLogout={logout}
        onOpenMemberProfile={(member) => setProfileMemberId(member.id)}
      />
      <ConnectionBanner
        state={model.connectionState}
        pending={model.pendingOutbox}
        onRetry={() => {
          void coreBridge.retryOutbox().catch((error: unknown) => {
            setActionError(
              error instanceof Error
                ? error.message
                : "Queued messages could not be retried.",
            );
          });
        }}
      />

      <div
        className={`app-content ${
          showVoicePanel ? "has-voice-dock" : "without-voice"
        } ${showVoicePanel && voiceCollapsed ? "voice-collapsed" : ""}`}
      >
        <main
          className={`conversation ${
            activeWorkspace?.directMessages && !activeChannel
              ? "conversation-home"
              : ""
          }`}
        >
          <section
            ref={messageListRef}
            className="message-list"
            aria-live="polite"
            onScroll={(event) => {
              const target = event.currentTarget;
              setMessageScrolled(target.scrollTop > 8);
              shouldStickToBottomRef.current =
                target.scrollHeight - target.scrollTop - target.clientHeight <
                96;
            }}
          >
            {activeWorkspace?.directMessages && !activeChannel ? (
              <DirectMessageHome
                workspace={activeWorkspace}
                relationships={model.relationships}
                membersById={membersById}
                onSelectChannel={selectChannel}
                onOpenFriend={openFriendConversation}
                onOpenFriends={() => setFriendsOpen(true)}
                onOpenSearch={() => setSearchOpen(true)}
              />
            ) : (
              <>
                {visibleMessages.length === 0 ? (
                  <div className="channel-intro">
                    <span>
                      {activeWorkspace?.directMessages ? (
                        <AtSign size={18} />
                      ) : (
                        <Hash size={18} />
                      )}
                    </span>
                    <div>
                      <h1>{activeChannel?.name ?? "Select a channel"}</h1>
                      <p>
                        This is the beginning of{" "}
                        <strong>
                          {activeWorkspace?.directMessages ? "@" : "#"}
                          {activeChannel?.name ?? "this channel"}
                        </strong>
                        .
                      </p>
                    </div>
                  </div>
                ) : null}
                {visibleMessageBlocks.map((block) => (
                  <section className="message-block" key={block.key}>
                    <div className="message-hour" aria-label={block.label}>
                      <span />
                      <time>{block.label}</time>
                      <span />
                    </div>
                    {block.messages.map((message) => {
                      const referenced = message.replyToId
                        ? model.messages.find(
                            (candidate) =>
                              candidate.id === message.replyToId &&
                              candidate.channelId === message.channelId,
                          )
                        : undefined;
                      const referencedMember = referenced
                        ? membersById.get(referenced.authorId)
                        : undefined;
                      const replyPreview = message.replyToId
                        ? {
                            author: referencedMember
                              ? referencedMember.name
                              : "Earlier message",
                            text:
                              referenced?.content ||
                              "Message unavailable on this device",
                          }
                        : undefined;
                      const own = message.authorId === model.currentUserId;
                      const busy =
                        messageActionBusy?.split(":").includes(message.id) ??
                        false;
                      return (
                        <MessageItem
                          key={message.clientKey ?? message.id}
                          message={message}
                          member={memberForMessage(message)}
                          replyPreview={replyPreview}
                          focused={message.id === focusedMessageId}
                          canReport={!own}
                          canEdit={own}
                          canDelete={
                            own ||
                            (!activeWorkspace?.directMessages &&
                              !activeWorkspace?.localOnly &&
                              canManageMessages)
                          }
                          canReact={canAddReactions}
                          editing={editingMessageId === message.id}
                          editValue={
                            editingMessageId === message.id ? editDraft : ""
                          }
                          deleteArmed={armedDeleteMessageId === message.id}
                          busy={busy}
                          onReport={() => setReportingMessage(message)}
                          onReply={() => {
                            setReplyingTo(message);
                            setArmedDeleteMessageId(null);
                            window.requestAnimationFrame(() =>
                              composerInputRef.current?.focus(),
                            );
                          }}
                          onEdit={() => {
                            setEditingMessageId(message.id);
                            setEditDraft(message.content);
                            setArmedDeleteMessageId(null);
                          }}
                          onEditValue={setEditDraft}
                          onSaveEdit={() => void saveMessageEdit()}
                          onCancelEdit={() => {
                            setEditingMessageId(null);
                            setEditDraft("");
                          }}
                          onDelete={() => void removeMessage(message)}
                          onRetry={() => void retryMessageDelivery(message)}
                          onReact={(emoji, added) =>
                            void updateReaction(message, emoji, added)
                          }
                          onOpenMemberProfile={(member) =>
                            setProfileMemberId(member.id)
                          }
                        />
                      );
                    })}
                  </section>
                ))}
                {visibleMessages.length === 0 ? (
                  <div className="empty-conversation">
                    <span>Quiet so far.</span>
                    <p>Start the conversation without fighting the interface.</p>
                  </div>
                ) : null}
              </>
            )}
            <div ref={messageEndRef} />
          </section>

          {activeTypers.length > 0 ? (
            <div className="typing-line">
              <span className="typing-dots" aria-hidden="true">
                <i />
                <i />
                <i />
              </span>
              {activeTypers.length === 1
                ? `${activeTypers[0]} is typing`
                : `${activeTypers.slice(0, 2).join(" and ")} are typing`}
            </div>
          ) : null}

          {replyingTo ? (
            <div className="composer-reply" aria-live="polite">
              <Reply size={13} />
              <span>
                Replying to{" "}
                <strong>
                  {membersById.get(replyingTo.authorId)?.name ??
                    "earlier message"}
                </strong>
              </span>
              <p>{replyingTo.content}</p>
              <button
                type="button"
                aria-label="Cancel reply"
                onClick={() => setReplyingTo(null)}
              >
                <X size={13} />
              </button>
            </div>
          ) : null}

          {composerAttachments.length > 0 || uploadingAttachments ? (
            <div className="composer-attachment-tray" aria-live="polite">
              {composerAttachments.map((attachment) => (
                <div className="composer-attachment" key={attachment.id}>
                  <span className="composer-attachment-icon">
                    {attachment.contentType.startsWith("image/") ? (
                      <Paperclip size={14} />
                    ) : attachment.contentType.startsWith("video/") ? (
                      <Film size={14} />
                    ) : attachment.contentType.startsWith("audio/") ? (
                      <Music size={14} />
                    ) : (
                      <FileText size={14} />
                    )}
                  </span>
                  <span>
                    <strong>{attachment.filename}</strong>
                    <small>{formatBytes(attachment.size)}</small>
                  </span>
                  <button
                    type="button"
                    aria-label={`Remove ${attachment.filename}`}
                    onClick={() => {
                      if (attachment.url.startsWith("blob:")) {
                        URL.revokeObjectURL(attachment.url);
                      }
                      setComposerAttachments((current) =>
                        current.filter(
                          (candidate) => candidate.id !== attachment.id,
                        ),
                      );
                    }}
                  >
                    <X size={13} />
                  </button>
                </div>
              ))}
              {uploadingAttachments ? (
                <div className="composer-uploading" role="status">
                  <span className="composer-uploading-progress" aria-hidden="true">
                    <span
                      style={{
                        width: `${Math.max(
                          12,
                          ((uploadingAttachmentStatus?.index ?? 1) /
                            Math.max(1, uploadingAttachmentStatus?.total ?? 1)) *
                            100,
                        )}%`,
                      }}
                    />
                  </span>
                  <LoaderCircle className="spin" size={13} />
                  <span className="composer-uploading-copy">
                    <strong>
                      {uploadingAttachmentStatus?.filename ?? "Uploading"}
                    </strong>
                    <small>
                      {uploadingAttachmentStatus
                        ? `${uploadingAttachmentStatus.index} of ${uploadingAttachmentStatus.total}`
                        : "Preparing"}
                    </small>
                  </span>
                  <button
                    type="button"
                    aria-label="Cancel uploads"
                    onClick={cancelAttachmentUpload}
                  >
                    <X size={12} />
                  </button>
                </div>
              ) : null}
            </div>
          ) : null}

          <GlassSurface
            as="form"
            variant="regular"
            className="composer"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              void sendMessage();
            }}
          >
            <input
              ref={attachmentInputRef}
              className="visually-hidden"
              type="file"
              multiple
              tabIndex={-1}
              onChange={(event) => void uploadFiles(event.target.files)}
            />
            <button
              className="composer-attach"
              type="button"
              aria-label="Attach files"
              title="Attach files · 25 MiB each"
              disabled={
                !activeChannel ||
                uploadingAttachments ||
                composerAttachments.length >= 10
              }
              onClick={() => attachmentInputRef.current?.click()}
            >
              <Paperclip size={16} />
            </button>
            <textarea
              ref={composerInputRef}
              rows={1}
              value={draft}
              aria-label={`Message ${activeWorkspace?.directMessages ? "@" : "#"}${activeChannel?.name ?? "channel"}`}
              disabled={!activeChannel}
              placeholder={
                composerAttachments.length > 0
                  ? "Add a message"
                  : activeChannel
                    ? `Message ${activeWorkspace?.directMessages ? "@" : "#"}${activeChannel.name}`
                    : "Choose a conversation"
              }
              onChange={(event) => {
                const value = event.target.value.slice(0, 4000);
                setDraft(value);
                const now = Date.now();
                if (
                  value.trim() &&
                  activeChannel &&
                  !activeWorkspace?.localOnly &&
                  model.connectionState === "connected" &&
                  now - lastTypingAtRef.current >= 4_000
                ) {
                  lastTypingAtRef.current = now;
                  void coreBridge.startTyping(activeChannel.id).catch(
                    () => undefined,
                  );
                }
              }}
              onKeyDown={onComposerKeyDown}
            />
            <button
              className="send-button"
              type="submit"
              aria-label="Send message"
              disabled={
                !activeChannel ||
                (!draft.trim() && composerAttachments.length === 0) ||
                sending ||
                uploadingAttachments
              }
            >
              <span>Send</span>
            </button>
          </GlassSurface>
        </main>

        {!showVoicePanel ? null : <VoicePanel
          room={activeVoiceRoom}
          membersById={membersById}
          collapsed={voiceCollapsed}
          session={voiceSession}
          onCollapse={() => setVoiceCollapsed((value) => !value)}
          onToggleMute={() => {
            void voiceClient
              .setMuted(!voiceSession.muted)
              .catch((error: unknown) =>
                setActionError(
                  error instanceof Error
                    ? error.message
                    : "The microphone could not be changed.",
                ),
              );
          }}
          onToggleDeafen={() => {
            void voiceClient
              .setDeafened(!voiceSession.deafened)
              .catch((error: unknown) =>
                setActionError(
                  error instanceof Error
                    ? error.message
                    : "Audio output could not be changed.",
                ),
              );
          }}
          onToggleShare={() => {
            void voiceClient
              .setScreenSharing(!voiceSession.sharing)
              .catch((error: unknown) =>
                setActionError(
                  error instanceof Error
                    ? error.message
                    : "Screen sharing could not be changed.",
                ),
              );
          }}
          onResumeAudio={() => {
            void voiceClient.resumeAudio().catch((error: unknown) => {
              setActionError(
                error instanceof Error
                  ? error.message
                  : "Audio could not resume.",
              );
            });
          }}
          onLeave={() => {
            void voiceClient.leave().catch((error: unknown) => {
              setActionError(
                error instanceof Error
                  ? error.message
                  : "Voice could not disconnect cleanly.",
              );
            });
            if (activeWorkspaceId) {
              void coreBridge.setActiveContext({
                workspaceId: activeWorkspaceId,
                channelId: activeChannelId,
                voiceRoomId: null,
              }).catch((error: unknown) => {
                setActionError(
                  error instanceof Error
                    ? error.message
                    : "The cleared voice state could not be saved.",
                );
              });
            }
          }}
          onOpenMemberProfile={(member) => setProfileMemberId(member.id)}
        />}
      </div>

      <CreateServerDialog
        open={createOpen}
        busy={creating || joining}
        onClose={() => setCreateOpen(false)}
        onCreate={createWorkspace}
        onJoin={joinWorkspace}
      />
      <InvitePeopleDialog
        open={inviteOpen}
        workspace={activeWorkspace}
        invite={createdInvite}
        busy={inviteBusy}
        canInvite={
          canInvite && activeWorkspace?.localOnly !== true
        }
        canManageRoles={
          canManageRoles && activeWorkspace?.localOnly !== true
        }
        canManageChannels={
          canManageChannels && activeWorkspace?.localOnly !== true
        }
        canModerate={
          canModerate && activeWorkspace?.localOnly !== true
        }
        canManageOwnership={
          isWorkspaceOwner && activeWorkspace?.localOnly !== true
        }
        onGenerate={generateInvite}
        onManageChannels={() => {
          setInviteOpen(false);
          setChannelsOpen(true);
        }}
        onManageRoles={() => {
          setInviteOpen(false);
          setRolesOpen(true);
        }}
        onModerate={() => {
          setInviteOpen(false);
          setModerationOpen(true);
        }}
        onManageOwnership={() => {
          setInviteOpen(false);
          setOwnershipOpen(true);
        }}
        onClose={() => setInviteOpen(false)}
      />
      <ServerOwnershipDialog
        open={ownershipOpen}
        workspace={activeWorkspace}
        currentUserId={model.currentUserId}
        onTransfer={async (memberId) => {
          if (!activeWorkspace) return;
          adoptModel(
            await coreBridge.transferServerOwnership(
              activeWorkspace.id,
              memberId,
            ),
          );
          setActionError(null);
        }}
        onDelete={async (confirmation) => {
          if (!activeWorkspace) return;
          await voiceClient.leave();
          adoptModel(
            await coreBridge.deleteServer(activeWorkspace.id, confirmation),
          );
          setActionError(null);
        }}
        onClose={() => setOwnershipOpen(false)}
      />
      <FriendsDialog
        open={friendsOpen}
        relationships={model.relationships}
        busyUserId={relationshipBusy}
        onRequest={async (handle) => {
          adoptModel(await coreBridge.requestFriend(handle));
        }}
        onAccept={(userId) =>
          relationshipAction(userId, () => coreBridge.acceptFriend(userId))
        }
        onRemove={(userId) =>
          relationshipAction(userId, () =>
            coreBridge.removeRelationship(userId),
          )
        }
        onBlock={(userId) =>
          relationshipAction(userId, () => coreBridge.blockUser(userId))
        }
        onMessage={openFriendConversation}
        onClose={() => setFriendsOpen(false)}
      />
      <ChannelManagerDialog
        open={channelsOpen}
        workspace={activeWorkspace}
        onClose={() => setChannelsOpen(false)}
      />
      <RoleManagerDialog
        open={rolesOpen}
        workspace={activeWorkspace}
        onClose={() => setRolesOpen(false)}
      />
      <ModerationDialog
        open={moderationOpen}
        workspace={activeWorkspace}
        currentUserId={model.currentUserId}
        canTimeout={canTimeoutMembers}
        canKick={canKickMembers}
        canBan={canBanMembers}
        canManageSafety={canManageSafety}
        canViewAudit={canViewAudit}
        onClose={() => setModerationOpen(false)}
      />
      <SearchDialog
        open={searchOpen}
        workspace={activeWorkspace}
        membersById={membersById}
        onOpenHit={(hit) => {
          setActionError(null);
          void coreBridge
            .openSearchHit({
              workspaceId: hit.workspaceId,
              channelId: hit.channelId,
              messageId: hit.message.id,
              localOnly: hit.localOnly,
            })
            .then(() => {
              navigationContextRef.current = {
                workspaceId: hit.workspaceId,
                channelId: hit.channelId,
              };
              setActiveWorkspaceId(hit.workspaceId);
              setActiveChannelId(hit.channelId);
              setFocusedMessageId(hit.message.id);
              setSearchOpen(false);
            })
            .catch((error: unknown) => {
              setActionError(
                error instanceof Error
                  ? error.message
                  : "That search result could not be opened.",
              );
            });
        }}
        onClose={() => setSearchOpen(false)}
      />
      <SettingsDialog
        open={settingsOpen}
        currentUser={currentUser}
        compact={compact}
        minimizeToTray={minimizeToTray}
        windowSettingsBusy={windowSettingsBusy}
        notificationMode={notificationMode}
        notificationBusy={notificationBusy}
        refractiveGlassMode={refractiveGlassMode}
        cacheProtection={model.cacheProtection}
        email={auth?.email ?? null}
        passwordAvailable={auth?.passwordAvailable ?? false}
        appleAvailable={auth?.appleAvailable ?? false}
        signingOut={signingOut}
        onCompactChange={setCompact}
        onUpdateProfile={async (input) => {
          adoptModel(await coreBridge.updateProfile(input));
        }}
        onMinimizeToTrayChange={changeMinimizeToTray}
        onNotificationModeChange={changeNotificationMode}
        onRefractiveGlassModeChange={setRefractiveGlassMode}
        onClose={() => setSettingsOpen(false)}
        onLogout={() => void logout()}
        onChangePassword={(currentPassword, newPassword) =>
          coreBridge.changePassword(currentPassword, newPassword)
        }
        onRegenerateRecoveryCodes={(currentPassword) =>
          coreBridge.regenerateRecoveryCodes(currentPassword)
        }
        onExportData={() => coreBridge.exportAccountData()}
        onDeleteAccount={scheduleAccountDeletion}
        onResolveOwnership={(workspaceId) => {
          const workspace = model.workspaces.find(
            (candidate) => candidate.id === workspaceId,
          );
          if (!workspace) {
            setActionError("That server is no longer available.");
            return;
          }
          selectWorkspace(workspace);
          setSettingsOpen(false);
          setOwnershipOpen(true);
        }}
      />
      <MemberProfileDialog
        member={profileMember}
        isCurrentUser={profileMember?.id === currentUser.id}
        onClose={() => setProfileMemberId(null)}
        onMessage={(memberId) => {
          setProfileMemberId(null);
          void openFriendConversation(memberId);
        }}
        onOpenSettings={() => {
          setProfileMemberId(null);
          setSettingsOpen(true);
        }}
      />
      <ReportDialog
        message={reportingMessage}
        member={
          reportingMessage
            ? membersById.get(reportingMessage.authorId)
            : undefined
        }
        onClose={() => setReportingMessage(null)}
      />
      {availableUpdate ? (
        <UpdatePrompt
          update={availableUpdate}
          onDismiss={() => {
            window.sessionStorage.setItem(
              "exocord.dismissed-update",
              availableUpdate.version,
            );
            setAvailableUpdate(null);
          }}
        />
      ) : null}
      {actionError ? (
        <div className="action-toast" role="alert">
          <CloudOff size={14} />
          <span>{actionError}</span>
          <button
            type="button"
            aria-label="Dismiss error"
            onClick={() => setActionError(null)}
          >
            <X size={13} />
          </button>
        </div>
      ) : null}
    </div>
  );
}
