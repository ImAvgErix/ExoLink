import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  CACHE_RESET_CONFIRMATION,
  cacheResetConfirmed,
} from "./cacheRecovery";
import {
  ACCOUNT_DELETE_CONFIRMATION,
  accountDeleteConfirmed,
} from "./accountDeletion";
import { serverNameConfirmed } from "./serverOwnership";
import { mockBootstrap } from "./mockData";
import type {
  BootstrapViewModel,
  ActiveContextInput,
  CreateWorkspaceInput,
  SendMessageInput,
  Workspace,
  ChatMessage,
  AuthView,
  EmailCodeChallenge,
  InvitePreview,
  InviteView,
  RoleManagerView,
  RoleMutationInput,
  ServerRole,
  ChannelManagerView,
  ChannelMutationInput,
  ChannelOverwrite,
  ChannelOverwriteInput,
  ManagedChannel,
  ModerationManagerView,
  MemberModerationInput,
  AutomodRule,
  AutomodRuleMutationInput,
  MessageAttachment,
  AttachmentUpload,
  SearchInput,
  SearchView,
  VoiceJoinGrant,
  RelationshipView,
  DeviceSecurityView,
  ReportMessageInput,
  ReportReceipt,
  CoreDelta,
  AccountDeletionView,
  AccountDeletionStatusView,
  ServerOwnershipView,
  NetworkConfigurationView,
  NetworkProbeView,
  OperatorInfoView,
  NotificationMode,
  NotificationSettingsView,
  WindowSettingsView,
  PasswordAuthenticationView,
  AccountAuthMethodsView,
  ProfileUpdateInput,
  UpdateStatusView,
} from "./models";

const mockRoleManagers = new Map<string, RoleManagerView>();
const mockChannelManagers = new Map<string, ChannelManagerView>();
const mockOverwrites = new Map<string, ChannelOverwrite[]>();
const mockModerationManagers = new Map<string, ModerationManagerView>();
const mockRevokedDevices = new Set<string>();
let mockNotificationMode: NotificationMode = "private";
let mockAppleLinked = false;

function mockDeletionScheduledFor(): string | null {
  if (typeof window === "undefined") return null;
  const value = new URLSearchParams(window.location.search).get(
    "deletion-pending",
  );
  if (!value) return null;
  return value === "1" ? "2026-08-28T18:30:00Z" : value;
}

function isTauri(): boolean {
  return (
    typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
  );
}

function cloneBootstrap(): BootstrapViewModel {
  const snapshot = structuredClone(mockBootstrap);
  if (typeof window === "undefined") return snapshot;
  const query = new URLSearchParams(window.location.search);
  const connection = query.get("connection");
  if (
    connection === "offline" ||
    connection === "connecting" ||
    connection === "connected" ||
    connection === "catching_up"
  ) {
    snapshot.connectionState = connection;
  }
  const pending = Number.parseInt(query.get("pending") ?? "0", 10);
  if (Number.isFinite(pending) && pending > 0) {
    snapshot.pendingOutbox = pending;
  }
  const recoveryReason = query.get("cache-recovery");
  if (recoveryReason) {
    const reason =
      recoveryReason === "vault_unavailable" ||
      recoveryReason === "cache_key_unavailable" ||
      recoveryReason === "encryption_unavailable" ||
      recoveryReason === "cache_corrupt" ||
      recoveryReason === "migration_failed" ||
      recoveryReason === "storage_failed"
        ? recoveryReason
        : "cache_locked";
    const titles = {
      vault_unavailable: "The secure key vault is unavailable",
      cache_key_unavailable: "The local cache key cannot be read",
      encryption_unavailable: "This build cannot open encrypted caches",
      cache_locked: "The local cache is locked",
      cache_corrupt: "The local cache did not pass verification",
      migration_failed: "The local cache upgrade was interrupted",
      storage_failed: "The local cache cannot be opened safely",
    } as const;
    snapshot.cacheRecovery = {
      reason,
      title: titles[reason],
      message:
        "Exo Link stopped before synchronization and left every local cache file untouched.",
      detail: "Preview: authenticated SQLCipher page verification failed.",
      cachePath: "%APPDATA%\\app.exocord.desktop\\client.sqlite3",
      canReset:
        reason !== "vault_unavailable" &&
        reason !== "encryption_unavailable" &&
        reason !== "storage_failed",
    };
    snapshot.cacheProtection = {
      encrypted: false,
      cipher: "Locked",
      keyStorage: "Operating-system credential vault",
    };
  }
  return snapshot;
}

export const coreBridge = {
  async networkConfiguration(): Promise<NetworkConfigurationView> {
    if (!isTauri()) {
      const query = new URLSearchParams(window.location.search);
      const apiUrl =
        query.get("api-url") ??
        window.localStorage.getItem("exocord.preview-api-url") ??
        "http://127.0.0.1:4100";
      const requestedSource = query.get("network-source");
      const source: NetworkConfigurationView["source"] =
        requestedSource === "environment" ||
        requestedSource === "saved" ||
        requestedSource === "build" ||
        requestedSource === "local_default" ||
        requestedSource === "preview"
          ? requestedSource
          : query.has("api-url")
            ? "saved"
            : "local_default";
      return {
        apiUrl,
        source,
        secure: apiUrl.startsWith("https://"),
        managed: false,
        warning: query.get("network-warning"),
      };
    }
    return invoke<NetworkConfigurationView>("network_configuration");
  },

  async notificationSettings(): Promise<NotificationSettingsView> {
    if (!isTauri()) return { mode: mockNotificationMode };
    return invoke<NotificationSettingsView>("notification_settings");
  },

  async saveNotificationSettings(
    mode: NotificationMode,
  ): Promise<NotificationSettingsView> {
    if (!isTauri()) {
      mockNotificationMode = mode;
      return { mode };
    }
    return invoke<NotificationSettingsView>("save_notification_settings", {
      input: { mode },
    });
  },

  async windowSettings(): Promise<WindowSettingsView> {
    if (!isTauri()) return { minimizeToTray: true };
    return invoke<WindowSettingsView>("window_settings");
  },

  async saveWindowSettings(
    minimizeToTray: boolean,
  ): Promise<WindowSettingsView> {
    if (!isTauri()) return { minimizeToTray };
    return invoke<WindowSettingsView>("save_window_settings", {
      input: { minimizeToTray },
    });
  },

  async probeNetworkConfiguration(apiUrl: string): Promise<NetworkProbeView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      let parsed: URL;
      try {
        parsed = new URL(apiUrl);
      } catch {
        throw new Error(
          "Enter a complete server URL such as https://alpha.example.com.",
        );
      }
      const loopback =
        parsed.hostname === "localhost" ||
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "::1";
      if (parsed.protocol !== "https:" && !loopback) {
        throw new Error("Remote alpha servers must use HTTPS.");
      }
      return {
        ready: true,
        storage: loopback ? "memory" : "postgres",
        attachments: loopback ? "local" : "r2",
        password: true,
        email: true,
        apple: true,
        developmentCodePreview: loopback,
        conversationActions: "replies_edits_deletes_unicode_reactions",
        nativeVoice: loopback
          ? "not_configured"
          : "livekit_sframe_mls_exporter",
        operator: {
          name: loopback ? "Local Exo Link development" : "Exo Link Test Alpha",
          privacyUrl: loopback
            ? null
            : "https://alpha.example.com/privacy",
          termsUrl: loopback ? null : "https://alpha.example.com/terms",
          supportEmail: loopback ? null : "help@alpha.example.com",
          abuseEmail: loopback ? null : "abuse@alpha.example.com",
        },
      };
    }
    return invoke<NetworkProbeView>("probe_network_configuration", {
      input: { apiUrl },
    });
  },

  async operatorInfo(): Promise<OperatorInfoView> {
    if (!isTauri()) {
      const loopback = (
        await this.networkConfiguration()
      ).apiUrl.startsWith("http://");
      return {
        name: loopback ? "Local Exo Link development" : "Exo Link Test Alpha",
        privacyUrl: loopback ? null : "https://alpha.example.com/privacy",
        termsUrl: loopback ? null : "https://alpha.example.com/terms",
        supportEmail: loopback ? null : "help@alpha.example.com",
        abuseEmail: loopback ? null : "abuse@alpha.example.com",
      };
    }
    return invoke<OperatorInfoView>("operator_info");
  },

  async openOperatorResource(
    resource: "privacy" | "terms" | "support" | "abuse",
  ): Promise<void> {
    if (!isTauri()) {
      const operator = await this.operatorInfo();
      const target =
        resource === "privacy"
          ? operator.privacyUrl
          : resource === "terms"
            ? operator.termsUrl
            : resource === "support"
              ? operator.supportEmail && `mailto:${operator.supportEmail}`
              : operator.abuseEmail && `mailto:${operator.abuseEmail}`;
      if (!target) throw new Error("That operator resource is unavailable.");
      window.open(target, "_blank", "noopener,noreferrer");
      return;
    }
    await invoke("open_operator_resource", { input: { resource } });
  },

  async saveNetworkConfiguration(apiUrl: string): Promise<void> {
    if (!isTauri()) {
      await this.probeNetworkConfiguration(apiUrl);
      window.localStorage.setItem("exocord.preview-api-url", apiUrl);
      return;
    }
    await invoke("save_network_configuration", { input: { apiUrl } });
  },

  async checkForUpdate(): Promise<UpdateStatusView> {
    if (!isTauri()) {
      return { currentVersion: "0.1.13", update: null };
    }
    return invoke<UpdateStatusView>("check_for_update");
  },

  async installAvailableUpdate(): Promise<void> {
    if (!isTauri()) {
      throw new Error("Update installation is available in the Windows app.");
    }
    await invoke("install_available_update");
  },

  async authStatus(): Promise<AuthView> {
    if (!isTauri()) {
      const signedOut = new URLSearchParams(window.location.search).has("signed-out");
      return {
        signedIn: !signedOut,
        email: signedOut ? null : "erix@example.com",
        deletionScheduledFor: signedOut ? null : mockDeletionScheduledFor(),
        passwordAvailable: true,
        appleAvailable: false,
        developmentCodePreview: true,
      };
    }
    return invoke<AuthView>("auth_status");
  },

  async deviceSecurityStatus(): Promise<DeviceSecurityView> {
    if (!isTauri()) {
      return {
        ready: true,
        deviceId: "01953d73-79b0-7e80-8a24-a50bbf31e4ad",
        fingerprint: "ARCTIC FABLE LUMEN RIVER QUARTZ NOVA",
        cipherSuite: "MLS 1.0 · X25519 · AES-128-GCM · Ed25519",
        noKeyBackup: false,
        historyNotice:
          "Sign in after reinstalling to restore account data and client-encrypted direct-message history. Exo Link never receives the recovery key or archived plaintext.",
        devices: [
          {
            deviceId: "01953d73-79b0-7e80-8a24-a50bbf31e4ad",
            name: "Exo Link Desktop",
            fingerprint: "ARCTIC FABLE LUMEN RIVER QUARTZ NOVA",
            current: true,
            revoked: false,
          },
          {
            deviceId: "01953d73-79b0-7e80-8a24-a50bbf31e4ae",
            name: "Windows · Surface",
            fingerprint: "EMBER CEDAR ORBIT GLASS SILVER TIDE",
            current: false,
            revoked: mockRevokedDevices.has(
              "01953d73-79b0-7e80-8a24-a50bbf31e4ae",
            ),
          },
        ],
        error: null,
      };
    }
    return invoke<DeviceSecurityView>("device_security_status");
  },

  async revokeDevice(deviceId: string): Promise<void> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 450));
      mockRevokedDevices.add(deviceId);
      return;
    }
    await invoke("revoke_device", { input: { deviceId } });
  },

  async reportMessage(input: ReportMessageInput): Promise<ReportReceipt> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 250));
      return {
        id: crypto.randomUUID(),
        status: "open",
        createdAt: new Date().toISOString(),
      };
    }
    return invoke<ReportReceipt>("report_message", { input });
  },

  async requestLoginCode(email: string): Promise<EmailCodeChallenge> {
    if (!isTauri()) {
      return {
        challengeId: crypto.randomUUID(),
        expiresInSeconds: 600,
        developmentCode: "482913",
      };
    }
    return invoke<EmailCodeChallenge>("request_login_code", {
      input: { email },
    });
  },

  async registerWithPassword(
    email: string,
    username: string,
    password: string,
  ): Promise<PasswordAuthenticationView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      if (password.length < 10) {
        throw new Error("The password must be between 10 and 128 characters");
      }
      return {
        auth: {
          signedIn: true,
          email: email.trim().toLowerCase(),
          deletionScheduledFor: mockDeletionScheduledFor(),
          passwordAvailable: true,
          appleAvailable: true,
          developmentCodePreview: true,
        },
        recoveryCodes: Array.from(
          { length: 8 },
          (_, index) => `exo_rc_preview_code_${index + 1}`,
        ),
      };
    }
    return invoke<PasswordAuthenticationView>("register_with_password", {
      input: { email, username, password },
    });
  },

  async loginWithPassword(
    email: string,
    password: string,
  ): Promise<PasswordAuthenticationView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      if (!email.includes("@") || !password) {
        throw new Error("The email or password is incorrect");
      }
      return {
        auth: {
          signedIn: true,
          email: email.trim().toLowerCase(),
          deletionScheduledFor: mockDeletionScheduledFor(),
          passwordAvailable: true,
          appleAvailable: true,
          developmentCodePreview: true,
        },
        recoveryCodes: [],
      };
    }
    return invoke<PasswordAuthenticationView>("login_with_password", {
      input: { email, password },
    });
  },

  async activateAuthenticatedAccount(): Promise<void> {
    if (!isTauri()) return;
    await invoke("activate_authenticated_account");
  },

  async changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      if (!currentPassword) {
        throw new Error("The email or password is incorrect");
      }
      if (newPassword.length < 10 || newPassword.length > 128) {
        throw new Error("The password must be between 10 and 128 characters");
      }
      if (currentPassword === newPassword) {
        throw new Error(
          "The new password must be different from the current password",
        );
      }
      return;
    }
    await invoke("change_password", {
      input: { currentPassword, newPassword },
    });
  },

  async recoverPassword(
    email: string,
    recoveryCode: string,
    newPassword: string,
  ): Promise<PasswordAuthenticationView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      if (!email.includes("@") || !recoveryCode.startsWith("exo_rc_")) {
        throw new Error(
          "The recovery code is invalid or has already been used",
        );
      }
      if (newPassword.length < 10 || newPassword.length > 128) {
        throw new Error("The password must be between 10 and 128 characters");
      }
      return {
        auth: {
          signedIn: true,
          email: email.trim().toLowerCase(),
          deletionScheduledFor: mockDeletionScheduledFor(),
          passwordAvailable: true,
          appleAvailable: true,
          developmentCodePreview: true,
        },
        recoveryCodes: Array.from(
          { length: 8 },
          (_, index) => `exo_rc_rotated_preview_${index + 1}`,
        ),
      };
    }
    return invoke<PasswordAuthenticationView>("recover_password", {
      input: { email, recoveryCode, newPassword },
    });
  },

  async regenerateRecoveryCodes(currentPassword: string): Promise<string[]> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      if (!currentPassword) {
        throw new Error("The current password is incorrect");
      }
      return Array.from(
        { length: 8 },
        (_, index) => `exo_rc_replaced_preview_${index + 1}`,
      );
    }
    return invoke<string[]>("regenerate_recovery_codes", {
      input: { currentPassword },
    });
  },

  async accountAuthMethods(): Promise<AccountAuthMethodsView> {
    if (!isTauri()) {
      return {
        passwordSet: true,
        appleLinked: mockAppleLinked,
        appleEmail: mockAppleLinked
          ? "erix@privaterelay.appleid.com"
          : null,
      };
    }
    return invoke<AccountAuthMethodsView>("account_auth_methods");
  },

  async linkApple(currentPassword: string): Promise<AccountAuthMethodsView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      if (!currentPassword) {
        throw new Error("The current password is incorrect");
      }
      mockAppleLinked = true;
      return {
        passwordSet: true,
        appleLinked: true,
        appleEmail: "erix@privaterelay.appleid.com",
      };
    }
    return invoke<AccountAuthMethodsView>("link_apple", {
      input: { currentPassword },
    });
  },

  async unlinkApple(currentPassword: string): Promise<AccountAuthMethodsView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      if (!currentPassword) {
        throw new Error("The current password is incorrect");
      }
      mockAppleLinked = false;
      return {
        passwordSet: true,
        appleLinked: false,
        appleEmail: null,
      };
    }
    return invoke<AccountAuthMethodsView>("unlink_apple", {
      input: { currentPassword },
    });
  },

  async verifyLoginCode(challengeId: string, code: string): Promise<AuthView> {
    if (!isTauri()) {
      if (code !== "482913") throw new Error("That code is not valid.");
      return {
        signedIn: true,
        email: "erix@example.com",
        deletionScheduledFor: mockDeletionScheduledFor(),
        passwordAvailable: true,
        appleAvailable: true,
        developmentCodePreview: true,
      };
    }
    return invoke<AuthView>("verify_login_code", {
      input: { challengeId, code },
    });
  },

  async loginWithApple(): Promise<AuthView> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      return {
        signedIn: true,
        email: "erix@privaterelay.appleid.com",
        deletionScheduledFor: mockDeletionScheduledFor(),
        passwordAvailable: true,
        appleAvailable: true,
        developmentCodePreview: true,
      };
    }
    return invoke<AuthView>("login_with_apple");
  },

  async logout(): Promise<AuthView> {
    if (!isTauri()) {
      return {
        signedIn: false,
        email: null,
        deletionScheduledFor: null,
        passwordAvailable: true,
        appleAvailable: true,
        developmentCodePreview: true,
      };
    }
    return invoke<AuthView>("logout_session");
  },

  async accountDeletionStatus(): Promise<AccountDeletionStatusView> {
    if (!isTauri()) {
      const scheduledFor = mockDeletionScheduledFor();
      const showOwnershipBlocker =
        typeof window !== "undefined" &&
        new URLSearchParams(window.location.search).get(
          "ownership-blockers",
        ) === "1";
      const ownedServer = mockBootstrap.workspaces.find(
        (workspace) =>
          !workspace.directMessages &&
          workspace.ownerId === mockBootstrap.currentUserId,
      );
      return {
        deletion: scheduledFor
          ? {
            requestedAt: "2026-07-29T18:30:00Z",
            scheduledFor,
          }
          : null,
        ownedServers:
          showOwnershipBlocker && ownedServer
            ? [
                {
                  id: ownedServer.id,
                  name: ownedServer.name,
                  memberCount: Math.max(2, mockBootstrap.members.length),
                },
              ]
            : [],
      };
    }
    return invoke<AccountDeletionStatusView>("account_deletion_status");
  },

  async exportAccountData(): Promise<string> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      return "ExoLink-data-export-preview.json";
    }
    return invoke<string>("export_account_data");
  },

  async scheduleAccountDeletion(
    confirmation: string,
  ): Promise<AccountDeletionView> {
    if (!accountDeleteConfirmed(confirmation)) {
      throw new Error(
        `Type ${ACCOUNT_DELETE_CONFIRMATION} exactly to schedule deletion.`,
      );
    }
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 650));
      const requestedAt = new Date();
      return {
        requestedAt: requestedAt.toISOString(),
        scheduledFor: new Date(
          requestedAt.getTime() + 30 * 24 * 60 * 60 * 1000,
        ).toISOString(),
      };
    }
    return invoke<AccountDeletionView>("schedule_account_deletion", {
      input: { confirmation },
    });
  },

  async cancelAccountDeletion(): Promise<void> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      return;
    }
    await invoke("cancel_account_deletion");
  },

  async bootstrap(): Promise<BootstrapViewModel> {
    if (!isTauri()) return cloneBootstrap();
    return invoke<BootstrapViewModel>("bootstrap_view_model");
  },

  async updateProfile(
    input: ProfileUpdateInput,
  ): Promise<BootstrapViewModel> {
    if (!isTauri()) {
      const snapshot = cloneBootstrap();
      const member = snapshot.members.find(
        (candidate) => candidate.id === snapshot.currentUserId,
      );
      if (member) {
        member.handle = input.handle;
        member.name = input.displayName;
        member.initials = input.displayName
          .split(/\s+/)
          .slice(0, 2)
          .map((part) => part[0]?.toUpperCase() ?? "")
          .join("");
        if (input.removeAvatar) delete member.avatarUrl;
        else if (input.avatarBase64 && input.avatarContentType) {
          member.avatarUrl = `data:${input.avatarContentType};base64,${input.avatarBase64}`;
        }
      }
      return snapshot;
    }
    return invoke<BootstrapViewModel>("update_profile", { input });
  },

  async retryLocalCache(): Promise<void> {
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      return;
    }
    await invoke("retry_local_cache");
  },

  async openLocalCacheFolder(): Promise<void> {
    if (!isTauri()) return;
    await invoke("open_local_cache_folder");
  },

  async resetLocalCache(confirmation: string): Promise<void> {
    if (!cacheResetConfirmed(confirmation)) {
      throw new Error(
        `Type ${CACHE_RESET_CONFIRMATION} exactly before resetting the local cache.`,
      );
    }
    if (!isTauri()) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      return;
    }
    await invoke("reset_local_cache", { input: { confirmation } });
  },

  async createWorkspace(input: CreateWorkspaceInput): Promise<Workspace> {
    if (isTauri()) {
      return invoke<Workspace>("create_workspace", { input });
    }
    const slug = input.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "");
    return {
      id: `${slug}-${crypto.randomUUID().slice(0, 6)}`,
      ownerId: mockBootstrap.currentUserId,
      name: input.name,
      initials: input.name.slice(0, 2).toUpperCase(),
      accent: "#3ecf8e",
      permissionKeys: ["administrator", "create_invite", "manage_roles"],
      directMessages: false,
      channels: [
        {
          id: `${slug}-general-${crypto.randomUUID().slice(0, 4)}`,
          name: "general",
          kind: "text",
        },
      ],
      voiceRooms: [],
    };
  },

  async createWorkspaceInvite(workspaceId: string): Promise<InviteView> {
    if (!isTauri()) {
      return {
        code: `demo_${workspaceId}_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`,
        maxUses: 50,
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      };
    }
    return invoke<InviteView>("create_workspace_invite", {
      input: { workspaceId },
    });
  },

  async previewServerInvite(value: string): Promise<InvitePreview> {
    const code = inviteCode(value);
    if (!isTauri()) {
      return {
        code,
        workspaceId: "preview-guild",
        name: "Night Shift",
        accent: "#3ecf8e",
        memberCount: 12,
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      };
    }
    return invoke<InvitePreview>("preview_server_invite", {
      input: { code },
    });
  },

  async acceptServerInvite(value: string): Promise<Workspace> {
    const code = inviteCode(value);
    if (!isTauri()) {
      return {
        id: `joined-${code}`,
        ownerId: "invite-owner",
        name: "Night Shift",
        initials: "NI",
        accent: "#3ecf8e",
        permissionKeys: [
          "view_member_list",
          "view_channel",
          "send_messages",
          "read_message_history",
          "connect",
          "speak",
          "use_vad",
        ],
        directMessages: false,
        channels: [
          {
            id: `joined-${code}-general`,
            name: "general",
            kind: "text",
          },
        ],
        voiceRooms: [],
      };
    }
    return invoke<Workspace>("accept_server_invite", {
      input: { code },
    });
  },

  async loadServerOwnership(
    workspaceId: string,
  ): Promise<ServerOwnershipView> {
    if (!isTauri()) {
      const workspace = mockBootstrap.workspaces.find(
        (candidate) => candidate.id === workspaceId,
      );
      if (!workspace) throw new Error("That server no longer exists.");
      return {
        workspaceId,
        ownerId: workspace.ownerId,
        name: workspace.name,
        members: mockBootstrap.members
          .filter((member) => member.id !== workspace.ownerId)
          .map((member) => ({
            id: member.id,
            name: member.name,
            handle: member.handle,
            initials: member.initials,
            color: member.color,
          })),
      };
    }
    return invoke<ServerOwnershipView>("load_server_ownership", {
      input: { workspaceId },
    });
  },

  async transferServerOwnership(
    workspaceId: string,
    memberId: string,
  ): Promise<BootstrapViewModel> {
    if (!isTauri()) {
      const workspace = mockBootstrap.workspaces.find(
        (candidate) => candidate.id === workspaceId,
      );
      if (!workspace) throw new Error("That server no longer exists.");
      if (!mockBootstrap.members.some((member) => member.id === memberId)) {
        throw new Error("That member is no longer available.");
      }
      workspace.ownerId = memberId;
      return cloneBootstrap();
    }
    return invoke<BootstrapViewModel>("transfer_server_ownership", {
      input: { workspaceId, memberId },
    });
  },

  async deleteServer(
    workspaceId: string,
    confirmation: string,
  ): Promise<BootstrapViewModel> {
    if (!isTauri()) {
      const workspace = mockBootstrap.workspaces.find(
        (candidate) => candidate.id === workspaceId,
      );
      if (!workspace) throw new Error("That server no longer exists.");
      if (!serverNameConfirmed(confirmation, workspace.name)) {
        throw new Error("Type the server name exactly to delete it.");
      }
      mockBootstrap.workspaces = mockBootstrap.workspaces.filter(
        (candidate) => candidate.id !== workspaceId,
      );
      if (mockBootstrap.activeWorkspaceId === workspaceId) {
        const next = mockBootstrap.workspaces[0];
        mockBootstrap.activeWorkspaceId = next?.id ?? "";
        mockBootstrap.activeChannelId = next?.channels[0]?.id ?? "";
        mockBootstrap.activeVoiceRoomId = null;
      }
      return cloneBootstrap();
    }
    return invoke<BootstrapViewModel>("delete_server", {
      input: { workspaceId, confirmation },
    });
  },

  async loadServerRoles(workspaceId: string): Promise<RoleManagerView> {
    if (!isTauri()) {
      const existing =
        mockRoleManagers.get(workspaceId) ?? createMockRoleManager(workspaceId);
      mockRoleManagers.set(workspaceId, existing);
      return structuredClone(existing);
    }
    return invoke<RoleManagerView>("load_server_roles", {
      input: { workspaceId },
    });
  },

  async createServerRole(input: RoleMutationInput): Promise<ServerRole> {
    if (!isTauri()) {
      const manager =
        mockRoleManagers.get(input.workspaceId) ??
        createMockRoleManager(input.workspaceId);
      const role: ServerRole = {
        id: `role-${crypto.randomUUID()}`,
        name: input.name,
        color: input.color,
        position:
          Math.max(0, ...manager.roles.map((candidate) => candidate.position)) + 1,
        permissionKeys: [...input.permissionKeys],
        everyone: false,
        managed: false,
      };
      manager.roles.unshift(role);
      mockRoleManagers.set(input.workspaceId, manager);
      return structuredClone(role);
    }
    return invoke<ServerRole>("create_server_role", { input });
  },

  async updateServerRole(input: RoleMutationInput): Promise<ServerRole> {
    if (!input.roleId) throw new Error("Choose a role to update.");
    if (!isTauri()) {
      const manager =
        mockRoleManagers.get(input.workspaceId) ??
        createMockRoleManager(input.workspaceId);
      const role = manager.roles.find(
        (candidate) => candidate.id === input.roleId,
      );
      if (!role) throw new Error("That role no longer exists.");
      role.name = role.everyone ? "@everyone" : input.name;
      role.color = input.color;
      role.permissionKeys = [...input.permissionKeys];
      mockRoleManagers.set(input.workspaceId, manager);
      return structuredClone(role);
    }
    return invoke<ServerRole>("update_server_role", { input });
  },

  async deleteServerRole(workspaceId: string, roleId: string): Promise<void> {
    if (!isTauri()) {
      const manager = mockRoleManagers.get(workspaceId);
      if (!manager) return;
      const role = manager.roles.find((candidate) => candidate.id === roleId);
      if (role?.everyone) throw new Error("@everyone cannot be deleted.");
      manager.roles = manager.roles.filter(
        (candidate) => candidate.id !== roleId,
      );
      manager.members.forEach((member) => {
        member.roleIds = member.roleIds.filter(
          (candidate) => candidate !== roleId,
        );
      });
      return;
    }
    await invoke("delete_server_role", {
      input: { workspaceId, roleId },
    });
  },

  async setServerMemberRole(
    workspaceId: string,
    memberId: string,
    roleId: string,
    assigned: boolean,
  ): Promise<void> {
    if (!isTauri()) {
      const manager =
        mockRoleManagers.get(workspaceId) ??
        createMockRoleManager(workspaceId);
      const member = manager.members.find(
        (candidate) => candidate.id === memberId,
      );
      if (!member) throw new Error("That member is no longer available.");
      member.roleIds = assigned
        ? [...new Set([...member.roleIds, roleId])]
        : member.roleIds.filter((candidate) => candidate !== roleId);
      mockRoleManagers.set(workspaceId, manager);
      return;
    }
    await invoke("set_server_member_role", {
      input: { workspaceId, memberId, roleId, assigned },
    });
  },

  async loadServerChannels(workspaceId: string): Promise<ChannelManagerView> {
    if (!isTauri()) {
      const existing =
        mockChannelManagers.get(workspaceId) ??
        createMockChannelManager(workspaceId);
      mockChannelManagers.set(workspaceId, existing);
      return structuredClone(existing);
    }
    return invoke<ChannelManagerView>("load_server_channels", {
      input: { workspaceId },
    });
  },

  async createServerChannel(
    input: ChannelMutationInput,
  ): Promise<ManagedChannel> {
    if (!isTauri()) {
      const manager =
        mockChannelManagers.get(input.workspaceId) ??
        createMockChannelManager(input.workspaceId);
      const channel: ManagedChannel = {
        id: `channel-${crypto.randomUUID()}`,
        name: input.name,
        kind: input.kind,
        encrypted: input.encrypted,
      };
      manager.channels.push(channel);
      mockChannelManagers.set(input.workspaceId, manager);
      return structuredClone(channel);
    }
    return invoke<ManagedChannel>("create_server_channel", { input });
  },

  async updateServerChannel(
    input: ChannelMutationInput,
  ): Promise<ManagedChannel> {
    if (!input.channelId) throw new Error("Choose a channel to update.");
    if (!isTauri()) {
      const manager =
        mockChannelManagers.get(input.workspaceId) ??
        createMockChannelManager(input.workspaceId);
      const channel = manager.channels.find(
        (candidate) => candidate.id === input.channelId,
      );
      if (!channel) throw new Error("That channel no longer exists.");
      channel.name = input.name;
      mockChannelManagers.set(input.workspaceId, manager);
      return structuredClone(channel);
    }
    return invoke<ManagedChannel>("update_server_channel", { input });
  },

  async deleteServerChannel(channelId: string): Promise<void> {
    if (!isTauri()) {
      for (const manager of mockChannelManagers.values()) {
        const channel = manager.channels.find(
          (candidate) => candidate.id === channelId,
        );
        if (!channel) continue;
        if (
          channel.kind === "text" &&
          manager.channels.filter((candidate) => candidate.kind === "text")
            .length <= 1
        ) {
          throw new Error("A server must keep at least one text channel.");
        }
        manager.channels = manager.channels.filter(
          (candidate) => candidate.id !== channelId,
        );
        mockOverwrites.delete(channelId);
        return;
      }
      return;
    }
    await invoke("delete_server_channel", { input: { channelId } });
  },

  async loadChannelOverwrites(
    channelId: string,
  ): Promise<ChannelOverwrite[]> {
    if (!isTauri()) {
      return structuredClone(mockOverwrites.get(channelId) ?? []);
    }
    return invoke<ChannelOverwrite[]>("load_channel_overwrites", {
      input: { channelId },
    });
  },

  async setServerChannelOverwrite(
    input: ChannelOverwriteInput,
  ): Promise<ChannelOverwrite> {
    if (!isTauri()) {
      const overwrite: ChannelOverwrite = {
        channelId: input.channelId,
        targetKind: input.targetKind,
        targetId: input.targetId,
        allowKeys: [...input.allowKeys],
        denyKeys: [...input.denyKeys],
      };
      const values = mockOverwrites.get(input.channelId) ?? [];
      const key = `${input.targetKind}:${input.targetId}`;
      mockOverwrites.set(input.channelId, [
        ...values.filter(
          (candidate) =>
            `${candidate.targetKind}:${candidate.targetId}` !== key,
        ),
        overwrite,
      ]);
      return structuredClone(overwrite);
    }
    return invoke<ChannelOverwrite>("set_server_channel_overwrite", {
      input,
    });
  },

  async deleteServerChannelOverwrite(
    channelId: string,
    targetKind: "role" | "member",
    targetId: string,
  ): Promise<void> {
    if (!isTauri()) {
      mockOverwrites.set(
        channelId,
        (mockOverwrites.get(channelId) ?? []).filter(
          (candidate) =>
            candidate.targetKind !== targetKind ||
            candidate.targetId !== targetId,
        ),
      );
      return;
    }
    await invoke("delete_server_channel_overwrite", {
      input: { channelId, targetKind, targetId },
    });
  },

  async loadServerModeration(
    workspaceId: string,
  ): Promise<ModerationManagerView> {
    if (!isTauri()) {
      const existing =
        mockModerationManagers.get(workspaceId) ??
        createMockModerationManager(workspaceId);
      mockModerationManagers.set(workspaceId, existing);
      return structuredClone(existing);
    }
    return invoke<ModerationManagerView>("load_server_moderation", {
      input: { workspaceId },
    });
  },

  async createAutomodRule(
    input: AutomodRuleMutationInput,
  ): Promise<AutomodRule> {
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(input.workspaceId) ??
        createMockModerationManager(input.workspaceId);
      const rule = mockAutomodRule(input);
      manager.rules.unshift(rule);
      manager.audit.unshift({
        id: crypto.randomUUID(),
        actorId: mockBootstrap.currentUserId,
        targetId: rule.id,
        actionType: 50,
        actionLabel: "Safety rule created",
        detail: rule.name,
        reason: null,
        createdAt: new Date().toISOString(),
      });
      mockModerationManagers.set(input.workspaceId, manager);
      return structuredClone(rule);
    }
    return invoke<AutomodRule>("create_automod_rule", { input });
  },

  async updateAutomodRule(
    input: AutomodRuleMutationInput,
  ): Promise<AutomodRule> {
    if (!input.ruleId) throw new Error("Choose a safety rule first.");
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(input.workspaceId) ??
        createMockModerationManager(input.workspaceId);
      const index = manager.rules.findIndex(
        (candidate) => candidate.id === input.ruleId,
      );
      if (index < 0) throw new Error("That safety rule is no longer available.");
      const rule = mockAutomodRule(input, input.ruleId);
      manager.rules[index] = rule;
      manager.audit.unshift({
        id: crypto.randomUUID(),
        actorId: mockBootstrap.currentUserId,
        targetId: rule.id,
        actionType: 51,
        actionLabel: "Safety rule updated",
        detail: rule.name,
        reason: null,
        createdAt: new Date().toISOString(),
      });
      mockModerationManagers.set(input.workspaceId, manager);
      return structuredClone(rule);
    }
    return invoke<AutomodRule>("update_automod_rule", { input });
  },

  async deleteAutomodRule(workspaceId: string, ruleId: string): Promise<void> {
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(workspaceId) ??
        createMockModerationManager(workspaceId);
      manager.rules = manager.rules.filter((candidate) => candidate.id !== ruleId);
      manager.audit.unshift({
        id: crypto.randomUUID(),
        actorId: mockBootstrap.currentUserId,
        targetId: ruleId,
        actionType: 52,
        actionLabel: "Safety rule deleted",
        detail: null,
        reason: null,
        createdAt: new Date().toISOString(),
      });
      mockModerationManagers.set(workspaceId, manager);
      return;
    }
    await invoke("delete_automod_rule", {
      input: { workspaceId, ruleId },
    });
  },

  async timeoutServerMember(input: MemberModerationInput): Promise<void> {
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(input.workspaceId) ??
        createMockModerationManager(input.workspaceId);
      const member = manager.members.find(
        (candidate) => candidate.id === input.memberId,
      );
      if (!member) throw new Error("That member is no longer available.");
      member.timeoutUntil = input.durationSeconds
        ? new Date(Date.now() + input.durationSeconds * 1000).toISOString()
        : null;
      mockModerationManagers.set(input.workspaceId, manager);
      return;
    }
    await invoke("timeout_server_member", { input });
  },

  async kickServerMember(input: MemberModerationInput): Promise<void> {
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(input.workspaceId) ??
        createMockModerationManager(input.workspaceId);
      manager.members = manager.members.filter(
        (candidate) => candidate.id !== input.memberId,
      );
      mockModerationManagers.set(input.workspaceId, manager);
      return;
    }
    await invoke("kick_server_member", { input });
  },

  async banServerMember(input: MemberModerationInput): Promise<void> {
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(input.workspaceId) ??
        createMockModerationManager(input.workspaceId);
      const member = manager.members.find(
        (candidate) => candidate.id === input.memberId,
      );
      if (!member) throw new Error("That member is no longer available.");
      manager.members = manager.members.filter(
        (candidate) => candidate.id !== input.memberId,
      );
      manager.bans.unshift({
        id: member.id,
        name: member.name,
        handle: member.handle,
        initials: member.initials,
        color: member.color,
        reason: input.reason ?? null,
        expiresAt: input.durationSeconds
          ? new Date(Date.now() + input.durationSeconds * 1000).toISOString()
          : null,
        createdAt: new Date().toISOString(),
      });
      mockModerationManagers.set(input.workspaceId, manager);
      return;
    }
    await invoke("ban_server_member", { input });
  },

  async unbanServerMember(input: MemberModerationInput): Promise<void> {
    if (!isTauri()) {
      const manager =
        mockModerationManagers.get(input.workspaceId) ??
        createMockModerationManager(input.workspaceId);
      manager.bans = manager.bans.filter(
        (candidate) => candidate.id !== input.memberId,
      );
      mockModerationManagers.set(input.workspaceId, manager);
      return;
    }
    await invoke("unban_server_member", { input });
  },

  async sendMessage(input: SendMessageInput): Promise<ChatMessage> {
    if (isTauri()) {
      return invoke<ChatMessage>("send_message", { input });
    }
    const message: ChatMessage = {
      id: crypto.randomUUID(),
      clientKey: crypto.randomUUID(),
      channelId: input.channelId,
      authorId: mockBootstrap.currentUserId,
      replyToId: input.replyToId,
      content: input.content,
      attachments: input.attachments,
      sentAt: new Intl.DateTimeFormat(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      }).format(new Date()),
      deliveryState: "sent",
      delivered: true,
    };
    mockBootstrap.messages.push(message);
    return structuredClone(message);
  },

  async editMessage(input: {
    channelId: string;
    messageId: string;
    content: string;
  }): Promise<ChatMessage> {
    if (isTauri()) {
      return invoke<ChatMessage>("edit_message", { input });
    }
    const message = mockBootstrap.messages.find(
      (candidate) =>
        candidate.id === input.messageId &&
        candidate.channelId === input.channelId,
    );
    if (!message || message.authorId !== mockBootstrap.currentUserId) {
      throw new Error("Only the message author can edit it.");
    }
    message.content = input.content.trim();
    message.edited = true;
    return structuredClone(message);
  },

  async deleteMessage(
    channelId: string,
    messageId: string,
  ): Promise<void> {
    if (isTauri()) {
      await invoke("delete_message", { input: { channelId, messageId } });
      return;
    }
    const index = mockBootstrap.messages.findIndex(
      (candidate) =>
        candidate.id === messageId && candidate.channelId === channelId,
    );
    if (index < 0) throw new Error("That message is no longer available.");
    mockBootstrap.messages.splice(index, 1);
  },

  async updateMessageReaction(input: {
    channelId: string;
    messageId: string;
    emoji: string;
    added: boolean;
  }): Promise<ChatMessage> {
    if (isTauri()) {
      return invoke<ChatMessage>("update_message_reaction", { input });
    }
    const message = mockBootstrap.messages.find(
      (candidate) =>
        candidate.id === input.messageId &&
        candidate.channelId === input.channelId,
    );
    if (!message) throw new Error("That message is no longer available.");
    const reactions = (message.reactions ??= []);
    const reaction = reactions.find(
      (candidate) => candidate.emoji === input.emoji,
    );
    if (input.added) {
      if (reaction) {
        if (!reaction.me) reaction.count += 1;
        reaction.me = true;
      } else {
        reactions.push({ emoji: input.emoji, count: 1, me: true });
      }
    } else if (reaction) {
      if (reaction.me) reaction.count = Math.max(0, reaction.count - 1);
      reaction.me = false;
      if (reaction.count === 0) {
        message.reactions = reactions.filter(
          (candidate) => candidate !== reaction,
        );
      }
    }
    return structuredClone(message);
  },

  async requestFriend(handle: string): Promise<BootstrapViewModel> {
    if (isTauri()) {
      return invoke<BootstrapViewModel>("request_friend", {
        input: { handle },
      });
    }
    const normalized = handle.trim().replace(/^@/, "").toLocaleLowerCase();
    const member = mockBootstrap.members.find(
      (candidate) => candidate.handle.toLocaleLowerCase() === normalized,
    );
    if (!member || member.id === mockBootstrap.currentUserId) {
      throw new Error("No account has that exact handle.");
    }
    if (
      mockBootstrap.relationships.some(
        (relationship) => relationship.userId === member.id,
      )
    ) {
      throw new Error("You already have a relationship with that account.");
    }
    mockBootstrap.relationships.push(relationshipFromMember(member, "outgoing"));
    return cloneBootstrap();
  },

  async acceptFriend(userId: string): Promise<BootstrapViewModel> {
    if (isTauri()) {
      return invoke<BootstrapViewModel>("accept_friend", {
        input: { userId },
      });
    }
    const relationship = mockBootstrap.relationships.find(
      (candidate) => candidate.userId === userId,
    );
    if (!relationship || relationship.kind !== "incoming") {
      throw new Error("That request is no longer available.");
    }
    relationship.kind = "friend";
    relationship.since = new Date().toISOString();
    return cloneBootstrap();
  },

  async removeRelationship(userId: string): Promise<BootstrapViewModel> {
    if (isTauri()) {
      return invoke<BootstrapViewModel>("remove_relationship", {
        input: { userId },
      });
    }
    mockBootstrap.relationships = mockBootstrap.relationships.filter(
      (candidate) => candidate.userId !== userId,
    );
    return cloneBootstrap();
  },

  async blockUser(userId: string): Promise<BootstrapViewModel> {
    if (isTauri()) {
      return invoke<BootstrapViewModel>("block_user", {
        input: { userId },
      });
    }
    const member = mockBootstrap.members.find(
      (candidate) => candidate.id === userId,
    );
    if (!member) throw new Error("That account is unavailable.");
    mockBootstrap.relationships = [
      ...mockBootstrap.relationships.filter(
        (candidate) => candidate.userId !== userId,
      ),
      relationshipFromMember(member, "blocked"),
    ];
    return cloneBootstrap();
  },

  async openDirectMessage(userId: string): Promise<BootstrapViewModel> {
    if (isTauri()) {
      return invoke<BootstrapViewModel>("open_direct_message", {
        input: { userId },
      });
    }
    const relationship = mockBootstrap.relationships.find(
      (candidate) =>
        candidate.userId === userId && candidate.kind === "friend",
    );
    if (!relationship) throw new Error("Direct messages are available to friends.");
    const messagesWorkspace = mockBootstrap.workspaces.find(
      (workspace) => workspace.directMessages,
    );
    if (!messagesWorkspace) throw new Error("Messages are unavailable.");
    let channel = messagesWorkspace.channels.find(
      (candidate) => candidate.id === `dm-${userId}`,
    );
    if (!channel) {
      channel = {
        id: `dm-${userId}`,
        name: relationship.name,
        kind: "text",
      };
      messagesWorkspace.channels.push(channel);
    }
    mockBootstrap.activeWorkspaceId = messagesWorkspace.id;
    mockBootstrap.activeChannelId = channel.id;
    return cloneBootstrap();
  },

  async acknowledgeReadState(
    channelId: string,
    messageId: string,
  ): Promise<void> {
    if (isTauri()) {
      await invoke("acknowledge_read_state", {
        input: { channelId, messageId },
      });
      return;
    }
    const workspace = mockBootstrap.workspaces.find((candidate) =>
      candidate.channels.some((channel) => channel.id === channelId),
    );
    const channel = workspace?.channels.find(
      (candidate) => candidate.id === channelId,
    );
    if (channel) channel.unread = false;
    if (workspace?.directMessages) {
      workspace.unreadCount = workspace.channels.filter(
        (candidate) => candidate.unread,
      ).length;
    }
  },

  async startTyping(channelId: string): Promise<void> {
    if (!isTauri()) return;
    await invoke("start_typing", { input: { channelId } });
  },

  async uploadAttachment(
    channelId: string,
    file: File,
  ): Promise<MessageAttachment> {
    if (file.size === 0) throw new Error("That file is empty.");
    if (file.size > 25 * 1024 * 1024) {
      throw new Error("Attachments are limited to 25 MiB.");
    }
    if (!isTauri()) {
      return {
        id: crypto.randomUUID(),
        filename: file.name,
        contentType: file.type || "application/octet-stream",
        size: file.size,
        url: URL.createObjectURL(file),
        width: null,
        height: null,
        animated: file.type === "image/gif" || file.type === "image/webp",
      };
    }
    const encrypted = await invoke<boolean>("channel_is_end_to_end_encrypted", {
      input: { channelId },
    });
    const originalContentType = file.type || "application/octet-stream";
    const originalBytes = encrypted ? await file.arrayBuffer() : null;
    const key = encrypted ? crypto.getRandomValues(new Uint8Array(32)) : null;
    const nonce = encrypted ? crypto.getRandomValues(new Uint8Array(12)) : null;
    const additionalData = encrypted
      ? new TextEncoder().encode(
          attachmentAdditionalData(
            channelId,
            file.name,
            originalContentType,
            file.size,
          ),
        )
      : null;
    const encryptedBytes =
      encrypted && originalBytes && key && nonce && additionalData
        ? await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: nonce,
              additionalData,
              tagLength: 128,
            },
            await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
              "encrypt",
            ]),
            originalBytes,
          )
        : null;
    const uploadBody = encryptedBytes ? new Blob([encryptedBytes]) : file;
    if (uploadBody.size > 25 * 1024 * 1024) {
      throw new Error(
        "Encrypted attachments are limited to 25 MiB including authentication data.",
      );
    }
    const sha256 = await sha256Hex(uploadBody);
    const plaintextSha256 =
      originalBytes === null ? null : await sha256Hex(new Blob([originalBytes]));
    const opaqueName = encrypted
      ? `${crypto.randomUUID().replaceAll("-", "")}.exo`
      : file.name;
    const upload = await invoke<AttachmentUpload>("prepare_attachment", {
      input: {
        channelId,
        filename: opaqueName,
        contentType: encrypted
          ? "application/octet-stream"
          : originalContentType,
        fileSize: uploadBody.size,
        sha256,
      },
    });
    const response = await fetch(upload.uploadUrl, {
      method: "PUT",
      headers: upload.uploadHeaders,
      body: uploadBody,
    });
    if (!response.ok && response.status !== 412) {
      throw new Error(`Upload failed with HTTP ${response.status}.`);
    }
    const completed = await invoke<MessageAttachment>("complete_attachment", {
      input: { attachmentId: upload.id },
    });
    if (!encrypted || !key || !nonce || !plaintextSha256) return completed;
    return {
      ...completed,
      filename: file.name,
      contentType: originalContentType,
      size: file.size,
      animated:
        originalContentType === "image/gif" ||
        originalContentType === "image/webp",
      encryption: {
        algorithm: "AES-256-GCM",
        key: base64Url(key),
        nonce: base64Url(nonce),
        plaintextSha256,
        ciphertextSha256: sha256,
      },
    };
  },

  async searchMessages(input: SearchInput): Promise<SearchView> {
    const query = input.query.trim().toLocaleLowerCase();
    if (!query) {
      return {
        total: 0,
        hits: [],
        encryptedChannelCount: 0,
        permissionExcludedCount: 0,
      };
    }
    if (isTauri()) {
      return invoke<SearchView>("search_messages", { input });
    }
    const workspace = mockBootstrap.workspaces.find(
      (candidate) => candidate.id === input.workspaceId,
    );
    const channelNames = new Map(
      workspace?.channels.map((channel) => [channel.id, channel.name]) ?? [],
    );
    const hits = mockBootstrap.messages
      .filter(
        (message) =>
          channelNames.has(message.channelId) &&
          message.content.toLocaleLowerCase().includes(query),
      )
      .map((message) => ({
        message: structuredClone(message),
        workspaceId: input.workspaceId,
        workspaceName: workspace?.name ?? "Server",
        channelId: message.channelId,
        channelName: channelNames.get(message.channelId) ?? "channel",
        localOnly: false,
      }));
    return {
      total: hits.length,
      hits,
      encryptedChannelCount: 0,
      permissionExcludedCount: 0,
    };
  },

  async openSearchHit(hit: {
    workspaceId: string;
    channelId: string;
    messageId: string;
    localOnly: boolean;
  }): Promise<void> {
    if (!isTauri()) return;
    await invoke("open_search_hit", {
      input: hit,
    });
  },

  async createVoiceGrant(channelId: string): Promise<VoiceJoinGrant> {
    if (isTauri()) {
      return invoke<VoiceJoinGrant>("create_voice_grant", {
        input: { channelId },
      });
    }
    const workspace = mockBootstrap.workspaces.find((candidate) =>
      candidate.voiceRooms.some((room) => room.id === channelId),
    );
    const room = workspace?.voiceRooms.find(
      (candidate) => candidate.id === channelId,
    );
    if (!workspace || !room) throw new Error("That voice room is unavailable.");
    const memberNames = new Map(
      mockBootstrap.members.map((member) => [member.id, member.name]),
    );
    const previewParticipants = room.participants.map((participant) => ({
      ...participant,
      displayName:
        memberNames.get(participant.memberId) ?? participant.memberId,
      isLocal: participant.memberId === mockBootstrap.currentUserId,
      screenSharing: false,
      connectionQuality: "excellent" as const,
    }));
    if (
      !previewParticipants.some(
        (participant) => participant.memberId === mockBootstrap.currentUserId,
      )
    ) {
      previewParticipants.unshift({
        memberId: mockBootstrap.currentUserId,
        displayName:
          memberNames.get(mockBootstrap.currentUserId) ?? "You",
        state: "idle",
        note: "you",
        isLocal: true,
        screenSharing: false,
        connectionQuality: "excellent",
      });
    }
    return {
      channelId,
      guildId: workspace.id,
      roomName: `preview-${channelId}`,
      serverUrl: "preview://voice",
      token: "preview",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      participantId: mockBootstrap.currentUserId,
      participantName:
        memberNames.get(mockBootstrap.currentUserId) ?? "You",
      canSpeak: true,
      canStream: true,
      transportEncrypted: true,
      endToEndEncrypted: false,
      preview: true,
      previewParticipants,
    };
  },

  async setActiveContext(input: ActiveContextInput): Promise<void> {
    if (!isTauri()) {
      mockBootstrap.activeWorkspaceId = input.workspaceId;
      mockBootstrap.activeChannelId = input.channelId;
      mockBootstrap.activeVoiceRoomId = input.voiceRoomId;
      return;
    }
    await invoke("set_active_context", { input });
  },

  async retryOutbox(): Promise<void> {
    if (!isTauri()) return;
    await invoke("retry_outbox");
  },

  async subscribe(
    onSnapshot: (snapshot: BootstrapViewModel) => void,
    onDelta: (delta: CoreDelta) => void,
  ): Promise<() => void> {
    if (!isTauri()) return () => undefined;
    const [unsubscribeSnapshot, unsubscribeDelta] = await Promise.all([
      listen<BootstrapViewModel>("core://snapshot", (event) => {
        onSnapshot(event.payload);
      }),
      listen<CoreDelta>("core://delta", (event) => {
        onDelta(event.payload);
      }),
    ]);
    return () => {
      unsubscribeSnapshot();
      unsubscribeDelta();
    };
  },

  async subscribeAuthorizationChanged(
    onChanged: () => void,
  ): Promise<() => void> {
    if (!isTauri()) return () => undefined;
    return listen("core://authorization-changed", () => onChanged());
  },

  async windowAction(
    action: "minimize" | "toggle_maximize" | "close",
  ): Promise<void> {
    if (!isTauri()) return;
    await invoke("window_action", { action });
  },
};

function createMockRoleManager(workspaceId: string): RoleManagerView {
  const moderatorId = `${workspaceId}-moderator`;
  return {
    roles: [
      {
        id: moderatorId,
        name: "Moderator",
        color: "#69d7bd",
        position: 1,
        permissionKeys: [
          "create_invite",
          "manage_messages",
          "moderate_members",
          "view_member_list",
          "view_channel",
          "send_messages",
          "read_message_history",
          "connect",
          "speak",
        ],
        everyone: false,
        managed: false,
      },
      {
        id: workspaceId,
        name: "@everyone",
        color: "#3ecf8e",
        position: 0,
        permissionKeys: [
          "view_member_list",
          "view_channel",
          "send_messages",
          "read_message_history",
          "connect",
          "speak",
          "use_vad",
        ],
        everyone: true,
        managed: false,
      },
    ],
    members: mockBootstrap.members.map((member, index) => ({
      id: member.id,
      name: member.name,
      handle: member.handle,
      initials: member.initials,
      color: member.color,
      roleIds: index === 1 ? [moderatorId] : [],
    })),
  };
}

function createMockChannelManager(workspaceId: string): ChannelManagerView {
  const roles =
    mockRoleManagers.get(workspaceId) ?? createMockRoleManager(workspaceId);
  mockRoleManagers.set(workspaceId, roles);
  const workspace = mockBootstrap.workspaces.find(
    (candidate) => candidate.id === workspaceId,
  );
  return {
    channels: [
      ...(workspace?.channels.map((channel) => ({
        ...channel,
        encrypted: false,
      })) ?? []),
      ...(workspace?.voiceRooms.map((room) => ({
        id: room.id,
        name: room.name,
        kind: "voice" as const,
        encrypted: room.encrypted,
      })) ?? []),
    ],
    roles: structuredClone(roles.roles),
    members: structuredClone(roles.members),
  };
}

function createMockModerationManager(
  workspaceId: string,
): ModerationManagerView {
  const roles =
    mockRoleManagers.get(workspaceId) ?? createMockRoleManager(workspaceId);
  mockRoleManagers.set(workspaceId, roles);
  return {
    members: roles.members.map((member) => ({
      ...structuredClone(member),
      timeoutUntil: null,
    })),
    bans: [],
    rules: [],
    audit: [],
  };
}

function mockAutomodRule(
  input: AutomodRuleMutationInput,
  id: string = crypto.randomUUID(),
): AutomodRule {
  return {
    id,
    name: input.name.trim(),
    enabled: input.enabled,
    triggerType: input.triggerType,
    terms: [...input.terms],
    mentionLimit: input.mentionLimit ?? null,
    repeatThreshold: input.repeatThreshold ?? null,
    windowSeconds: input.windowSeconds ?? null,
    maxAccountAgeDays: input.maxAccountAgeDays ?? null,
    combiningMarkLimit: input.combiningMarkLimit ?? null,
    action: input.action,
    durationSeconds: input.durationSeconds ?? null,
    explanation: input.explanation.trim(),
    updatedAt: new Date().toISOString(),
  };
}

function inviteCode(value: string): string {
  const cleaned = value.trim().replace(/[?#].*$/, "").replace(/\/+$/, "");
  return cleaned.split("/").at(-1) ?? cleaned;
}

function relationshipFromMember(
  member: (typeof mockBootstrap.members)[number],
  kind: RelationshipView["kind"],
): RelationshipView {
  return {
    userId: member.id,
    name: member.name,
    handle: member.handle,
    initials: member.initials,
    color: member.color,
    kind,
    since: new Date().toISOString(),
  };
}

function attachmentAdditionalData(
  channelId: string,
  filename: string,
  contentType: string,
  size: number,
): string {
  return `exocord-attachment-v1\n${channelId}\n${filename}\n${contentType}\n${size}`;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function sha256Hex(file: Blob): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
