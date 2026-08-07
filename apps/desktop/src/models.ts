export type ChannelKind = "text" | "voice";
export type Presence = "online" | "away" | "offline";
export type VoiceState = "speaking" | "muted" | "idle";
export type VoiceConnectionState =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "failed";
export type ConnectionState =
  | "offline"
  | "connecting"
  | "connected"
  | "catching_up";
export type DeliveryState = "sent" | "pending" | "failed";
export type NotificationMode = "off" | "private" | "names";

export interface NotificationSettingsView {
  mode: NotificationMode;
}

export interface WindowSettingsView {
  minimizeToTray: boolean;
}

export interface Channel {
  id: string;
  name: string;
  kind: ChannelKind;
  unread?: boolean;
}

export interface Member {
  id: string;
  name: string;
  handle: string;
  initials: string;
  color: string;
  avatarUrl?: string;
  presence: Presence;
}

export interface ProfileUpdateInput {
  handle: string;
  displayName: string;
  avatarContentType?: string;
  avatarBase64?: string;
  removeAvatar: boolean;
}

export interface VoiceParticipant {
  memberId: string;
  displayName?: string;
  state: VoiceState;
  note: string;
  screenSharing?: boolean;
  isLocal?: boolean;
  connectionQuality?: "excellent" | "good" | "poor" | "unknown";
}

export interface VoiceRoom {
  id: string;
  name: string;
  latencyMs: number;
  encrypted: boolean;
  participants: VoiceParticipant[];
}

export interface VoiceJoinGrant {
  channelId: string;
  guildId?: string | null;
  roomName: string;
  serverUrl: string;
  token: string;
  expiresAt: string;
  participantId: string;
  participantName: string;
  canSpeak: boolean;
  canStream: boolean;
  transportEncrypted: boolean;
  endToEndEncrypted: boolean;
  e2eeKey?: string | null;
  preview?: boolean;
  previewParticipants?: VoiceParticipant[];
}

export interface VoiceSessionSnapshot {
  roomId: string | null;
  status: VoiceConnectionState;
  participants: VoiceParticipant[];
  muted: boolean;
  deafened: boolean;
  sharing: boolean;
  canSpeak: boolean;
  canStream: boolean;
  transportEncrypted: boolean;
  endToEndEncrypted: boolean;
  error: string | null;
}

export interface VoiceDevice {
  deviceId: string;
  label: string;
}

export interface VoiceDeviceSnapshot {
  inputs: VoiceDevice[];
  outputs: VoiceDevice[];
  activeInputId: string | null;
  activeOutputId: string | null;
}

export interface Workspace {
  id: string;
  ownerId: string;
  name: string;
  initials: string;
  accent: string;
  permissionKeys: string[];
  memberIds?: string[];
  channels: Channel[];
  voiceRooms: VoiceRoom[];
  directMessages: boolean;
  localOnly?: boolean;
  unreadCount?: number;
}

export type RelationshipKind = "incoming" | "outgoing" | "friend" | "blocked";

export interface RelationshipView {
  userId: string;
  name: string;
  handle: string;
  initials: string;
  color: string;
  kind: RelationshipKind;
  since: string;
}

export interface TypingView {
  channelId: string;
  userId: string;
  expiresAt: string;
}

export interface MessageAttachment {
  id: string;
  filename: string;
  contentType: string;
  size: number;
  url: string;
  width: number | null;
  height: number | null;
  animated: boolean;
  encryption?: AttachmentEncryption;
}

export interface AttachmentEncryption {
  algorithm: "AES-256-GCM";
  key: string;
  nonce: string;
  plaintextSha256: string;
  ciphertextSha256: string;
}

export interface AttachmentUpload {
  id: string;
  uploadUrl: string;
  uploadHeaders: Record<string, string>;
  expiresAt: string;
  maxBytes: number;
}

export interface ReplyPreview {
  author: string;
  text: string;
}

export interface Reaction {
  emoji: string;
  count: number;
  me?: boolean;
}

export interface ChatMessage {
  id: string;
  clientKey?: string;
  channelId: string;
  authorId: string;
  replyToId?: string;
  content: string;
  sentAt: string;
  edited?: boolean;
  deliveryState?: DeliveryState;
  delivered?: boolean;
  reply?: ReplyPreview;
  attachments?: MessageAttachment[];
  reactions?: Reaction[];
}

export interface BootstrapViewModel {
  revision: number;
  currentUserId: string;
  activeWorkspaceId: string;
  activeChannelId: string;
  activeVoiceRoomId: string | null;
  connectionState: ConnectionState;
  pendingOutbox: number;
  workspaces: Workspace[];
  members: Member[];
  relationships: RelationshipView[];
  typing: TypingView[];
  messages: ChatMessage[];
  cacheProtection: CacheProtectionView;
  cacheRecovery: CacheRecoveryView | null;
}

export interface CacheProtectionView {
  encrypted: boolean;
  cipher: string;
  keyStorage: string;
}

export interface CacheRecoveryView {
  reason:
    | "vault_unavailable"
    | "cache_key_unavailable"
    | "encryption_unavailable"
    | "cache_locked"
    | "cache_corrupt"
    | "migration_failed"
    | "storage_failed";
  title: string;
  message: string;
  detail: string;
  cachePath: string;
  canReset: boolean;
}

export interface DirectUnreadDelta {
  channelId: string;
  unread: boolean;
  unreadCount: number;
}

export type CoreDelta =
  | {
      version: 1;
      revision: number;
      type: "message_upsert";
      message: ChatMessage;
      directUnread?: DirectUnreadDelta;
      notify?: true;
    }
  | {
      version: 1;
      revision: number;
      type: "message_delete";
      messageId: string;
      channelId: string;
    }
  | {
      version: 1;
      revision: number;
      type: "presence";
      userId: string;
      presence: Presence;
    }
  | {
      version: 1;
      revision: number;
      type: "typing_upsert";
      typing: TypingView;
    }
  | {
      version: 1;
      revision: number;
      type: "typing_remove";
      channelId: string;
      userId: string;
    }
  | {
      version: 1;
      revision: number;
      type: "read_state";
      directUnread: DirectUnreadDelta;
    }
  | {
      version: 1;
      revision: number;
      type: "connection";
      connectionState: ConnectionState;
    };

export interface CreateWorkspaceInput {
  name: string;
}

export interface SendMessageInput {
  channelId: string;
  content: string;
  replyToId?: string;
  attachments: MessageAttachment[];
}

export interface SearchInput {
  workspaceId: string;
  query: string;
}

export interface SearchHit {
  message: ChatMessage;
  workspaceId: string;
  workspaceName: string;
  channelId: string;
  channelName: string;
  localOnly: boolean;
}

export interface SearchView {
  total: number;
  hits: SearchHit[];
  encryptedChannelCount: number;
  permissionExcludedCount: number;
}

export interface ActiveContextInput {
  workspaceId: string;
  channelId: string;
  voiceRoomId: string | null;
}

export interface AuthView {
  signedIn: boolean;
  email: string | null;
  deletionScheduledFor: string | null;
  passwordAvailable: boolean;
  appleAvailable: boolean;
  developmentCodePreview: boolean;
}

export interface PasswordAuthenticationView {
  auth: AuthView;
  recoveryCodes: string[];
}

export interface AccountAuthMethodsView {
  passwordSet: boolean;
  appleLinked: boolean;
  appleEmail: string | null;
}

export interface NetworkConfigurationView {
  apiUrl: string;
  source: "environment" | "saved" | "build" | "local_default" | "preview";
  secure: boolean;
  managed: boolean;
  warning: string | null;
}

export interface UpdateManifest {
  version: string;
  filename: string;
  sha256: string;
  notes: string;
}

export interface UpdateStatusView {
  currentVersion: string;
  update: UpdateManifest | null;
}

export interface NetworkProbeView {
  ready: boolean;
  storage: string;
  attachments: string;
  password: boolean;
  email: boolean;
  apple: boolean;
  developmentCodePreview: boolean;
  conversationActions: string;
  nativeVoice: string;
  operator: OperatorInfoView;
}

export interface OperatorInfoView {
  name: string;
  privacyUrl: string | null;
  termsUrl: string | null;
  supportEmail: string | null;
  abuseEmail: string | null;
}

export interface AccountDeletionView {
  requestedAt: string;
  scheduledFor: string;
}

export interface OwnedServerStatus {
  id: string;
  name: string;
  memberCount: number;
}

export interface AccountDeletionStatusView {
  deletion: AccountDeletionView | null;
  ownedServers: OwnedServerStatus[];
}

export interface ServerOwnershipMember {
  id: string;
  name: string;
  handle: string;
  initials: string;
  color: string;
}

export interface ServerOwnershipView {
  workspaceId: string;
  ownerId: string;
  name: string;
  members: ServerOwnershipMember[];
}

export interface DeviceSecurityDevice {
  deviceId: string;
  name: string;
  fingerprint: string;
  current: boolean;
  revoked: boolean;
}

export interface DeviceSecurityView {
  ready: boolean;
  deviceId: string;
  fingerprint: string | null;
  cipherSuite: string;
  noKeyBackup: boolean;
  historyNotice: string;
  devices: DeviceSecurityDevice[];
  error: string | null;
}

export interface EmailCodeChallenge {
  challengeId: string;
  expiresInSeconds: number;
  developmentCode?: string;
}

export type ReportCategory =
  | "spam"
  | "harassment"
  | "threats_violence"
  | "sexual_content_involving_minors"
  | "self_harm"
  | "illegal_content"
  | "impersonation"
  | "other";

export interface ReportMessageInput {
  messageId: string;
  category: ReportCategory;
  detail?: string;
}

export interface ReportReceipt {
  id: string;
  status: string;
  createdAt: string;
}

export interface InviteView {
  code: string;
  maxUses: number | null;
  expiresAt: string | null;
}

export interface InvitePreview {
  code: string;
  workspaceId: string;
  name: string;
  accent: string;
  memberCount: number;
  expiresAt: string | null;
}

export interface ServerRole {
  id: string;
  name: string;
  color: string;
  position: number;
  permissionKeys: string[];
  everyone: boolean;
  managed: boolean;
}

export interface RoleMember {
  id: string;
  name: string;
  handle: string;
  initials: string;
  color: string;
  roleIds: string[];
}

export interface RoleManagerView {
  roles: ServerRole[];
  members: RoleMember[];
}

export interface RoleMutationInput {
  workspaceId: string;
  roleId?: string;
  name: string;
  color: string;
  permissionKeys: string[];
}

export interface ManagedChannel {
  id: string;
  name: string;
  kind: ChannelKind;
  encrypted: boolean;
}

export interface ChannelManagerView {
  channels: ManagedChannel[];
  roles: ServerRole[];
  members: RoleMember[];
}

export type OverwriteTargetKind = "role" | "member";

export interface ChannelOverwrite {
  channelId: string;
  targetKind: OverwriteTargetKind;
  targetId: string;
  allowKeys: string[];
  denyKeys: string[];
}

export interface ChannelMutationInput {
  workspaceId: string;
  channelId?: string;
  name: string;
  kind: ChannelKind;
  encrypted: boolean;
}

export interface ChannelOverwriteInput {
  channelId: string;
  targetKind: OverwriteTargetKind;
  targetId: string;
  allowKeys: string[];
  denyKeys: string[];
}

export interface ModerationMember {
  id: string;
  name: string;
  handle: string;
  initials: string;
  color: string;
  roleIds: string[];
  timeoutUntil: string | null;
}

export interface ServerBan {
  id: string;
  name: string;
  handle: string;
  initials: string;
  color: string;
  reason: string | null;
  expiresAt: string | null;
  createdAt: string;
}

export interface ModerationManagerView {
  members: ModerationMember[];
  bans: ServerBan[];
  rules: AutomodRule[];
  audit: AuditLogEntry[];
}

export interface MemberModerationInput {
  workspaceId: string;
  memberId: string;
  durationSeconds?: number;
  reason?: string;
}

export type AutomodTriggerType =
  | "keyword"
  | "regex"
  | "invite_link"
  | "mass_mention"
  | "repeated_content"
  | "new_account_link"
  | "zalgo";

export type AutomodAction = "flag" | "block" | "timeout" | "kick" | "ban";

export interface AutomodRule {
  id: string;
  name: string;
  enabled: boolean;
  triggerType: AutomodTriggerType;
  terms: string[];
  mentionLimit: number | null;
  repeatThreshold: number | null;
  windowSeconds: number | null;
  maxAccountAgeDays: number | null;
  combiningMarkLimit: number | null;
  action: AutomodAction;
  durationSeconds: number | null;
  explanation: string;
  updatedAt: string;
}

export interface AutomodRuleMutationInput {
  workspaceId: string;
  ruleId?: string;
  name: string;
  enabled: boolean;
  triggerType: AutomodTriggerType;
  terms: string[];
  mentionLimit?: number;
  repeatThreshold?: number;
  windowSeconds?: number;
  maxAccountAgeDays?: number;
  combiningMarkLimit?: number;
  action: AutomodAction;
  durationSeconds?: number;
  explanation: string;
}

export interface AuditLogEntry {
  id: string;
  actorId: string | null;
  targetId: string | null;
  actionType: number;
  actionLabel: string;
  detail: string | null;
  reason: string | null;
  createdAt: string;
}
