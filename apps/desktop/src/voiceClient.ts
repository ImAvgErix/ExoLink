import type {
  ConnectionQuality,
  Participant,
  RemoteTrack,
  Room,
} from "livekit-client";
import E2EEWorker from "livekit-client/e2ee-worker?worker";
import type {
  VoiceJoinGrant,
  VoiceDeviceSnapshot,
  VoiceParticipant,
  VoiceSessionSnapshot,
} from "./models";

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

type VoiceListener = (snapshot: VoiceSessionSnapshot) => void;
type LiveKitModule = typeof import("livekit-client");

export type VoiceJoinOptions = {
  startMuted?: boolean;
  startDeafened?: boolean;
  resumeScreenShare?: boolean;
};

type ActiveVoiceConnection = {
  generation: number;
  room: Room;
  worker: Worker | null;
  e2eeKey: string | null;
};

export class VoiceClient {
  private room: Room | null = null;
  private livekit: LiveKitModule | null = null;
  private snapshot: VoiceSessionSnapshot = EMPTY_VOICE_SESSION;
  private listeners = new Set<VoiceListener>();
  private joinGeneration = 0;
  private preDeafenMicrophone = false;
  private preview = false;
  private activeConnection: ActiveVoiceConnection | null = null;
  private mediaMutation: Promise<void> = Promise.resolve();

  subscribe(listener: VoiceListener): () => void {
    this.listeners.add(listener);
    listener(this.current());
    return () => {
      this.listeners.delete(listener);
    };
  }

  current(): VoiceSessionSnapshot {
    return structuredClone(this.snapshot);
  }

  async preload(): Promise<void> {
    await this.loadLiveKit();
  }

  async join(
    grant: VoiceJoinGrant,
    options: VoiceJoinOptions = {},
  ): Promise<void> {
    const generation = ++this.joinGeneration;
    await this.disconnectRoom();
    if (generation !== this.joinGeneration) return;
    const startMuted = options.startMuted === true || !grant.canSpeak;
    const startDeafened = options.startDeafened === true;
    const resumeScreenShare =
      options.resumeScreenShare === true && grant.canStream;
    this.preview = grant.preview === true;
    this.preDeafenMicrophone = false;
    this.update({
      ...EMPTY_VOICE_SESSION,
      roomId: grant.channelId,
      status: "connecting",
      muted: startMuted || startDeafened,
      deafened: startDeafened,
      canSpeak: grant.canSpeak,
      canStream: grant.canStream,
      transportEncrypted: grant.transportEncrypted,
      endToEndEncrypted: grant.endToEndEncrypted,
    });

    if (this.preview) {
      this.update({
        status: "connected",
        sharing: resumeScreenShare,
        participants: (
          grant.previewParticipants?.map((participant) => ({
            ...participant,
          })) ?? [
            {
              memberId: grant.participantId,
              displayName: grant.participantName,
              state: "idle",
              note: "you",
              isLocal: true,
              connectionQuality: "excellent",
            },
          ]
        ).map((participant) =>
          participant.isLocal
            ? {
                ...participant,
                state: startMuted || startDeafened ? "muted" : "idle",
                note: resumeScreenShare
                  ? "you · sharing"
                  : startMuted || startDeafened
                    ? "muted"
                    : "you",
                screenSharing: resumeScreenShare,
              }
            : participant,
        ),
      });
      return;
    }

    let room: Room | null = null;
    let worker: Worker | null = null;
    try {
      const { ExternalE2EEKeyProvider, Room } = await this.loadLiveKit();
      if (generation !== this.joinGeneration) return;
      // Fail closed only when the grant promises E2EE but omits a key.
      // Transport-only grants (LiveKit WSS, no SFrame) must still connect so
      // mute/deafen/PTT/screen-share remain usable against alpha backends.
      if (grant.endToEndEncrypted && !grant.e2eeKey) {
        throw new Error(
          "Voice refused to connect because an end-to-end encryption key is unavailable.",
        );
      }
      const roomOptions: ConstructorParameters<typeof Room>[0] = {
        adaptiveStream: true,
        dynacast: true,
        disconnectOnPageLeave: true,
        audioCaptureDefaults: {
          autoGainControl: true,
          echoCancellation: true,
          noiseSuppression: true,
        },
      };
      if (grant.endToEndEncrypted && grant.e2eeKey) {
        const keyProvider = new ExternalE2EEKeyProvider();
        await keyProvider.setKey(decodeBase64Url(grant.e2eeKey));
        if (generation !== this.joinGeneration) return;
        worker = new E2EEWorker();
        roomOptions.encryption = {
          keyProvider,
          worker,
        };
      }
      room = new Room(roomOptions);
      if (generation !== this.joinGeneration) {
        worker?.terminate();
        return;
      }
      this.room = room;
      this.activeConnection = {
        generation,
        room,
        worker,
        e2eeKey: grant.endToEndEncrypted ? grant.e2eeKey ?? null : null,
      };
      this.bindRoom(room, generation);
      await room.connect(grant.serverUrl, grant.token, {
        autoSubscribe: true,
        maxRetries: 3,
        peerConnectionTimeout: 15_000,
        websocketTimeout: 10_000,
      });
      if (generation !== this.joinGeneration) {
        await room.disconnect(true);
        return;
      }
      await room.startAudio().catch(() => undefined);
      let microphoneError: string | null = null;
      if (startMuted || startDeafened || !grant.canSpeak) {
        await room.localParticipant
          .setMicrophoneEnabled(false)
          .catch(() => undefined);
      } else {
        try {
          await room.localParticipant.setMicrophoneEnabled(true);
        } catch (error) {
          microphoneError = mediaError(
            error,
            "Microphone access was denied. You joined muted.",
          );
        }
      }
      if (generation !== this.joinGeneration || this.room !== room) {
        await room.disconnect(true).catch(() => undefined);
        worker?.terminate();
        return;
      }
      if (resumeScreenShare) {
        await room.localParticipant
          .setScreenShareEnabled(true, {
            audio: true,
            contentHint: "detail",
          })
          .catch((error) => {
            microphoneError ??= mediaError(
              error,
              "Screen sharing could not be resumed.",
            );
          });
      }
      this.setRemoteAudioMuted(startDeafened);
      this.refresh({
        status: "connected",
        deafened: startDeafened,
        error: microphoneError,
      });
    } catch (error) {
      if (room && this.room === room && generation === this.joinGeneration) {
        this.room = null;
        this.activeConnection = null;
      }
      await room?.disconnect(true).catch(() => undefined);
      worker?.terminate();
      if (generation !== this.joinGeneration) return;
      this.update({
        status: "failed",
        participants: [],
        muted: true,
        sharing: false,
        error: mediaError(error, "Voice could not connect."),
      });
      throw error;
    }
  }

  async leave(): Promise<void> {
    ++this.joinGeneration;
    await this.disconnectRoom();
    this.preview = false;
    this.update({ ...EMPTY_VOICE_SESSION });
  }

  async reauthorize(grant: VoiceJoinGrant): Promise<void> {
    if (this.snapshot.roomId !== grant.channelId) return;
    // MLS membership changes advance the exported SFrame key.  LiveKit does
    // not renegotiate an external E2EE key on an existing Room, so reconnect
    // the active session when the grant carries a different key.  This keeps
    // every participant on the same serialized MLS epoch instead of leaving
    // an existing client on the prior voice key.
    const e2eeKey = grant.endToEndEncrypted ? grant.e2eeKey ?? null : null;
    if (
      !this.preview &&
      this.activeConnection?.e2eeKey !== e2eeKey
    ) {
      await this.join(grant, {
        startMuted: this.snapshot.muted,
        startDeafened: this.snapshot.deafened,
        resumeScreenShare: this.snapshot.sharing,
      });
      return;
    }
    const expanded =
      (grant.canSpeak && !this.snapshot.canSpeak) ||
      (grant.canStream && !this.snapshot.canStream);
    if (expanded) {
      await this.join(grant, {
        startMuted: this.snapshot.muted,
        startDeafened: this.snapshot.deafened,
        resumeScreenShare: this.snapshot.sharing,
      });
      return;
    }
    if (this.preview) {
      const muted = grant.canSpeak ? this.snapshot.muted : true;
      const sharing = grant.canStream ? this.snapshot.sharing : false;
      this.update({
        canSpeak: grant.canSpeak,
        canStream: grant.canStream,
        muted,
        sharing,
        participants: this.previewParticipantState(muted, sharing),
      });
      return;
    }
    this.update({
      canSpeak: grant.canSpeak,
      canStream: grant.canStream,
      transportEncrypted: grant.transportEncrypted,
      endToEndEncrypted: grant.endToEndEncrypted,
    });
    const generation = this.joinGeneration;
    await this.queueMediaMutation(generation, async () => {
      const room = this.requireRoom();
      if (!grant.canSpeak && room.localParticipant.isMicrophoneEnabled) {
        await room.localParticipant.setMicrophoneEnabled(false);
      }
      if (!grant.canStream && room.localParticipant.isScreenShareEnabled) {
        await room.localParticipant.setScreenShareEnabled(false);
      }
      if (generation === this.joinGeneration && room === this.room) {
        this.refresh();
      }
    });
  }

  async setMuted(muted: boolean): Promise<void> {
    const generation = this.joinGeneration;
    return this.queueMediaMutation(generation, async () => {
      if (this.snapshot.status !== "connected") return;
      if (this.snapshot.deafened) {
        throw new Error("Undeafen before changing your microphone.");
      }
      if (!this.snapshot.canSpeak && !muted) {
        throw new Error("You do not have permission to speak in this room.");
      }
      if (this.preview) {
        this.update({
          muted,
          participants: this.previewParticipantState(
            muted,
            this.snapshot.sharing,
          ),
        });
        return;
      }
      const room = this.requireRoom();
      await room.localParticipant.setMicrophoneEnabled(!muted);
      if (generation === this.joinGeneration && room === this.room) {
        this.refresh({ muted });
      }
    });
  }

  async setDeafened(deafened: boolean): Promise<void> {
    const generation = this.joinGeneration;
    return this.queueMediaMutation(generation, async () => {
      if (this.snapshot.status !== "connected") return;
      if (this.preview) {
        if (deafened) {
          this.preDeafenMicrophone = !this.snapshot.muted;
        }
        const muted =
          deafened || !this.preDeafenMicrophone || !this.snapshot.canSpeak;
        this.update({
          deafened,
          muted,
          participants: this.previewParticipantState(
            muted,
            this.snapshot.sharing,
          ),
        });
        if (!deafened) this.preDeafenMicrophone = false;
        return;
      }
      const room = this.requireRoom();
      if (deafened) {
        this.preDeafenMicrophone = room.localParticipant.isMicrophoneEnabled;
        if (this.preDeafenMicrophone) {
          await room.localParticipant.setMicrophoneEnabled(false);
        }
      } else if (this.preDeafenMicrophone && this.snapshot.canSpeak) {
        await room.localParticipant.setMicrophoneEnabled(true);
      }
      if (generation !== this.joinGeneration || room !== this.room) return;
      if (!deafened) this.preDeafenMicrophone = false;
      this.setRemoteAudioMuted(deafened);
      this.refresh({
        deafened,
        muted: !room.localParticipant.isMicrophoneEnabled,
      });
    });
  }

  async setScreenSharing(sharing: boolean): Promise<void> {
    const generation = this.joinGeneration;
    return this.queueMediaMutation(generation, async () => {
      if (this.snapshot.status !== "connected") return;
      if (!this.snapshot.canStream && sharing) {
        throw new Error("You do not have permission to share your screen here.");
      }
      if (this.preview) {
        this.update({
          sharing,
          participants: this.previewParticipantState(
            this.snapshot.muted,
            sharing,
          ),
        });
        return;
      }
      const room = this.requireRoom();
      await room.localParticipant.setScreenShareEnabled(sharing, {
        audio: true,
        contentHint: "detail",
      });
      if (generation === this.joinGeneration && room === this.room) {
        this.refresh({ sharing: room.localParticipant.isScreenShareEnabled });
      }
    });
  }

  async resumeAudio(): Promise<void> {
    if (this.preview) return;
    await this.room?.startAudio();
  }

  async devices(): Promise<VoiceDeviceSnapshot> {
    if (this.preview) {
      return {
        inputs: [
          { deviceId: "preview-mic", label: "Studio microphone" },
          { deviceId: "preview-headset", label: "Headset microphone" },
        ],
        outputs: [
          { deviceId: "preview-speakers", label: "Desktop speakers" },
          { deviceId: "preview-headphones", label: "Headphones" },
        ],
        activeInputId: "preview-mic",
        activeOutputId: "preview-headphones",
      };
    }
    const room = this.requireRoom();
    const [inputs, outputs] = await Promise.all([
      this.requireLiveKit().Room.getLocalDevices("audioinput", true),
      this.requireLiveKit().Room.getLocalDevices("audiooutput", false),
    ]);
    return {
      inputs: inputs.map((device, index) => ({
        deviceId: device.deviceId,
        label: device.label || `Microphone ${index + 1}`,
      })),
      outputs: outputs.map((device, index) => ({
        deviceId: device.deviceId,
        label: device.label || `Speaker ${index + 1}`,
      })),
      activeInputId: room.getActiveDevice("audioinput") ?? null,
      activeOutputId: room.getActiveDevice("audiooutput") ?? null,
    };
  }

  async switchDevice(
    kind: "audioinput" | "audiooutput",
    deviceId: string,
  ): Promise<void> {
    if (this.preview) return;
    const changed = await this.requireRoom().switchActiveDevice(
      kind,
      deviceId,
      true,
    );
    if (!changed) {
      throw new Error(
        kind === "audioinput"
          ? "The microphone could not be selected."
          : "This system does not support changing speakers inside the app.",
      );
    }
  }

  attachScreenShare(
    container: HTMLElement,
    participantId: string,
  ): () => void {
    container.replaceChildren();
    if (this.preview) {
      const placeholder = document.createElement("div");
      placeholder.className = "voice-screen-preview-placeholder";
      placeholder.textContent = "Live screen preview";
      container.append(placeholder);
      return () => placeholder.remove();
    }
    const room = this.room;
    if (!room) return () => undefined;
    const { Track } = this.requireLiveKit();
    const participant =
      room.localParticipant.identity === participantId
        ? room.localParticipant
        : room.remoteParticipants.get(participantId);
    const track = participant
      ?.getTrackPublication(Track.Source.ScreenShare)
      ?.track;
    if (!track || track.kind !== Track.Kind.Video) return () => undefined;
    const video = document.createElement("video");
    video.autoplay = true;
    video.playsInline = true;
    video.muted = participant?.isLocal === true;
    video.setAttribute(
      "aria-label",
      `${participant?.name ?? participantId}'s screen`,
    );
    track.attach(video);
    container.append(video);
    return () => {
      track.detach(video);
      video.remove();
    };
  }

  private bindRoom(room: Room, generation: number): void {
    const { RoomEvent } = this.requireLiveKit();
    const current = (action: () => void) => {
      if (generation === this.joinGeneration && this.room === room) action();
    };
    room
      .on(RoomEvent.Connected, () =>
        current(() => this.refresh({ status: "connected" })),
      )
      .on(RoomEvent.Reconnecting, () =>
        current(() => this.refresh({ status: "reconnecting" })),
      )
      .on(RoomEvent.Reconnected, () =>
        current(() => this.refresh({ status: "connected" })),
      )
      .on(RoomEvent.Disconnected, () => {
        current(() => {
          this.detachAllMedia();
          this.activeConnection?.worker?.terminate();
          this.activeConnection = null;
          this.room = null;
          this.update({
            status: "failed",
            participants: [],
            muted: true,
            sharing: false,
            error: "The voice connection ended. Select the room to reconnect.",
          });
        });
      })
      .on(RoomEvent.ParticipantConnected, () => current(() => this.refresh()))
      .on(RoomEvent.ParticipantDisconnected, () => current(() => this.refresh()))
      .on(RoomEvent.ActiveSpeakersChanged, () => current(() => this.refresh()))
      .on(RoomEvent.ConnectionQualityChanged, () => current(() => this.refresh()))
      .on(RoomEvent.TrackMuted, () => current(() => this.refresh()))
      .on(RoomEvent.TrackUnmuted, () => current(() => this.refresh()))
      .on(RoomEvent.TrackPublished, () => current(() => this.refresh()))
      .on(RoomEvent.TrackUnpublished, () => current(() => this.refresh()))
      .on(RoomEvent.LocalTrackPublished, () => current(() => this.refresh()))
      .on(RoomEvent.LocalTrackUnpublished, () => current(() => this.refresh()))
      .on(RoomEvent.TrackSubscribed, (track) => {
        current(() => {
          this.attachRemoteTrack(track);
          this.refresh();
        });
      })
      .on(RoomEvent.TrackUnsubscribed, (track) => {
        current(() => {
          this.detachTrack(track);
          this.refresh();
        });
      })
      .on(RoomEvent.AudioPlaybackStatusChanged, (playing) => {
        current(() =>
          this.refresh({
            error: playing
              ? null
              : "Audio playback is paused. Click the voice panel to resume it.",
          }),
        );
      })
      .on(RoomEvent.MediaDevicesError, (error) => {
        current(() =>
          this.refresh({
            error: mediaError(error, "A media device stopped working."),
          }),
        );
      })
      .on(RoomEvent.EncryptionError, (error) => {
        current(() =>
          this.refresh({
            error: mediaError(
              error,
              "Voice encryption failed. Leave and rejoin the room.",
            ),
          }),
        );
      });
  }

  private attachRemoteTrack(track: RemoteTrack): void {
    const { Track } = this.requireLiveKit();
    if (track.kind !== Track.Kind.Audio) return;
    const element = track.attach();
    element.autoplay = true;
    element.muted = this.snapshot.deafened;
    element.dataset.exocordVoiceAudio = "true";
    element.style.display = "none";
    document.body.append(element);
  }

  private detachTrack(track: RemoteTrack): void {
    for (const element of track.detach()) {
      element.remove();
    }
  }

  private detachAllMedia(): void {
    document
      .querySelectorAll<HTMLMediaElement>("[data-exocord-voice-audio]")
      .forEach((element) => element.remove());
  }

  private setRemoteAudioMuted(muted: boolean): void {
    document
      .querySelectorAll<HTMLMediaElement>("[data-exocord-voice-audio]")
      .forEach((element) => {
        element.muted = muted;
      });
  }

  private participants(): VoiceParticipant[] {
    const room = this.room;
    if (!room) return this.snapshot.participants;
    const participants = [
      room.localParticipant,
      ...room.remoteParticipants.values(),
    ].map((participant) =>
      participantView(
        participant,
        this.requireLiveKit().ConnectionQuality,
      ),
    );
    participants.sort((left, right) => {
      if (left.isLocal !== right.isLocal) return left.isLocal ? -1 : 1;
      if (left.state !== right.state) {
        return left.state === "speaking" ? -1 : 1;
      }
      return (left.displayName ?? left.memberId).localeCompare(
        right.displayName ?? right.memberId,
      );
    });
    return participants;
  }

  private refresh(patch: Partial<VoiceSessionSnapshot> = {}): void {
    const room = this.room;
    this.update({
      participants: this.participants(),
      muted: room ? !room.localParticipant.isMicrophoneEnabled : true,
      sharing: room?.localParticipant.isScreenShareEnabled ?? false,
      ...patch,
    });
  }

  private previewParticipantState(
    muted: boolean,
    sharing: boolean,
  ): VoiceParticipant[] {
    return this.snapshot.participants.map((participant) =>
      participant.isLocal
        ? {
            ...participant,
            state: muted ? "muted" : "idle",
            note: sharing ? "you · sharing" : muted ? "muted" : "you",
            screenSharing: sharing,
          }
        : participant,
    );
  }

  private update(patch: Partial<VoiceSessionSnapshot>): void {
    this.snapshot = { ...this.snapshot, ...patch };
    const next = this.current();
    for (const listener of this.listeners) listener(next);
  }

  private requireRoom(): Room {
    if (!this.room) throw new Error("Voice is not connected.");
    return this.room;
  }

  private async loadLiveKit(): Promise<LiveKitModule> {
    this.livekit ??= await import("livekit-client");
    return this.livekit;
  }

  private requireLiveKit(): LiveKitModule {
    if (!this.livekit) throw new Error("Voice media is not loaded.");
    return this.livekit;
  }

  private queueMediaMutation(
    generation: number,
    mutation: () => Promise<void>,
  ): Promise<void> {
    const operation = this.mediaMutation.then(async () => {
      if (generation !== this.joinGeneration) return;
      await mutation();
    });
    this.mediaMutation = operation.catch(() => undefined);
    return operation;
  }

  private async disconnectRoom(): Promise<void> {
    const room = this.room;
    const connection =
      this.activeConnection?.room === room ? this.activeConnection : null;
    this.room = null;
    this.activeConnection = null;
    if (!room) return;
    try {
      await room.disconnect(true);
    } finally {
      this.detachAllMedia();
      connection?.worker?.terminate();
    }
  }
}

function decodeBase64Url(value: string): ArrayBuffer {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(
    `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`,
  );
  return Uint8Array.from(
    binary,
    (character) => character.charCodeAt(0),
  ).buffer as ArrayBuffer;
}

function participantView(
  participant: Participant,
  connectionQuality: LiveKitModule["ConnectionQuality"],
): VoiceParticipant {
  const muted = !participant.isMicrophoneEnabled;
  return {
    memberId: participant.identity,
    displayName: participant.name || participant.identity,
    state: participant.isSpeaking ? "speaking" : muted ? "muted" : "idle",
    note: participant.isLocal
      ? participant.isScreenShareEnabled
        ? "you · sharing"
        : "you"
      : participant.isScreenShareEnabled
        ? "sharing screen"
        : participant.isSpeaking
          ? "speaking"
          : muted
            ? "muted"
            : "listening",
    screenSharing: participant.isScreenShareEnabled,
    isLocal: participant.isLocal,
    connectionQuality: quality(
      participant.connectionQuality,
      connectionQuality,
    ),
  };
}

function quality(
  value: ConnectionQuality,
  connectionQuality: LiveKitModule["ConnectionQuality"],
): VoiceParticipant["connectionQuality"] {
  if (value === connectionQuality.Excellent) return "excellent";
  if (value === connectionQuality.Good) return "good";
  if (
    value === connectionQuality.Poor ||
    value === connectionQuality.Lost
  ) {
    return "poor";
  }
  return "unknown";
}

function mediaError(error: unknown, fallback: string): string {
  if (error instanceof DOMException) {
    if (error.name === "NotAllowedError") return fallback;
    if (error.name === "NotFoundError") return "No compatible media device was found.";
  }
  if (error instanceof Error && error.message.trim()) return error.message;
  return fallback;
}

export const voiceClient = new VoiceClient();
