import { describe, expect, it, vi } from "vitest";
import type { VoiceJoinGrant } from "./models";

vi.stubGlobal("document", {
  body: { append: () => undefined },
  querySelectorAll: () => [],
});

const fake = vi.hoisted(() => {
  const events = {
    Connected: "connected",
    Reconnecting: "reconnecting",
    Reconnected: "reconnected",
    Disconnected: "disconnected",
    ParticipantConnected: "participant-connected",
    ParticipantDisconnected: "participant-disconnected",
    ActiveSpeakersChanged: "active-speakers",
    ConnectionQualityChanged: "connection-quality",
    TrackMuted: "track-muted",
    TrackUnmuted: "track-unmuted",
    TrackPublished: "track-published",
    TrackUnpublished: "track-unpublished",
    LocalTrackPublished: "local-track-published",
    LocalTrackUnpublished: "local-track-unpublished",
    TrackSubscribed: "track-subscribed",
    TrackUnsubscribed: "track-unsubscribed",
    AudioPlaybackStatusChanged: "audio-playback",
    MediaDevicesError: "media-devices-error",
    EncryptionError: "encryption-error",
  };
  class Worker {
    terminated = false;
    terminate() {
      this.terminated = true;
    }
  }
  class Participant {
    identity = "local-member";
    name = "Local member";
    isLocal = true;
    isSpeaking = false;
    isMicrophoneEnabled = false;
    isScreenShareEnabled = false;
    connectionQuality = "excellent";
    microphoneGate: Promise<void> | null = null;
    async setMicrophoneEnabled(enabled: boolean) {
      if (enabled && this.microphoneGate) await this.microphoneGate;
      this.isMicrophoneEnabled = enabled;
    }
    async setScreenShareEnabled(enabled: boolean) {
      this.isScreenShareEnabled = enabled;
    }
    getTrackPublication() {
      return undefined;
    }
  }
  class Room {
    static rooms: Room[] = [];
    static slowGate: Promise<void> | null = null;
    static async getLocalDevices() {
      return [];
    }
    readonly localParticipant = new Participant();
    readonly remoteParticipants = new Map();
    readonly handlers = new Map<string, Array<(...args: never[]) => void>>();
    token = "";
    disconnected = false;
    constructor() {
      Room.rooms.push(this);
    }
    on(event: string, handler: (...args: never[]) => void) {
      const handlers = this.handlers.get(event) ?? [];
      handlers.push(handler);
      this.handlers.set(event, handlers);
      return this;
    }
    emit(event: string) {
      for (const handler of this.handlers.get(event) ?? []) handler();
    }
    async connect(_url: string, token: string) {
      this.token = token;
      if (token === "slow") await Room.slowGate;
      this.emit(events.Connected);
    }
    async disconnect() {
      this.disconnected = true;
      this.emit(events.Disconnected);
    }
    async startAudio() {}
    getActiveDevice() {
      return null;
    }
    async switchActiveDevice() {
      return true;
    }
  }
  return { events, Room, Worker };
});

vi.mock("livekit-client/e2ee-worker?worker", () => ({
  default: fake.Worker,
}));

vi.mock("livekit-client", () => ({
  ConnectionQuality: {
    Excellent: "excellent",
    Good: "good",
    Poor: "poor",
    Lost: "lost",
  },
  ExternalE2EEKeyProvider: class {
    async setKey() {}
  },
  Room: fake.Room,
  RoomEvent: fake.events,
  Track: {
    Kind: { Audio: "audio", Video: "video" },
    Source: { ScreenShare: "screen-share" },
  },
}));

import { VoiceClient } from "./voiceClient";

function grant(
  channelId: string,
  token: string,
  overrides: Partial<VoiceJoinGrant> = {},
): VoiceJoinGrant {
  return {
    channelId,
    guildId: "guild",
    roomName: channelId,
    serverUrl: "wss://voice.example.test",
    token,
    expiresAt: "2099-01-01T00:00:00Z",
    participantId: "local-member",
    participantName: "Local member",
    canSpeak: true,
    canStream: true,
    transportEncrypted: true,
    endToEndEncrypted: true,
    e2eeKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ...overrides,
  };
}

async function until(predicate: () => boolean) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not reached");
}

describe("real voice connection state machine", () => {
  it("keeps a newer room alive when an older join resolves late", async () => {
    fake.Room.rooms.length = 0;
    const client = new VoiceClient();
    let releaseSlow: () => void = () => {};
    const slowGate = new Promise<void>((resolve) => {
      releaseSlow = resolve;
    });
    fake.Room.slowGate = slowGate;

    const firstJoin = client.join(grant("first", "slow"));
    await until(() => fake.Room.rooms.length === 1);
    const secondJoin = client.join(grant("second", "fast"));
    await secondJoin;
    const secondRoom = fake.Room.rooms[1]!;
    expect(client.current()).toMatchObject({
      roomId: "second",
      status: "connected",
    });

    releaseSlow();
    await firstJoin;
    fake.Room.rooms[0]!.emit(fake.events.Disconnected);

    expect(client.current()).toMatchObject({
      roomId: "second",
      status: "connected",
    });
    expect(secondRoom.disconnected).toBe(false);
  });

  it("opens a real room muted for push-to-talk", async () => {
    fake.Room.rooms.length = 0;
    const client = new VoiceClient();
    await client.join(grant("ptt", "fast"), { startMuted: true });

    expect(fake.Room.rooms[0]!.localParticipant.isMicrophoneEnabled).toBe(false);
    expect(client.current()).toMatchObject({
      roomId: "ptt",
      status: "connected",
      muted: true,
    });
  });

  it("joins transport-only grants without requiring an E2EE key", async () => {
    fake.Room.rooms.length = 0;
    const client = new VoiceClient();
    await client.join(
      grant("transport-only", "fast", {
        endToEndEncrypted: false,
        e2eeKey: null,
      }),
    );

    expect(fake.Room.rooms).toHaveLength(1);
    expect(client.current()).toMatchObject({
      roomId: "transport-only",
      status: "connected",
      transportEncrypted: true,
      endToEndEncrypted: false,
      error: null,
    });
  });

  it("fails closed when E2EE is required but the grant omits a key", async () => {
    fake.Room.rooms.length = 0;
    const client = new VoiceClient();
    await expect(
      client.join(
        grant("e2ee-missing", "fast", {
          endToEndEncrypted: true,
          e2eeKey: null,
        }),
      ),
    ).rejects.toThrow(/end-to-end encryption key is unavailable/);

    expect(client.current()).toMatchObject({
      status: "failed",
      endToEndEncrypted: true,
    });
    expect(client.current().error).toMatch(/end-to-end encryption key/i);
  });

  it("surfaces an error when mute is toggled outside a connected room", async () => {
    const client = new VoiceClient();
    await expect(client.setMuted(true)).rejects.toThrow(
      /Join a voice room before changing your microphone/,
    );
  });

  it("reconnects an active room when MLS rotates the SFrame key", async () => {
    fake.Room.rooms.length = 0;
    const client = new VoiceClient();
    await client.join(grant("rotating", "first"));
    const firstRoom = fake.Room.rooms[0]!;

    await client.reauthorize(
      grant("rotating", "second", {
        e2eeKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      }),
    );

    expect(firstRoom.disconnected).toBe(true);
    expect(fake.Room.rooms).toHaveLength(2);
    expect(client.current()).toMatchObject({
      roomId: "rotating",
      status: "connected",
      endToEndEncrypted: true,
    });
  });

  it("serializes a quick press and release so the microphone ends muted", async () => {
    fake.Room.rooms.length = 0;
    const client = new VoiceClient();
    await client.join(grant("ptt", "fast"), { startMuted: true });
    let releaseMicrophone: () => void = () => {};
    fake.Room.rooms[0]!.localParticipant.microphoneGate = new Promise<void>(
      (resolve) => {
        releaseMicrophone = resolve;
      },
    );

    const press = client.setMuted(false);
    const release = client.setMuted(true);
    releaseMicrophone();
    await Promise.all([press, release]);

    expect(fake.Room.rooms[0]!.localParticipant.isMicrophoneEnabled).toBe(false);
    expect(client.current().muted).toBe(true);
  });
});
