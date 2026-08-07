import { afterEach, describe, expect, it } from "vitest";
import type { VoiceJoinGrant } from "./models";
import { voiceClient } from "./voiceClient";

const grant = (
  overrides: Partial<VoiceJoinGrant> = {},
): VoiceJoinGrant => ({
  channelId: "voice-test",
  guildId: "guild-test",
  roomName: "exo-guild-test-voice-voice-test",
  serverUrl: "ws://127.0.0.1:7880",
  token: "preview-token",
  expiresAt: "2099-01-01T00:00:00Z",
  participantId: "member-test",
  participantName: "Test member",
  canSpeak: true,
  canStream: true,
  transportEncrypted: true,
  endToEndEncrypted: false,
  preview: true,
  previewParticipants: [
    {
      memberId: "member-test",
      displayName: "Test member",
      state: "idle",
      note: "you",
      isLocal: true,
      connectionQuality: "excellent",
    },
  ],
  ...overrides,
});

afterEach(async () => {
  await voiceClient.leave();
});

describe("voice client media state", () => {
  it("joins and leaves a preview voice session", async () => {
    await voiceClient.join(grant());

    expect(voiceClient.current()).toMatchObject({
      roomId: "voice-test",
      status: "connected",
      canSpeak: true,
      canStream: true,
      transportEncrypted: true,
      endToEndEncrypted: false,
    });

    await voiceClient.leave();
    expect(voiceClient.current()).toMatchObject({
      roomId: null,
      status: "idle",
      participants: [],
    });
  });

  it("restores the microphone state after undeafening", async () => {
    await voiceClient.join(grant());
    await voiceClient.setMuted(false);
    await voiceClient.setDeafened(true);
    expect(voiceClient.current()).toMatchObject({
      deafened: true,
      muted: true,
      participants: [
        {
          state: "muted",
          note: "muted",
        },
      ],
    });

    await voiceClient.setDeafened(false);
    expect(voiceClient.current()).toMatchObject({
      deafened: false,
      muted: false,
      participants: [
        {
          state: "idle",
          note: "you",
        },
      ],
    });
  });

  it("preserves a deliberately muted microphone across deafen", async () => {
    await voiceClient.join(grant());
    await voiceClient.setMuted(true);
    await voiceClient.setDeafened(true);
    await voiceClient.setDeafened(false);

    expect(voiceClient.current()).toMatchObject({
      deafened: false,
      muted: true,
    });
  });

  it("stops newly forbidden media when permissions shrink", async () => {
    await voiceClient.join(grant());
    await voiceClient.setScreenSharing(true);
    expect(voiceClient.current()).toMatchObject({
      sharing: true,
      participants: [
        {
          screenSharing: true,
          note: "you · sharing",
        },
      ],
    });
    await voiceClient.reauthorize(
      grant({
        canSpeak: false,
        canStream: false,
      }),
    );

    expect(voiceClient.current()).toMatchObject({
      canSpeak: false,
      canStream: false,
      muted: true,
      sharing: false,
    });
    await expect(voiceClient.setMuted(false)).rejects.toThrow(
      "permission to speak",
    );
    await expect(voiceClient.setScreenSharing(true)).rejects.toThrow(
      "permission to share",
    );
  });

  it("exposes preview input and output devices", async () => {
    await voiceClient.join(grant());
    const devices = await voiceClient.devices();

    expect(devices.inputs[0]?.deviceId).toBe("preview-mic");
    expect(devices.outputs[0]?.deviceId).toBe("preview-speakers");
  });
});
