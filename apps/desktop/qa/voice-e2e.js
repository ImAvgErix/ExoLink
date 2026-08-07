import { Room, RoomEvent, Track } from "livekit-client";

const api = new URLSearchParams(location.search).get("api")
  ?? "http://127.0.0.1:4188";
const summary = document.querySelector("#summary");
const steps = document.querySelector("#steps");
const results = [];

window.__voiceQa = {
  state: "running",
  results,
};

function record(name, passed, detail = "") {
  const result = { name, passed, detail };
  results.push(result);
  const item = document.createElement("li");
  item.dataset.state = passed ? "passed" : "failed";
  item.textContent = `${passed ? "✓" : "×"} ${name}${detail ? ` — ${detail}` : ""}`;
  steps.append(item);
  if (!passed) throw new Error(`${name}: ${detail || "failed"}`);
}

async function request(path, options = {}) {
  const response = await fetch(`${api}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${options.method ?? "GET"} ${path} returned ${response.status}: ${body}`);
  }
  if (response.status === 204) return null;
  return response.json();
}

function waitUntil(predicate, description, timeoutMs = 12_000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      if (predicate()) {
        resolve();
      } else if (Date.now() - started >= timeoutMs) {
        reject(new Error(`Timed out waiting for ${description}`));
      } else {
        setTimeout(check, 50);
      }
    };
    check();
  });
}

function artificialAudio() {
  const context = new AudioContext();
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  const destination = context.createMediaStreamDestination();
  oscillator.frequency.value = 220;
  gain.gain.value = 0.02;
  oscillator.connect(gain).connect(destination);
  oscillator.start();
  return {
    context,
    oscillator,
    track: destination.stream.getAudioTracks()[0],
  };
}

function artificialVideo() {
  const canvas = document.createElement("canvas");
  canvas.width = 640;
  canvas.height = 360;
  const context = canvas.getContext("2d");
  let frame = 0;
  const paint = () => {
    context.fillStyle = "#11141b";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = "#8b7cff";
    context.fillRect(52, 50, 12 + (frame % 520), 6);
    context.font = "600 32px system-ui";
    context.fillText("Exocord screen share QA", 128, 190);
    frame += 1;
  };
  paint();
  const interval = setInterval(paint, 100);
  const stream = canvas.captureStream(8);
  return {
    canvas,
    stop: () => clearInterval(interval),
    track: stream.getVideoTracks()[0],
  };
}

async function createMember(label) {
  const email = `voice-qa-${label}-${Date.now()}@example.test`;
  const challenge = await request("/v1/auth/email/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  return request("/v1/auth/email/verify", {
    method: "POST",
    body: JSON.stringify({
      challengeId: challenge.challengeId,
      code: challenge.developmentCode,
      deviceId: `voice-qa-${label}-${Date.now()}`,
      clientName: "Exocord voice QA",
    }),
  });
}

async function addMemberToVoice(guild, voice, session, ownerHeaders) {
  const memberHeaders = { authorization: `Bearer ${session.accessToken}` };
  const invite = await request(`/v1/guilds/${guild.id}/invites`, {
    method: "POST",
    headers: ownerHeaders,
    body: JSON.stringify({ maxUses: 1, expiresInSeconds: 600 }),
  });
  await request(`/v1/invites/${invite.code}`, {
    method: "POST",
    headers: memberHeaders,
  });
  const grant = await request(
    `/v1/channels/${voice.id}/voice-token`,
    { method: "POST", headers: memberHeaders },
  );
  return { grant, headers: memberHeaders };
}

async function run() {
  const ownerHeaders = { "x-exocord-user-id": "1" };
  let roomA;
  let roomB;
  let roomC;
  let audio;
  let video;
  try {
    const sync = await request("/v1/sync", { headers: ownerHeaders });
    const guild = sync.guilds[0];
    const voice = sync.channels.find((channel) => channel.kind === "voice");
    record("Owner and voice room are available", Boolean(guild && voice));

    const ownerGrant = await request(
      `/v1/channels/${voice.id}/voice-token`,
      { method: "POST", headers: ownerHeaders },
    );
    record(
      "Owner receives a transport-encrypted scoped grant",
      ownerGrant.transportEncrypted === true
        && ownerGrant.endToEndEncrypted === false
        && ownerGrant.roomName.includes(voice.id),
      ownerGrant.roomName,
    );

    const session = await createMember("logout");
    record(
      "Second member signs in through the email flow",
      Boolean(session.user?.id && session.accessToken),
      session.user.id,
    );

    const {
      grant: memberGrant,
      headers: memberHeaders,
    } = await addMemberToVoice(
      guild,
      voice,
      session,
      ownerHeaders,
    );
    record(
      "Invite membership authorizes the exact same room",
      memberGrant.roomName === ownerGrant.roomName
        && memberGrant.participantId === session.user.id,
    );

    const subscribed = [];
    roomA = new Room({ adaptiveStream: true, dynacast: true });
    roomB = new Room({ adaptiveStream: true, dynacast: true });
    roomB.on(RoomEvent.TrackSubscribed, (track, publication, participant) => {
      subscribed.push({
        kind: track.kind,
        source: publication.source,
        participant: participant.identity,
      });
    });
    await Promise.all([
      roomA.connect(ownerGrant.serverUrl, ownerGrant.token),
      roomB.connect(memberGrant.serverUrl, memberGrant.token),
    ]);
    await waitUntil(
      () => roomA.remoteParticipants.size === 1
        && roomB.remoteParticipants.size === 1,
      "both participants to discover each other",
    );
    record(
      "Two authenticated members connect through the SFU",
      roomA.remoteParticipants.has(session.user.id)
        && roomB.remoteParticipants.has("1"),
    );

    audio = artificialAudio();
    await roomA.localParticipant.publishTrack(audio.track, {
      name: "synthetic-microphone",
      source: Track.Source.Microphone,
    });
    await waitUntil(
      () => subscribed.some(
        (track) => track.kind === Track.Kind.Audio
          && track.source === Track.Source.Microphone,
      ),
      "the remote microphone subscription",
    );
    record(
      "Microphone media publishes and subscribes",
      subscribed.some((track) => track.source === Track.Source.Microphone),
    );

    video = artificialVideo();
    await roomA.localParticipant.publishTrack(video.track, {
      name: "synthetic-screen",
      source: Track.Source.ScreenShare,
    });
    await waitUntil(
      () => subscribed.some(
        (track) => track.kind === Track.Kind.Video
          && track.source === Track.Source.ScreenShare,
      ),
      "the remote screen-share subscription",
    );
    record(
      "Screen-share media publishes and subscribes",
      subscribed.some((track) => track.source === Track.Source.ScreenShare),
    );

    let loggedOut = false;
    roomB.on(RoomEvent.Disconnected, () => {
      loggedOut = true;
    });
    await request("/v1/auth/logout", {
      method: "POST",
      headers: memberHeaders,
    });
    await waitUntil(() => loggedOut, "logout eviction");
    record("Signing out forcibly evicts the active media session", loggedOut);

    const loggedOutGrant = await fetch(
      `${api}/v1/channels/${voice.id}/voice-token`,
      { method: "POST", headers: memberHeaders },
    );
    record(
      "A signed-out session cannot mint another grant",
      loggedOutGrant.status === 401,
      `HTTP ${loggedOutGrant.status}`,
    );

    const moderatedSession = await createMember("moderated");
    const {
      grant: moderatedGrant,
      headers: moderatedHeaders,
    } = await addMemberToVoice(
      guild,
      voice,
      moderatedSession,
      ownerHeaders,
    );
    roomC = new Room({ adaptiveStream: true, dynacast: true });
    await roomC.connect(moderatedGrant.serverUrl, moderatedGrant.token);
    await waitUntil(
      () => roomA.remoteParticipants.has(moderatedSession.user.id)
        && roomC.remoteParticipants.has("1"),
      "the moderated member to join",
    );
    record(
      "A newly invited member can join after the logout check",
      roomC.remoteParticipants.has("1"),
      moderatedSession.user.id,
    );

    let removed = false;
    roomC.on(RoomEvent.Disconnected, () => {
      removed = true;
    });
    await request(
      `/v1/guilds/${guild.id}/members/${moderatedSession.user.id}`,
      {
        method: "PATCH",
        headers: ownerHeaders,
        body: JSON.stringify({
          timeoutSeconds: 300,
          reason: "automated voice authorization check",
        }),
      },
    );
    await waitUntil(() => removed, "moderation eviction");
    record("A timeout forcibly evicts the active media session", removed);

    const rejected = await fetch(
      `${api}/v1/channels/${voice.id}/voice-token`,
      { method: "POST", headers: moderatedHeaders },
    );
    record(
      "A timed-out member cannot mint a replacement grant",
      rejected.status === 403 || rejected.status === 404,
      `HTTP ${rejected.status}`,
    );

    window.__voiceQa.state = "passed";
    summary.dataset.state = "passed";
    summary.textContent = `Passed ${results.length}/${results.length} checks`;
  } catch (error) {
    window.__voiceQa.state = "failed";
    window.__voiceQa.error = error instanceof Error ? error.message : String(error);
    summary.dataset.state = "failed";
    summary.textContent = `Failed: ${window.__voiceQa.error}`;
  } finally {
    await roomA?.disconnect(true).catch(() => undefined);
    await roomB?.disconnect(true).catch(() => undefined);
    await roomC?.disconnect(true).catch(() => undefined);
    audio?.oscillator.stop();
    await audio?.context.close().catch(() => undefined);
    audio?.track.stop();
    video?.stop();
    video?.track.stop();
  }
}

void run();
