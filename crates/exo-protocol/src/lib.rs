use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const PROTOCOL_VERSION: u8 = 1;
pub const BASE_HEADER_LEN: usize = 8;
pub const ROUTED_HEADER_LEN: usize = 24;
pub const COMPRESSION_THRESHOLD: usize = 128;

const FLAG_COMPRESSED: u8 = 1 << 0;
const FLAG_DICTIONARY: u8 = 1 << 1;
const FLAG_REPLAYED: u8 = 1 << 2;
const FLAG_ROUTING: u8 = 1 << 3;
const KNOWN_FLAGS: u8 = FLAG_COMPRESSED | FLAG_DICTIONARY | FLAG_REPLAYED | FLAG_ROUTING;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EventType {
    Ready = 1,
    Resumed = 2,
    SessionReplaced = 3,
    UserUpdate = 10,
    UserSettingsUpdate = 11,
    GuildCreate = 100,
    GuildUpdate = 101,
    GuildDelete = 102,
    GuildEmojiUpdate = 110,
    GuildMembersChunk = 120,
    ChannelCreate = 200,
    ChannelUpdate = 201,
    ChannelDelete = 202,
    ChannelPinsUpdate = 210,
    ChannelCategoryReorder = 220,
    MessageCreate = 300,
    MessageUpdate = 301,
    MessageDelete = 302,
    MessageDeleteBulk = 303,
    MessageAck = 310,
    MessageEmbedUpdate = 320,
    ReactionAdd = 400,
    ReactionRemove = 401,
    PresenceUpdate = 600,
    TypingStart = 610,
    VoiceStateUpdate = 700,
    VoiceServerUpdate = 701,
    VoiceSpeaking = 710,
    RelationshipUpdate = 800,
    DirectChannelCreate = 810,
    ReadStateUpdate = 820,
    MlsWelcome = 1100,
    MlsCommit = 1101,
    MlsProposal = 1102,
    MlsKeyPackageConsumed = 1110,
    E2eeChannelEnabled = 1120,
}

impl TryFrom<u16> for EventType {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Resumed),
            3 => Ok(Self::SessionReplaced),
            10 => Ok(Self::UserUpdate),
            11 => Ok(Self::UserSettingsUpdate),
            100 => Ok(Self::GuildCreate),
            101 => Ok(Self::GuildUpdate),
            102 => Ok(Self::GuildDelete),
            110 => Ok(Self::GuildEmojiUpdate),
            120 => Ok(Self::GuildMembersChunk),
            200 => Ok(Self::ChannelCreate),
            201 => Ok(Self::ChannelUpdate),
            202 => Ok(Self::ChannelDelete),
            210 => Ok(Self::ChannelPinsUpdate),
            220 => Ok(Self::ChannelCategoryReorder),
            300 => Ok(Self::MessageCreate),
            301 => Ok(Self::MessageUpdate),
            302 => Ok(Self::MessageDelete),
            303 => Ok(Self::MessageDeleteBulk),
            310 => Ok(Self::MessageAck),
            320 => Ok(Self::MessageEmbedUpdate),
            400 => Ok(Self::ReactionAdd),
            401 => Ok(Self::ReactionRemove),
            600 => Ok(Self::PresenceUpdate),
            610 => Ok(Self::TypingStart),
            700 => Ok(Self::VoiceStateUpdate),
            701 => Ok(Self::VoiceServerUpdate),
            710 => Ok(Self::VoiceSpeaking),
            800 => Ok(Self::RelationshipUpdate),
            810 => Ok(Self::DirectChannelCreate),
            820 => Ok(Self::ReadStateUpdate),
            1100 => Ok(Self::MlsWelcome),
            1101 => Ok(Self::MlsCommit),
            1102 => Ok(Self::MlsProposal),
            1110 => Ok(Self::MlsKeyPackageConsumed),
            1120 => Ok(Self::E2eeChannelEnabled),
            other => Err(ProtocolError::UnknownEvent(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingMetadata {
    pub guild_id: u64,
    pub channel_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub version: u8,
    pub compressed: bool,
    pub dictionary: bool,
    pub replayed: bool,
    pub event_type: EventType,
    pub sequence: u32,
    pub routing: Option<RoutingMetadata>,
}

impl FrameHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::decode_with_len(bytes).map(|(header, _)| header)
    }

    fn decode_with_len(bytes: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if bytes.len() < BASE_HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader {
                expected: BASE_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let flags = bytes[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(ProtocolError::ReservedFlags(flags));
        }
        let has_routing = flags & FLAG_ROUTING != 0;
        let header_len = if has_routing {
            ROUTED_HEADER_LEN
        } else {
            BASE_HEADER_LEN
        };
        if bytes.len() < header_len {
            return Err(ProtocolError::TruncatedHeader {
                expected: header_len,
                actual: bytes.len(),
            });
        }
        let mut sequence = [0_u8; 4];
        sequence.copy_from_slice(&bytes[4..8]);
        let routing = if has_routing {
            let mut guild_id = [0_u8; 8];
            guild_id.copy_from_slice(&bytes[8..16]);
            let mut channel_id = [0_u8; 8];
            channel_id.copy_from_slice(&bytes[16..24]);
            Some(RoutingMetadata {
                guild_id: u64::from_le_bytes(guild_id),
                channel_id: u64::from_le_bytes(channel_id),
            })
        } else {
            None
        };

        Ok((
            Self {
                version,
                compressed: flags & FLAG_COMPRESSED != 0,
                dictionary: flags & FLAG_DICTIONARY != 0,
                replayed: flags & FLAG_REPLAYED != 0,
                event_type: EventType::try_from(u16::from_le_bytes([bytes[2], bytes[3]]))?,
                sequence: u32::from_le_bytes(sequence),
                routing,
            },
            header_len,
        ))
    }

    fn append_to(self, output: &mut Vec<u8>) {
        let mut flags = 0;
        if self.compressed {
            flags |= FLAG_COMPRESSED;
        }
        if self.dictionary {
            flags |= FLAG_DICTIONARY;
        }
        if self.replayed {
            flags |= FLAG_REPLAYED;
        }
        if self.routing.is_some() {
            flags |= FLAG_ROUTING;
        }

        output.push(self.version);
        output.push(flags);
        output.extend_from_slice(&(self.event_type as u16).to_le_bytes());
        output.extend_from_slice(&self.sequence.to_le_bytes());
        if let Some(routing) = self.routing {
            output.extend_from_slice(&routing.guild_id.to_le_bytes());
            output.extend_from_slice(&routing.channel_id.to_le_bytes());
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReadyPayload {
    pub session_id: String,
    pub heartbeat_interval_ms: u32,
    pub resume_gateway_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame header is truncated: expected {expected} bytes, received {actual}")]
    TruncatedHeader { expected: usize, actual: usize },
    #[error("protocol version {0} is not supported")]
    UnsupportedVersion(u8),
    #[error("frame uses reserved flag bits: {0:#010b}")]
    ReservedFlags(u8),
    #[error("event type {0} is unknown")]
    UnknownEvent(u16),
    #[error("MessagePack encode failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("MessagePack decode failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("zstd failed: {0}")]
    Compression(#[from] std::io::Error),
}

pub fn encode_frame<T: Serialize>(
    event_type: EventType,
    sequence: u32,
    payload: &T,
) -> Result<Vec<u8>, ProtocolError> {
    encode_frame_with_routing(event_type, sequence, None, payload)
}

pub fn encode_routed_frame<T: Serialize>(
    event_type: EventType,
    sequence: u32,
    routing: RoutingMetadata,
    payload: &T,
) -> Result<Vec<u8>, ProtocolError> {
    encode_frame_with_routing(event_type, sequence, Some(routing), payload)
}

fn encode_frame_with_routing<T: Serialize>(
    event_type: EventType,
    sequence: u32,
    routing: Option<RoutingMetadata>,
    payload: &T,
) -> Result<Vec<u8>, ProtocolError> {
    let encoded = rmp_serde::to_vec(payload)?;
    let (payload, compressed) = if encoded.len() >= COMPRESSION_THRESHOLD {
        (zstd::stream::encode_all(encoded.as_slice(), 3)?, true)
    } else {
        (encoded, false)
    };
    let header = FrameHeader {
        version: PROTOCOL_VERSION,
        compressed,
        dictionary: false,
        replayed: false,
        event_type,
        sequence,
        routing,
    };
    let header_len = if routing.is_some() {
        ROUTED_HEADER_LEN
    } else {
        BASE_HEADER_LEN
    };
    let mut frame = Vec::with_capacity(header_len + payload.len());
    header.append_to(&mut frame);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<(FrameHeader, T), ProtocolError> {
    let (header, header_len) = FrameHeader::decode_with_len(frame)?;
    let payload = &frame[header_len..];
    let decoded = if header.compressed {
        zstd::stream::decode_all(payload)?
    } else {
        payload.to_vec()
    };
    Ok((header, rmp_serde::from_slice(&decoded)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Example {
        value: String,
    }

    #[test]
    fn small_frames_use_the_fixed_eight_byte_little_endian_header() {
        let expected = Example {
            value: "hello".into(),
        };
        let frame = encode_frame(EventType::MessageCreate, 0x0102_0304, &expected).unwrap();
        let (header, actual): (_, Example) = decode_frame(&frame).unwrap();

        assert_eq!(&frame[2..4], &300_u16.to_le_bytes());
        assert_eq!(&frame[4..8], &0x0102_0304_u32.to_le_bytes());
        assert_eq!(header.event_type, EventType::MessageCreate);
        assert!(!header.compressed);
        assert_eq!(actual, expected);
    }

    #[test]
    fn large_frames_are_independently_compressed() {
        let expected = Example {
            value: "compress me ".repeat(200),
        };
        let frame = encode_frame(EventType::Ready, 7, &expected).unwrap();
        let (header, actual): (_, Example) = decode_frame(&frame).unwrap();

        assert!(header.compressed);
        assert_eq!(actual, expected);
    }

    #[test]
    fn routing_metadata_is_read_without_decoding_payload() {
        let routing = RoutingMetadata {
            guild_id: 42,
            channel_id: 91,
        };
        let frame = encode_routed_frame(EventType::TypingStart, 8, routing, &"opaque").unwrap();
        let header = FrameHeader::decode(&frame).unwrap();
        assert_eq!(
            frame.len() - rmp_serde::to_vec(&"opaque").unwrap().len(),
            24
        );
        assert_eq!(header.routing, Some(routing));
    }

    #[test]
    fn reserved_flag_bits_are_rejected() {
        let mut frame = encode_frame(EventType::Ready, 1, &()).unwrap();
        frame[1] |= 1 << 7;
        assert!(matches!(
            FrameHeader::decode(&frame),
            Err(ProtocolError::ReservedFlags(_))
        ));
    }
}
