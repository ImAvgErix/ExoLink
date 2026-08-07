use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE_WINDOW: usize = 100;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowState {
    Sent,
    Pending,
    Failed,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MessageNode {
    Text(String),
    Mention { id: String, label: String },
    Link { href: String, label: String },
    Code(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachmentView {
    pub id: String,
    pub filename: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub thumbnail_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReactionView {
    pub emoji: String,
    pub count: u32,
    pub selected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplyPreview {
    pub author_name: String,
    pub content_label: String,
}

/// A render-ready row. Domain entities and caches never cross the UI boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MessageRow {
    pub id: String,
    pub client_key: String,
    pub group_start: bool,
    pub author_name: String,
    pub author_color: u32,
    pub avatar_url: Option<String>,
    pub timestamp_label: String,
    pub content_ast: Vec<MessageNode>,
    pub attachments: Vec<AttachmentView>,
    pub reactions: Vec<ReactionView>,
    pub state: RowState,
    pub edited: bool,
    pub reply: Option<ReplyPreview>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Offline,
    Connecting,
    Resuming,
    Connected,
    CatchingUp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Delta {
    MessageAppend(MessageRow),
    MessageUpdate {
        id: String,
        row: MessageRow,
    },
    MessageRemove {
        id: String,
    },
    WindowShift {
        dropped_head: u32,
        dropped_tail: u32,
    },
    ChannelUnread {
        channel_id: String,
        count: u32,
        mentions: u32,
    },
    PresenceBatch(Vec<String>),
    TypingSet {
        channel_id: String,
        users: Vec<String>,
    },
    ConnectionState(ConnectionState),
}
