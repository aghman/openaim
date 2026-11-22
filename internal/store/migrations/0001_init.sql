-- 0001: initial schema (M1). Times are unix milliseconds.

-- Small key/value facts about this installation (public identity key, …).
-- Secrets never go here: the identity seed lives in the keystore.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) WITHOUT ROWID;

CREATE TABLE buddies (
    id           INTEGER PRIMARY KEY,
    ed_key       BLOB    NOT NULL UNIQUE CHECK (length(ed_key) = 32),
    handle       TEXT,                      -- verified handle, if any
    petname      TEXT,
    group_name   TEXT    NOT NULL DEFAULT 'Buddies',
    state        TEXT    NOT NULL CHECK (state IN ('pending_out', 'pending_in', 'accepted', 'blocked')),
    verified     INTEGER NOT NULL DEFAULT 0, -- safety number or handle checked by the user
    recovery_key BLOB    CHECK (recovery_key IS NULL OR length(recovery_key) = 32),
    send_seq     INTEGER NOT NULL DEFAULT 0, -- last seq used on frames we sent
    added_at     INTEGER NOT NULL
);

-- Sealed outgoing messages. Seal once: the frames are written in the same
-- transaction that allocates the seq, before anything is sent, and are
-- never rewritten. Retries and fallbacks re-send these bytes.
CREATE TABLE outbox (
    id           INTEGER PRIMARY KEY,
    buddy_id     INTEGER NOT NULL REFERENCES buddies (id) ON DELETE CASCADE,
    conv_tag     BLOB    NOT NULL CHECK (length(conv_tag) = 8),
    msg_id       BLOB    NOT NULL CHECK (length(msg_id) = 8),
    layout       INTEGER NOT NULL,
    content_type INTEGER NOT NULL,
    seq          INTEGER NOT NULL,
    frag_count   INTEGER NOT NULL CHECK (frag_count BETWEEN 1 AND 16),
    state        TEXT    NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'acked', 'failed')),
    acked_mask   INTEGER NOT NULL DEFAULT 0,
    attempts     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_attempt INTEGER,
    UNIQUE (conv_tag, msg_id),
    UNIQUE (buddy_id, seq)
);
CREATE INDEX outbox_pending ON outbox (buddy_id, state, id);

CREATE TABLE outbox_frames (
    outbox_id INTEGER NOT NULL REFERENCES outbox (id) ON DELETE CASCADE,
    idx       INTEGER NOT NULL,
    frame     BLOB    NOT NULL,
    PRIMARY KEY (outbox_id, idx)
) WITHOUT ROWID;

-- Messages received and delivered (chat history).
CREATE TABLE inbox (
    id           INTEGER PRIMARY KEY,
    buddy_id     INTEGER NOT NULL REFERENCES buddies (id) ON DELETE CASCADE,
    conv_tag     BLOB    NOT NULL,
    msg_id       BLOB    NOT NULL,
    content_type INTEGER NOT NULL,
    flags        INTEGER NOT NULL,
    sent_ts      INTEGER NOT NULL, -- inner timestamp, seconds since the OpenAIM epoch
    seq          INTEGER NOT NULL,
    body         BLOB    NOT NULL,
    received_at  INTEGER NOT NULL,
    UNIQUE (conv_tag, msg_id)
);
CREATE INDEX inbox_by_buddy ON inbox (buddy_id, received_at);

-- Fragment dedup (design §8.9): (conv_tag, msg_id, frag) for 30 days.
CREATE TABLE dedup (
    conv_tag BLOB    NOT NULL,
    msg_id   BLOB    NOT NULL,
    frag     INTEGER NOT NULL,
    seen_at  INTEGER NOT NULL,
    PRIMARY KEY (conv_tag, msg_id, frag)
) WITHOUT ROWID;
CREATE INDEX dedup_seen ON dedup (seen_at);
