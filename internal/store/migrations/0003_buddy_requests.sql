-- 0003: buddy requests and accepts (design §5.4, spec/wire.md §11).
-- Times are unix milliseconds unless noted.

-- Requests we sent: sealed FIRST_CONTACT frames, kept apart from the outbox.
-- A first contact has no conversation tag (its frames carry e ‖ msg_id) and
-- is addressed to a key through a contact hint, not to a buddy's
-- conversation, so outbox's (conv_tag, msg_id, buddy seq) keys don't fit.
-- Seal once, as for the outbox: the frames are written before anything is
-- sent and are never rewritten; retries re-send these bytes. Sealing again
-- (a new e) makes a new, unlinkable request: a new row.
CREATE TABLE request_out (
    id           INTEGER PRIMARY KEY,
    buddy_id     INTEGER NOT NULL REFERENCES buddies (id) ON DELETE CASCADE,
    e            BLOB    NOT NULL CHECK (length(e) = 32),
    msg_id       BLOB    NOT NULL CHECK (length(msg_id) = 8),
    layout       INTEGER NOT NULL,
    frag_count   INTEGER NOT NULL CHECK (frag_count BETWEEN 1 AND 2),
    contact_hint TEXT,               -- multiaddr text, or NULL if none known
    sent_ts      INTEGER NOT NULL,   -- inner timestamp, seconds since the OpenAIM epoch
    state        TEXT    NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'sent', 'answered', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_attempt INTEGER,
    last_error   TEXT,
    UNIQUE (e, msg_id)
);
CREATE INDEX request_out_by_buddy ON request_out (buddy_id, state);

CREATE TABLE request_out_frames (
    request_id INTEGER NOT NULL REFERENCES request_out (id) ON DELETE CASCADE,
    idx        INTEGER NOT NULL,
    frame      BLOB    NOT NULL,
    PRIMARY KEY (request_id, idx)
) WITHOUT ROWID;

-- Requests we received, one row per requester: repeat requests from the
-- same key are merged into it. Everything here came from an authenticated
-- BUDDY_REQUEST, but is the requester's own claim (shown as unverified).
CREATE TABLE request_in (
    buddy_id     INTEGER PRIMARY KEY REFERENCES buddies (id) ON DELETE CASCADE,
    display_name TEXT    NOT NULL DEFAULT '',
    greeting     TEXT    NOT NULL DEFAULT '',
    sent_ts      INTEGER NOT NULL, -- latest request's inner timestamp (OpenAIM-epoch seconds)
    first_at     INTEGER NOT NULL,
    last_at      INTEGER NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1,
    transport    TEXT    NOT NULL DEFAULT ''
);

-- What a buddy told us about themselves, only ever from authenticated frame
-- content (design §7.1): their presence key and display name from
-- BUDDY_ACCEPT, and their reachability from REACH in a BUDDY_REQUEST or
-- BUDDY_ACCEPT. A REACH with a lower seq than the one held, or already
-- expired, is ignored.
CREATE TABLE buddy_peer (
    buddy_id      INTEGER PRIMARY KEY REFERENCES buddies (id) ON DELETE CASCADE,
    display_name  TEXT    NOT NULL DEFAULT '',
    presence_key  BLOB    CHECK (presence_key IS NULL OR length(presence_key) = 32),
    reach         BLOB,    -- REACH protobuf
    reach_seq     INTEGER,
    reach_expires INTEGER, -- OpenAIM-epoch seconds
    caps          BLOB,    -- CAPS protobuf
    accepted_at   INTEGER, -- when their BUDDY_ACCEPT arrived
    updated_at    INTEGER NOT NULL
);
