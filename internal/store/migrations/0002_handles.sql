-- 0002: handle re-check state (design §5.3 rules 4-5, spec/handle.md §7).
-- Times are unix milliseconds.
--
-- One row per buddy whose handle has been checked. The buddy's handle lives
-- in buddies.handle and its pinned key in buddies.ed_key; nothing here ever
-- replaces either. A buddy with a handle but no row here has never been
-- checked and is due at once.
CREATE TABLE handle_checks (
    buddy_id    INTEGER PRIMARY KEY REFERENCES buddies (id) ON DELETE CASCADE,
    -- What the buddy list shows: the last conclusive outcome. An
    -- unreachable check keeps the previous status (NULL: never conclusive).
    status      TEXT CHECK (status IS NULL OR status IN ('verified', 'moved', 'unverified')),
    -- The outcome of the most recent check, unreachable included.
    last_result TEXT    NOT NULL CHECK (last_result IN ('verified', 'moved', 'unverified', 'unreachable')),
    checked_at  INTEGER NOT NULL, -- most recent check
    verified_at INTEGER,          -- most recent check that verified
    next_check  INTEGER NOT NULL,
    -- The key the handle points to now, while status is 'moved'. For
    -- display only: the pin stays buddies.ed_key.
    moved_key   BLOB CHECK (moved_key IS NULL OR length(moved_key) = 32),
    -- The inbox hint from the last verified record, for first contact.
    inbox_hint  TEXT,
    -- Why the most recent check didn't verify, or NULL.
    error       TEXT
);
CREATE INDEX handle_checks_due ON handle_checks (next_check);
