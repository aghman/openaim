-- 0004: a deterministic conversation order (openaim-nxb.37).
--
-- Chat history merges the inbox and the outbox. Their timestamps have
-- millisecond resolution, so two messages stored in the same millisecond
-- sorted either way. Every row of either table now gets `ord`, the next
-- value of one counter shared by both, at insert time: history is ordered
-- by insertion into this store, ties impossible. Triggers assign it, so
-- every writer gets it without knowing about it.

ALTER TABLE inbox ADD COLUMN ord INTEGER;
ALTER TABLE outbox ADD COLUMN ord INTEGER;

-- One row: the last ord handed out.
CREATE TABLE history_seq (
    n INTEGER NOT NULL
);

-- Existing rows: by store time, outgoing before incoming on a tie (the old
-- order sorted outgoing first too, in practice), then by row id.
WITH rows_ AS (
    SELECT 0 AS dir, id, created_at AS t FROM outbox
    UNION ALL
    SELECT 1 AS dir, id, received_at AS t FROM inbox
), numbered AS (
    SELECT dir, id, row_number() OVER (ORDER BY t, dir, id) AS r FROM rows_
)
UPDATE outbox SET ord = (SELECT r FROM numbered WHERE dir = 0 AND numbered.id = outbox.id);

WITH rows_ AS (
    SELECT 0 AS dir, id, created_at AS t FROM outbox
    UNION ALL
    SELECT 1 AS dir, id, received_at AS t FROM inbox
), numbered AS (
    SELECT dir, id, row_number() OVER (ORDER BY t, dir, id) AS r FROM rows_
)
UPDATE inbox SET ord = (SELECT r FROM numbered WHERE dir = 1 AND numbered.id = inbox.id);

INSERT INTO history_seq (n) SELECT (SELECT count(*) FROM inbox) + (SELECT count(*) FROM outbox);

CREATE TRIGGER inbox_ord AFTER INSERT ON inbox BEGIN
    UPDATE history_seq SET n = n + 1;
    UPDATE inbox SET ord = (SELECT n FROM history_seq) WHERE id = NEW.id;
END;

CREATE TRIGGER outbox_ord AFTER INSERT ON outbox BEGIN
    UPDATE history_seq SET n = n + 1;
    UPDATE outbox SET ord = (SELECT n FROM history_seq) WHERE id = NEW.id;
END;

CREATE INDEX inbox_by_ord ON inbox (buddy_id, ord);
CREATE INDEX outbox_by_ord ON outbox (buddy_id, ord);
