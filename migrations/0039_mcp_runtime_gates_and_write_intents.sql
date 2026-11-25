-- V1-14 PR3: database-backed worker rollout gate and terminal write-intent invariant trigger.
CREATE TABLE openmettle.runtime_feature_gates (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false
);
INSERT INTO openmettle.runtime_feature_gates (id, two_phase_effect_intents_enabled)
VALUES (
    true,
    coalesce(pg_catalog.current_setting('openmettle.bootstrap_from_zero', true), 'false') = 'true'
);
GRANT SELECT ON openmettle.runtime_feature_gates TO openmettle_api, openmettle_worker;

-- Defense-in-depth terminal write-intent guard and fallback resolution (ADR 0039 PR3).
-- The caller holds the run lock. Frame observations identically to runs::record_observation.
CREATE FUNCTION openmettle.resolve_terminal_write_intents() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    op uuid;
    k text;
    seq bigint;
    frame bytea;
    field bytea;
    fmt constant text := 'openmettle.unresolved-write';
    observed constant bytea := convert_to('{"reason":"unresolved_write_intent"}','UTF8');
BEGIN
    IF NEW.state = 'succeeded' THEN
        IF EXISTS (
            SELECT 1 FROM openmettle.operations o
             WHERE o.scope_id = NEW.scope_id
               AND o.run_id = NEW.id
               AND o.capability IN ('idempotent', 'lookup', 'non_repeatable')
               AND o.outcome IN ('intent', 'outcome_unknown')
        ) THEN
            RAISE EXCEPTION 'cannot settle run succeeded with unresolved write operation'
                USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;

    FOR op IN
        SELECT o.id FROM openmettle.operations o
         WHERE o.scope_id = NEW.scope_id
           AND o.run_id = NEW.id
           AND o.capability IN ('idempotent', 'lookup', 'non_repeatable')
           AND o.outcome = 'intent'
           AND o.revision = 0
         ORDER BY o.id
         FOR UPDATE
    LOOP
        UPDATE openmettle.operations
           SET outcome = 'outcome_unknown',
               revision = 1,
               observation_format = fmt,
               observation_version = 1,
               evidence = observed
         WHERE id = op;
        k := 'unresolved-write:' || op::text;
        frame := convert_to('openmettle/observation/1','UTF8') || decode('00','hex');
        FOREACH field IN ARRAY ARRAY[
            convert_to(NEW.scope_id::text,'UTF8'),
            convert_to(NEW.id::text,'UTF8'),
            convert_to(op::text,'UTF8'),
            convert_to(k,'UTF8'),
            int8send(0),
            convert_to('outcome_unknown','UTF8'),
            decode('00','hex'),
            ''::bytea,
            convert_to(fmt,'UTF8'),
            int4send(1),
            observed
        ]
        LOOP
            frame := frame || int8send(octet_length(field)::bigint) || field;
        END LOOP;
        UPDATE openmettle.runs
           SET last_event_sequence = last_event_sequence + 1
         WHERE id = NEW.id AND scope_id = NEW.scope_id
        RETURNING last_event_sequence INTO STRICT seq;
        INSERT INTO openmettle.run_events(
            scope_id, run_id, sequence, append_key, format, format_version, payload, identity, digest
        ) VALUES (
            NEW.scope_id, NEW.id, seq, k, fmt, 1, observed, frame, sha256(frame)
        );
    END LOOP;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.resolve_terminal_write_intents() FROM PUBLIC;
CREATE TRIGGER resolve_terminal_write_intents AFTER UPDATE OF state ON openmettle.runs
    FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state
        AND OLD.state NOT IN ('succeeded','failed','cancelled','interrupted')
        AND NEW.state IN ('succeeded','failed','cancelled','interrupted'))
    EXECUTE FUNCTION openmettle.resolve_terminal_write_intents();
