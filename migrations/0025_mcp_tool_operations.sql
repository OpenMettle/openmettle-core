-- NULL preserves the dispatch uncertainty of pre-upgrade workers.
ALTER TABLE openmettle.operations
    ADD COLUMN dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3),
    ADD COLUMN effective_expires_us bigint DEFAULT NULL;
GRANT INSERT (dispatched_attempts, effective_expires_us), UPDATE (dispatched_attempts)
    ON openmettle.operations TO openmettle_worker;

CREATE FUNCTION openmettle.guard_operation_dispatch() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.effective_expires_us IS DISTINCT FROM NEW.effective_expires_us OR
        (OLD.dispatched_attempts IS NOT NULL AND
         (NEW.dispatched_attempts IS NULL OR NEW.dispatched_attempts < OLD.dispatched_attempts)) THEN
        RAISE EXCEPTION 'invalid operation dispatch update' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.guard_operation_dispatch() FROM PUBLIC;
CREATE TRIGGER guard_operation_dispatch BEFORE UPDATE ON openmettle.operations
    FOR EACH ROW EXECUTE FUNCTION openmettle.guard_operation_dispatch();

-- The caller holds the run lock. Frame the observation exactly like runs::record_observation.
CREATE FUNCTION openmettle.fail_abandoned_reads(s uuid, r uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    op uuid;
    k text;
    seq bigint;
    frame bytea;
    field bytea;
    fmt constant text := 'openmettle.abandoned-read';
    observed constant bytea := convert_to('{"reason":"abandoned_read"}','UTF8');
BEGIN
    FOR op IN SELECT id FROM openmettle.operations WHERE scope_id=s AND run_id=r
        AND capability='repeatable_read' AND outcome='intent' AND revision=0 ORDER BY id FOR UPDATE
    LOOP
        UPDATE openmettle.operations SET outcome='failed', revision=1,
            observation_format=fmt, observation_version=1, evidence=observed WHERE id=op;
        k := 'abandoned-read:' || op::text;
        frame := convert_to('openmettle/observation/1','UTF8') || decode('00','hex');
        FOREACH field IN ARRAY ARRAY[convert_to(s::text,'UTF8'), convert_to(r::text,'UTF8'),
            convert_to(op::text,'UTF8'), convert_to(k,'UTF8'), int8send(0), convert_to('failed','UTF8'),
            decode('00','hex'), ''::bytea, convert_to(fmt,'UTF8'), int4send(1), observed]
        LOOP
            frame := frame || int8send(octet_length(field)::bigint) || field;
        END LOOP;
        UPDATE openmettle.runs SET last_event_sequence=last_event_sequence+1
            WHERE id=r AND scope_id=s RETURNING last_event_sequence INTO STRICT seq;
        INSERT INTO openmettle.run_events(scope_id,run_id,sequence,append_key,format,format_version,payload,identity,digest)
            VALUES(s,r,seq,k,fmt,1,observed,frame,sha256(frame));
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION openmettle.fail_abandoned_reads(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION openmettle.resolve_abandoned_repeatable_reads() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM openmettle.fail_abandoned_reads(NEW.scope_id, NEW.id);
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.resolve_abandoned_repeatable_reads() FROM PUBLIC;
CREATE TRIGGER resolve_abandoned_repeatable_reads AFTER UPDATE OF state ON openmettle.runs
    FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state
        AND OLD.state NOT IN ('succeeded','failed','cancelled','interrupted')
        AND NEW.state IN ('waiting','succeeded','failed','cancelled','interrupted'))
    EXECUTE FUNCTION openmettle.resolve_abandoned_repeatable_reads();

SELECT openmettle.fail_abandoned_reads(r.scope_id,r.id) FROM openmettle.runs r
WHERE r.state IN ('queued','waiting') AND EXISTS (SELECT FROM openmettle.operations o
    WHERE o.run_id=r.id AND o.capability='repeatable_read' AND o.outcome='intent' AND o.revision=0)
ORDER BY r.id FOR NO KEY UPDATE;
