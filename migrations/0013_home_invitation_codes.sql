-- Operator-issued one-time codes for home invitations (ADR 0022). The create script generates
-- 16 random bytes, stores only this domain-separated SHA-256 hash and prints the code once.
ALTER TABLE openmettle.home_invitations
    ADD COLUMN code_hash bytea CHECK (code_hash IS NULL OR octet_length(code_hash) = 32);
-- A pending invitation without a code could never be redeemed. Validation refuses the upgrade
-- (SQLSTATE 23514) while one exists: withdraw it, migrate, then invite again. Closed rows keep
-- NULL, and the hash stays after redemption or withdrawal.
ALTER TABLE openmettle.home_invitations
    ADD CONSTRAINT home_invitations_pending_code_check
    CHECK (code_hash IS NOT NULL OR withdrawn_at IS NOT NULL OR approval_id IS NOT NULL);

-- The sealed login gains the aes256gcm-v2 length (76 bytes) beside v1 (59 bytes), which stays
-- valid for logins in flight during the upgrade. Migration 6 left its check unnamed, so it is
-- found by the column it constrains: exactly one check must reference ciphertext.
DO $$
DECLARE
    previous name;
BEGIN
    SELECT c.conname INTO STRICT previous FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'openmettle.login_transactions'::pg_catalog.regclass AND c.contype = 'c'
       AND c.conkey @> ARRAY[(SELECT a.attnum FROM pg_catalog.pg_attribute a
                               WHERE a.attrelid = c.conrelid AND a.attname = 'ciphertext')];
    EXECUTE pg_catalog.format('ALTER TABLE openmettle.login_transactions DROP CONSTRAINT %I', previous);
END $$;
ALTER TABLE openmettle.login_transactions
    ADD CONSTRAINT login_transactions_ciphertext_check
    CHECK ((consumed AND ciphertext IS NULL) OR
        (NOT consumed AND ciphertext IS NOT NULL AND octet_length(ciphertext) IN (59, 76)));

-- Redemption now also requires the code. Dropping the five-argument function removes its grant,
-- so a caller without the code has no redemption entry point.
DROP FUNCTION openmettle.redeem_home_invitation(uuid, text, text, text, bigint);

-- Same contract, lock order and checks as migration 12, plus the code. The pending invitation
-- is located by issuer, subject, provider, generation and code hash together, so a wrong code
-- follows the path of a missing invitation and locks no invitation row. The API role has no
-- privilege on home_invitations and no function returns code_hash.
CREATE FUNCTION openmettle.redeem_home_invitation(provider uuid, exact_issuer text,
    exact_subject text, origin_login text, proof_epoch bigint, invitation_code bytea)
RETURNS TABLE(identity_id text, user_id text, redeem_before_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    invite openmettle.home_invitations%ROWTYPE;
    new_user uuid;
    new_identity uuid;
    new_approval uuid;
    generation bigint;
    client text;
    current_epoch bigint;
    current_revision text;
    login_expiry bigint;
    stored bytea;
    config bytea;
    config_length integer;
BEGIN
    -- Same lock order as the managed caller. Also enforce the durable gates at this boundary.
    SELECT l.expires_ms, l.binding INTO STRICT login_expiry, stored
        FROM openmettle.login_transactions l
        WHERE l.id = origin_login AND l.consumed AND NOT l.session_issued FOR UPDATE;
    SELECT p.access_generation, p.client_id INTO STRICT generation, client
        FROM openmettle.login_providers p
        WHERE p.id = provider AND p.issuer COLLATE "C" = exact_issuer FOR SHARE;
    SELECT r.epoch, r.revision INTO STRICT current_epoch, current_revision
        FROM openmettle.login_provider_revisions r
        WHERE r.provider_id = provider ORDER BY r.epoch DESC LIMIT 1;
    IF current_epoch <> proof_epoch OR current_revision IS NULL THEN RETURN; END IF;

    -- The originating login must carry the managed binding of this exact provider
    -- configuration and epoch: domain, u64 length, configuration, u64 length, epoch (see
    -- provider_keys::persisted). The configuration's leading fields are provider UUID,
    -- issuer, client and revision, each a u64 big-endian length then bytes. Bytes are
    -- compared as stored, without encoding conversion.
    config := convert_to('openmettle/login-provider/2', 'SQL_ASCII') || decode('00', 'hex')
        || int8send(octet_length(provider::text)::bigint)
        || convert_to(provider::text, getdatabaseencoding()::name)
        || int8send(octet_length(exact_issuer)::bigint)
        || convert_to(exact_issuer, getdatabaseencoding()::name)
        || int8send(octet_length(client)::bigint)
        || convert_to(client, getdatabaseencoding()::name)
        || int8send(octet_length(current_revision)::bigint)
        || convert_to(current_revision, getdatabaseencoding()::name);
    config_length := octet_length(stored) - 27 - 8 - 16;
    IF config_length < octet_length(config)
       OR substring(stored FROM 1 FOR 27)
          IS DISTINCT FROM convert_to('openmettle/managed-login/2', 'SQL_ASCII') || decode('00', 'hex')
       OR substring(stored FROM 28 FOR 8) IS DISTINCT FROM int8send(config_length)
       OR substring(stored FROM 36 FOR octet_length(config)) IS DISTINCT FROM config
       OR substring(stored FROM 36 + config_length)
          IS DISTINCT FROM int8send(8) || int8send(proof_epoch) THEN
        RETURN;
    END IF;

    -- A missing, short or long code is refused before any invitation is read.
    IF octet_length(invitation_code) IS DISTINCT FROM 16 THEN RETURN; END IF;
    SELECT i.* INTO STRICT invite FROM openmettle.home_invitations i
        WHERE i.issuer COLLATE "C" = exact_issuer AND i.subject COLLATE "C" = exact_subject AND i.provider_id = provider
          AND i.provider_generation = generation AND i.withdrawn_at IS NULL AND i.approval_id IS NULL
          AND i.code_hash = sha256(convert_to('openmettle/home-invitation-code/1', 'SQL_ASCII')
                                   || decode('00', 'hex') || invitation_code)
        FOR UPDATE;
    -- Any retirement after creation fences the decision, including legacy retirement that
    -- left the generation unchanged and a later restoration. Routine revisions do not.
    IF NOT EXISTS (SELECT FROM openmettle.login_provider_revisions r
        WHERE r.epoch = invite.provider_epoch AND r.provider_id = provider AND r.revision IS NOT NULL)
       OR EXISTS (SELECT FROM openmettle.login_provider_revisions r
        WHERE r.provider_id = provider AND r.epoch > invite.provider_epoch AND r.revision IS NULL)
        THEN RETURN; END IF;
    IF floor(extract(epoch FROM clock_timestamp()) * 1000) >= least(invite.redeem_before_ms, login_expiry)
        THEN RETURN; END IF;
    INSERT INTO openmettle.users DEFAULT VALUES RETURNING id INTO new_user;
    -- A competing or existing identity makes the *entire* block roll back. Never adopt it.
    INSERT INTO openmettle.user_identities(user_id, issuer, subject)
        VALUES (new_user, invite.issuer, invite.subject) RETURNING id INTO new_identity;
    INSERT INTO openmettle.scopes(kind, personal_user_id) VALUES ('personal', new_user);
    INSERT INTO openmettle.local_identity_approvals(provider_id, identity_id, active,
        expires_ms, changed_by, change_reason)
        VALUES (provider, new_identity, true, invite.approval_until_ms, invite.created_by::text,
                'home invitation ' || invite.id::text) RETURNING id INTO new_approval;
    UPDATE openmettle.home_invitations SET approval_id = new_approval, login_id = origin_login,
        redeemed_at = clock_timestamp() WHERE id = invite.id;
    RETURN QUERY SELECT new_identity::text, new_user::text, invite.redeem_before_ms;
EXCEPTION WHEN no_data_found OR unique_violation THEN RETURN;
END $$;
REVOKE ALL ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea) TO openmettle_api;
