-- Native sign-in (ADR 0023): one delivery of an already issued native session, and the
-- first-account redemption check for a login that a native sign-in started.

-- registration fences the pending code to the exact configuration that issued it. audience
-- binds the delivered bearer's validation and logout. Owner session cleanup cascades.
CREATE TABLE openmettle.native_handoffs (
    session_id text PRIMARY KEY REFERENCES openmettle.local_sessions(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    registration bytea NOT NULL CHECK (octet_length(registration) = 32),
    audience bytea NOT NULL CHECK (octet_length(audience) = 32),
    challenge bytea NOT NULL CHECK (octet_length(challenge) = 32),
    sealed bytea CHECK (octet_length(sealed) = 103),
    expires_ms bigint NOT NULL CHECK (expires_ms > 0)
);
GRANT SELECT ON openmettle.native_handoffs TO openmettle_api;
GRANT INSERT (session_id, code_hash, registration, audience, challenge, sealed, expires_ms)
    ON openmettle.native_handoffs TO openmettle_api;
GRANT UPDATE (sealed) ON openmettle.native_handoffs TO openmettle_api;

-- Same signature, contract, lock order and checks as migration 13 (ADR 0022). The only change
-- is the binding check: the originating login may carry the managed binding or the native
-- binding, and nothing else. A native login therefore redeems an invitation under exactly the
-- rules of a browser login, including the code. Replacing the function keeps its owner and its
-- one EXECUTE grant to the API role.
CREATE OR REPLACE FUNCTION openmettle.redeem_home_invitation(provider uuid, exact_issuer text,
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
    domain_bytes integer;
    attempt_bytes integer;
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

    -- The originating login must carry a binding of this exact provider configuration and
    -- epoch, in one of two layouts (see provider_keys::persisted). Every field is a u64
    -- big-endian length then bytes.
    --   managed: 'openmettle/managed-login/2' 00, configuration, epoch
    --   native:  'openmettle/native-managed-login/1' 00, configuration, attempt, epoch
    -- The attempt is the 32-byte digest of the native registration and the app's challenge
    -- and state. The database cannot recompute it, so only its length is checked. The
    -- configuration's leading fields are provider UUID, issuer, client and revision. Bytes
    -- are compared as stored, without encoding conversion.
    config := convert_to('openmettle/login-provider/2', 'SQL_ASCII') || decode('00', 'hex')
        || int8send(octet_length(provider::text)::bigint)
        || convert_to(provider::text, getdatabaseencoding()::name)
        || int8send(octet_length(exact_issuer)::bigint)
        || convert_to(exact_issuer, getdatabaseencoding()::name)
        || int8send(octet_length(client)::bigint)
        || convert_to(client, getdatabaseencoding()::name)
        || int8send(octet_length(current_revision)::bigint)
        || convert_to(current_revision, getdatabaseencoding()::name);
    IF substring(stored FROM 1 FOR 27)
       IS NOT DISTINCT FROM convert_to('openmettle/managed-login/2', 'SQL_ASCII') || decode('00', 'hex') THEN
        domain_bytes := 27;
        attempt_bytes := 0;
    ELSIF substring(stored FROM 1 FOR 34)
       IS NOT DISTINCT FROM convert_to('openmettle/native-managed-login/1', 'SQL_ASCII') || decode('00', 'hex') THEN
        domain_bytes := 34;
        attempt_bytes := 40;
    ELSE
        RETURN;
    END IF;
    config_length := octet_length(stored) - domain_bytes - 8 - attempt_bytes - 16;
    IF config_length < octet_length(config)
       OR substring(stored FROM domain_bytes + 1 FOR 8) IS DISTINCT FROM int8send(config_length)
       OR substring(stored FROM domain_bytes + 9 FOR octet_length(config)) IS DISTINCT FROM config
       OR (attempt_bytes = 40 AND substring(stored FROM domain_bytes + 9 + config_length FOR 8)
           IS DISTINCT FROM int8send(32))
       OR substring(stored FROM domain_bytes + 9 + config_length + attempt_bytes)
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
