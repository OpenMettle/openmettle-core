-- Home first-account invitations. The version number is assigned at integration; nothing in
-- this file depends on it, so renumbering does not change its hash.
CREATE TABLE openmettle.home_invitations (
    id uuid PRIMARY KEY,
    provider_id uuid NOT NULL REFERENCES openmettle.login_providers(id),
    provider_generation bigint NOT NULL CHECK (provider_generation >= 0),
    -- The provider's current non-retired epoch observed under the provider lock at creation.
    provider_epoch bigint NOT NULL REFERENCES openmettle.login_provider_revisions(epoch),
    issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    -- Same byte predicate as the operator script: every stored byte is 00-7F, including on
    -- SQL_ASCII databases where the server does not validate client encoding.
    subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255)
        CHECK (encode(convert_to(subject, getdatabaseencoding()::name), 'hex')
               COLLATE "C" ~ '^([0-7][0-9a-f])+$'),
    redeem_before_ms bigint NOT NULL CHECK (redeem_before_ms > 0),
    approval_until_ms bigint NOT NULL CHECK (approval_until_ms >= redeem_before_ms),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL,
    withdrawn_by uuid,
    withdrawn_at timestamptz,
    approval_id uuid UNIQUE REFERENCES openmettle.local_identity_approvals(id),
    redeemed_at timestamptz,
    login_id text,
    CHECK ((withdrawn_by IS NULL) = (withdrawn_at IS NULL)),
    CHECK ((approval_id IS NULL) = (redeemed_at IS NULL)),
    CHECK ((approval_id IS NULL) = (login_id IS NULL)),
    CHECK (withdrawn_at IS NULL OR redeemed_at IS NULL)
);
-- The identity namespace spans provider configurations. Expired entries can be withdrawn.
CREATE UNIQUE INDEX home_invitations_pending ON openmettle.home_invitations(issuer, subject)
    WHERE withdrawn_at IS NULL AND approval_id IS NULL;

-- API execution conveys only the scoped decision already made by the owner. No caller-
-- selected account, identity, approval lifetime or authority change. All names are pinned.
-- The database cannot verify an OIDC proof: it checks only the rows named below, which
-- the API role can also write (see docs/operator/home-invitations.md, trust boundary).
CREATE FUNCTION openmettle.redeem_home_invitation(provider uuid, exact_issuer text,
    exact_subject text, origin_login text, proof_epoch bigint)
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

    SELECT i.* INTO STRICT invite FROM openmettle.home_invitations i
        WHERE i.issuer COLLATE "C" = exact_issuer AND i.subject COLLATE "C" = exact_subject AND i.provider_id = provider
          AND i.provider_generation = generation AND i.withdrawn_at IS NULL AND i.approval_id IS NULL
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
REVOKE ALL ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint) TO openmettle_api;

-- Read-only commit gate for the row that recorded a redemption. It observes only the session,
-- login marker and identity rows for that login and approval at commit. It cannot tell whether
-- the API verified a proof or delivered a credential. SQLSTATE OMH01 identifies a definite
-- cutoff refusal. Missing rows use the default code because the managed path never omits them.
CREATE FUNCTION openmettle.check_home_redemption() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    cutoff bigint;
BEGIN
    SELECT least(NEW.redeem_before_ms, l.expires_ms, s.expires_ms) INTO cutoff
        FROM openmettle.local_sessions s
        JOIN openmettle.login_transactions l ON l.id = s.login_id
        JOIN openmettle.user_identities i ON i.id = s.identity_id
        WHERE s.login_id = NEW.login_id AND s.approval_id = NEW.approval_id
          AND i.user_id = s.user_id AND l.consumed AND l.session_issued;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'home invitation requires current first session';
    END IF;
    IF floor(extract(epoch FROM clock_timestamp()) * 1000) >= cutoff THEN
        RAISE EXCEPTION 'home invitation cutoff passed before commit' USING ERRCODE = 'OMH01';
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openmettle.check_home_redemption() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER home_redemption_session
    AFTER UPDATE ON openmettle.home_invitations DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (OLD.approval_id IS NULL AND NEW.approval_id IS NOT NULL)
    EXECUTE FUNCTION openmettle.check_home_redemption();
