-- Provisional number on the private v10 base. Integrate after membership and native.
CREATE TABLE openmettle.home_invitations (
    id uuid PRIMARY KEY,
    provider_id uuid NOT NULL REFERENCES openmettle.login_providers(id),
    provider_generation bigint NOT NULL CHECK (provider_generation >= 0),
    issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255),
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
    login_expiry bigint;
BEGIN
    -- Same lock order as the managed caller. Also enforce the durable gates at this boundary.
    SELECT l.expires_ms INTO STRICT login_expiry FROM openmettle.login_transactions l
        WHERE l.id = origin_login AND l.consumed AND NOT l.session_issued FOR UPDATE;
    SELECT p.access_generation INTO STRICT generation FROM openmettle.login_providers p
        WHERE p.id = provider AND p.issuer COLLATE "C" = exact_issuer FOR SHARE;
    IF NOT EXISTS (SELECT FROM (SELECT epoch, revision FROM openmettle.login_provider_revisions
        WHERE provider_id = provider ORDER BY epoch DESC LIMIT 1) r
        WHERE r.epoch = proof_epoch AND r.revision IS NOT NULL) THEN RETURN; END IF;

    SELECT i.* INTO STRICT invite FROM openmettle.home_invitations i
        WHERE i.issuer COLLATE "C" = exact_issuer AND i.subject COLLATE "C" = exact_subject AND i.provider_id = provider
          AND i.provider_generation = generation AND i.withdrawn_at IS NULL AND i.approval_id IS NULL
        FOR UPDATE;
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

-- Even a direct function invocation cannot commit a detached approval. Session/login
-- cleanup later is independent of the permanent invitation receipt.
CREATE FUNCTION openmettle.check_home_redemption() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM openmettle.local_sessions s
        JOIN openmettle.login_transactions l ON l.id = s.login_id
        JOIN openmettle.user_identities i ON i.id = s.identity_id
        WHERE s.login_id = NEW.login_id AND s.approval_id = NEW.approval_id
          AND i.user_id = s.user_id AND l.consumed AND l.session_issued
          AND floor(extract(epoch FROM clock_timestamp()) * 1000)
              < least(NEW.redeem_before_ms, l.expires_ms, s.expires_ms)) THEN
        RAISE EXCEPTION 'home invitation requires current first session';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER home_redemption_session
    AFTER UPDATE ON openmettle.home_invitations DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (OLD.approval_id IS NULL AND NEW.approval_id IS NOT NULL)
    EXECUTE FUNCTION openmettle.check_home_redemption();
