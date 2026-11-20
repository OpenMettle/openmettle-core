//! Synthetic fixtures only. Identifiers are opaque labels, not real users or projects.
use super::*;

const MEMBER_KEY: &str = "0b2c6f1e-4d3a-4c55-9e21-7a8b9c0d1e2f";

fn user(id: &str) -> Principal {
    Principal {
        user_id: id.into(),
        personal_scope_id: format!("scope-{id}"),
        account_active: true,
        approval_active: true,
        provider_active: true,
        ..Principal::default()
    }
}

fn admin(id: &str) -> Principal {
    Principal {
        account_admin: true,
        ..user(id)
    }
}

fn grant<P>(grantee: Grantee, permission: P) -> Grant<P> {
    Grant {
        grantee,
        permission,
        origin: Origin::Direct,
        recorded_active: true,
    }
}

fn u(id: &str) -> Grantee {
    Grantee::User(id.into())
}

/// Project p1: owner `own`, editors `ed` and `ed2`, viewer `vw`, local group `lg` as
/// editor, OIDC group `og` as viewer. `out` has no membership.
fn project() -> Project {
    Project {
        id: "p1".into(),
        grants: vec![
            grant(u("own"), ProjectRole::Owner),
            grant(u("ed"), ProjectRole::Editor),
            grant(u("ed2"), ProjectRole::Editor),
            grant(u("vw"), ProjectRole::Viewer),
            grant(Grantee::LocalGroup("lg".into()), ProjectRole::Editor),
            grant(Grantee::OidcGroup("og".into()), ProjectRole::Viewer),
        ],
    }
}

fn personal(id: &str) -> Scope {
    Scope::Personal {
        scope_id: format!("scope-{id}"),
        owner_user_id: id.into(),
    }
}

fn item(kind: ResourceKind, creator: &str, scope: Scope) -> Resource {
    Resource {
        kind,
        id: "r1".into(),
        creator_user_id: creator.into(),
        scope,
        shares: Vec::new(),
    }
}

fn conversation(creator: &str) -> Resource {
    item(
        ResourceKind::Conversation,
        creator,
        Scope::Project(project()),
    )
}

fn shared(mut r: Resource, grantee: Grantee, access: ResourceAccess) -> Resource {
    r.shares.push(grant(grantee, access));
    r
}

const ALLOW: Decision = Decision::Allow;
const HIDDEN: Decision = Decision::Deny(DenialReason::NotFound);
const INACTIVE: Decision = Decision::Deny(DenialReason::InactivePrincipal);

fn refused(reason: PolicyReason) -> Decision {
    Decision::Deny(DenialReason::Policy(reason))
}

const READS: [Action; 4] = [
    Action::Read,
    Action::Stream,
    Action::Search,
    Action::Download,
];
const ALL: [Action; 17] = [
    Action::Read,
    Action::Write,
    Action::Stream,
    Action::Search,
    Action::Download,
    Action::CreateInScope,
    Action::RunExecute,
    Action::ShareResource,
    Action::RevokeResourceShare,
    Action::ManageProjectSettings,
    Action::ManageProjectMembers,
    Action::DeleteProject,
    Action::ManageLocalGroups,
    Action::ManageUserCapabilityDenies,
    Action::ManageQuotas,
    Action::ManageAccountAdmin,
    Action::ManageAccounts,
];

// --- Vocabulary -------------------------------------------------------------------------

#[test]
fn vocabulary_accepts_only_exact_known_entries() {
    use GrantPermission::*;
    let p = GrantVocabulary::parse;
    assert_eq!(
        p(PROJECT_MEMBER, 1, MEMBER_KEY),
        Ok(ProjectRole(super::ProjectRole::Viewer))
    );
    for (key, role) in [
        ("viewer", super::ProjectRole::Viewer),
        ("editor", super::ProjectRole::Editor),
        ("owner", super::ProjectRole::Owner),
    ] {
        assert_eq!(p(PROJECT_ROLE, 1, key), Ok(ProjectRole(role)));
    }
    assert_eq!(
        p(RESOURCE_GRANT, 1, "read"),
        Ok(Resource(ResourceAccess::Read))
    );
    assert_eq!(
        p(RESOURCE_GRANT, 1, "write"),
        Ok(Resource(ResourceAccess::Write))
    );
}

#[test]
fn vocabulary_rejects_unknown_formats_and_versions() {
    use VocabularyError::*;
    let p = GrantVocabulary::parse;
    for format in [
        "",
        "test.assignment",
        "openmettle.project-roles",
        "OpenMettle.project-role",
        " openmettle.project-role",
        "openmettle.project-role ",
        "openmettle.project-role\0",
        "openmettle.admin",
    ] {
        assert_eq!(p(format, 1, "owner"), Err(UnknownFormat), "{format:?}");
    }
    for format in [PROJECT_MEMBER, PROJECT_ROLE, RESOURCE_GRANT] {
        for version in [0, -1, 2, i32::MAX, i32::MIN] {
            assert_eq!(p(format, version, "read"), Err(UnsupportedVersion));
        }
    }
}

#[test]
fn vocabulary_rejects_unknown_padded_and_cased_keys() {
    let p = GrantVocabulary::parse;
    for key in [
        "", "Owner", "OWNER", " owner", "owner ", "owner\0", "owner\n", "admin", "manage", "read",
        "write", "own",
    ] {
        assert_eq!(
            p(PROJECT_ROLE, 1, key),
            Err(VocabularyError::UnknownKey),
            "{key:?}"
        );
    }
    for key in [
        "", "Read", "READ", " read", "read\0", "write ", "admin", "owner", "share", "rw",
    ] {
        assert_eq!(
            p(RESOURCE_GRANT, 1, key),
            Err(VocabularyError::UnknownKey),
            "{key:?}"
        );
    }
}

#[test]
fn project_member_key_is_a_canonical_approval_uuid_never_a_role() {
    let p = GrantVocabulary::parse;
    for key in [
        "owner",
        "editor",
        "viewer",
        "0B2C6F1E-4D3A-4C55-9E21-7A8B9C0D1E2F",
        "0b2c6f1e4d3a4c559e217a8b9c0d1e2f",
        "{0b2c6f1e-4d3a-4c55-9e21-7a8b9c0d1e2f}",
        " 0b2c6f1e-4d3a-4c55-9e21-7a8b9c0d1e2f",
        "0b2c6f1e-4d3a-4c55-9e21-7a8b9c0d1e2f\0",
        "0b2c6f1e-4d3a-4c55-9e21-7a8b9c0d1e2g",
        "0b2c6f1e_4d3a-4c55-9e21-7a8b9c0d1e2f",
    ] {
        assert_eq!(
            p(PROJECT_MEMBER, 1, key),
            Err(VocabularyError::UnknownKey),
            "{key:?}"
        );
    }
}

#[test]
fn permission_kind_must_match_target() {
    let role = GrantVocabulary::parse(PROJECT_ROLE, 1, "owner").unwrap();
    let access = GrantVocabulary::parse(RESOURCE_GRANT, 1, "write").unwrap();
    assert_eq!(role.project_role(), Ok(ProjectRole::Owner));
    assert_eq!(role.resource_access(), Err(VocabularyError::WrongTarget));
    assert_eq!(access.resource_access(), Ok(ResourceAccess::Write));
    assert_eq!(access.project_role(), Err(VocabularyError::WrongTarget));
}

// --- Principal and decision mapping -------------------------------------------------------

#[test]
fn require_fails_closed_before_any_grant() {
    assert_eq!(require(None), Err(DenialReason::Unauthenticated));
    let ok = user("own");
    assert_eq!(require(Some(&ok)), Ok(&ok));
    for f in [
        |p: &mut Principal| p.account_active = false,
        |p: &mut Principal| p.approval_active = false,
        |p: &mut Principal| p.provider_active = false,
    ] {
        let mut p = user("own");
        f(&mut p);
        assert_eq!(require(Some(&p)), Err(DenialReason::InactivePrincipal));
        let scope = Scope::Project(project());
        for action in ALL {
            assert_eq!(authorize_scope(&p, &scope, action), INACTIVE);
            assert_eq!(
                authorize_resource(&p, &conversation("own"), action),
                INACTIVE
            );
        }
        assert_eq!(authorize_revoke(&p, &conversation("own")), INACTIVE);
    }
}

#[test]
fn denials_map_to_adr_0007_problem_codes() {
    use DenialReason::*;
    assert_eq!((NotFound.status(), NotFound.code()), (404, "not_found"));
    let p = Policy(PolicyReason::InsufficientRole);
    assert_eq!((p.status(), p.code()), (403, "policy"));
    for r in [Unauthenticated, InactivePrincipal] {
        assert_eq!((r.status(), r.code()), (401, "unauthenticated"));
    }
}

#[test]
fn decision_bridges_to_capability_caller() {
    assert_eq!(ALLOW.caller(), Caller::Visible(Authorization::Allowed));
    assert_eq!(
        refused(PolicyReason::CapabilityDenied).caller(),
        Caller::Visible(Authorization::Denied)
    );
    assert_eq!(HIDDEN.caller(), Caller::Hidden);
    assert_eq!(INACTIVE.caller(), Caller::Hidden);
    assert!(ALLOW.is_allowed() && !HIDDEN.is_allowed());
}

// --- Project roles --------------------------------------------------------------------------

#[test]
fn project_role_matrix() {
    let scope = Scope::Project(project());
    let owner_only = [
        Action::ManageProjectSettings,
        Action::ManageProjectMembers,
        Action::DeleteProject,
    ];
    let editor = [Action::Write, Action::CreateInScope, Action::RunExecute];
    for (id, role) in [
        ("own", ProjectRole::Owner),
        ("ed", ProjectRole::Editor),
        ("vw", ProjectRole::Viewer),
    ] {
        let p = user(id);
        for a in READS {
            assert_eq!(authorize_scope(&p, &scope, a), ALLOW, "{id} {a:?}");
        }
        for a in editor {
            let expect = if role >= ProjectRole::Editor {
                ALLOW
            } else {
                refused(PolicyReason::InsufficientRole)
            };
            assert_eq!(authorize_scope(&p, &scope, a), expect, "{id} {a:?}");
        }
        for a in owner_only {
            let expect = if role == ProjectRole::Owner {
                ALLOW
            } else {
                refused(PolicyReason::InsufficientRole)
            };
            assert_eq!(authorize_scope(&p, &scope, a), expect, "{id} {a:?}");
        }
    }
}

#[test]
fn scope_rejects_actions_outside_its_domain() {
    let scope = Scope::Project(project());
    let owner = user("own");
    for a in [
        Action::ShareResource,
        Action::RevokeResourceShare,
        Action::ManageLocalGroups,
        Action::ManageUserCapabilityDenies,
        Action::ManageQuotas,
        Action::ManageAccountAdmin,
        Action::ManageAccounts,
    ] {
        assert_eq!(
            authorize_scope(&owner, &scope, a),
            refused(PolicyReason::NotApplicable)
        );
    }
    for a in [
        Action::ManageProjectSettings,
        Action::ManageProjectMembers,
        Action::DeleteProject,
    ] {
        assert_eq!(
            authorize_scope(&owner, &personal("own"), a),
            refused(PolicyReason::NotApplicable)
        );
    }
}

#[test]
fn non_members_and_admins_cannot_see_projects() {
    let scope = Scope::Project(project());
    for p in [user("out"), admin("out")] {
        for a in ALL {
            assert_eq!(authorize_scope(&p, &scope, a), HIDDEN, "{a:?}");
        }
    }
}

#[test]
fn highest_active_role_wins_across_sources() {
    let mut proj = project();
    proj.grants.push(grant(u("vw"), ProjectRole::Owner));
    assert_eq!(proj.role_of(&user("vw")), Some(ProjectRole::Owner));

    // Local group grants Editor to a user who holds only a direct Viewer grant.
    let mut p = user("vw");
    p.local_groups.insert("lg".into());
    assert_eq!(project().role_of(&p), Some(ProjectRole::Editor));

    let mut p = user("x");
    p.oidc_groups.insert("og".into());
    assert_eq!(project().role_of(&p), Some(ProjectRole::Viewer));
}

#[test]
fn group_namespaces_are_distinct_and_non_nested() {
    // A local group named like an OIDC group, or a group named like a user, grants nothing.
    let mut p = user("x");
    p.local_groups.insert("og".into());
    p.oidc_groups.insert("lg".into());
    p.oidc_groups.insert("own".into());
    assert_eq!(project().role_of(&p), None);

    // Membership of a group that is itself a grantee's "member" confers nothing.
    let mut proj = project();
    proj.grants.push(grant(u("lg"), ProjectRole::Owner));
    let mut p = user("x");
    p.local_groups.insert("lg".into());
    assert_eq!(proj.role_of(&p), Some(ProjectRole::Editor));
}

#[test]
fn inactive_or_unconfirmed_grants_confer_nothing() {
    for observation in [
        Observation::Absent,
        Observation::Missing,
        Observation::Partial,
        Observation::Ambiguous,
        Observation::Stale,
        Observation::Failed,
    ] {
        let proj = Project {
            id: "p1".into(),
            grants: vec![Grant {
                origin: Origin::Mapped(observation),
                ..grant(u("x"), ProjectRole::Viewer)
            }],
        };
        assert_eq!(proj.role_of(&user("x")), None, "{observation:?}");
    }
    let proj = Project {
        id: "p1".into(),
        grants: vec![Grant {
            origin: Origin::Mapped(Observation::Present),
            ..grant(u("x"), ProjectRole::Viewer)
        }],
    };
    assert_eq!(proj.role_of(&user("x")), Some(ProjectRole::Viewer));
    let proj = Project {
        id: "p1".into(),
        grants: vec![Grant {
            recorded_active: false,
            ..grant(u("x"), ProjectRole::Owner)
        }],
    };
    assert_eq!(proj.role_of(&user("x")), None);
}

// --- Personal scope -------------------------------------------------------------------------

#[test]
fn personal_scope_is_private_to_its_owner() {
    let scope = personal("own");
    let owner = user("own");
    for a in [
        Action::Read,
        Action::Write,
        Action::CreateInScope,
        Action::RunExecute,
    ] {
        assert_eq!(authorize_scope(&owner, &scope, a), ALLOW);
    }
    for p in [user("ed"), admin("adm")] {
        for a in ALL {
            assert_eq!(authorize_scope(&p, &scope, a), HIDDEN);
        }
    }
    // A mismatched scope/owner pair is never the caller's scope.
    let forged = Scope::Personal {
        scope_id: "scope-own".into(),
        owner_user_id: "ed".into(),
    };
    assert_eq!(authorize_scope(&owner, &forged, Action::Read), HIDDEN);
    assert_eq!(authorize_scope(&user("ed"), &forged, Action::Read), HIDDEN);
}

#[test]
fn personal_items_need_explicit_direct_or_group_share() {
    let r = item(ResourceKind::Artifact, "own", personal("own"));
    assert_eq!(authorize_resource(&user("own"), &r, Action::Write), ALLOW);
    assert_eq!(authorize_resource(&user("x"), &r, Action::Read), HIDDEN);
    assert_eq!(authorize_resource(&admin("adm"), &r, Action::Read), HIDDEN);

    // Direct share: exactly the shared access, never reshare rights.
    let direct = shared(r.clone(), u("x"), ResourceAccess::Read);
    assert_eq!(authorize_resource(&user("x"), &direct, Action::Read), ALLOW);
    assert_eq!(
        authorize_resource(&user("x"), &direct, Action::Write),
        refused(PolicyReason::InsufficientAccess)
    );
    assert_eq!(
        authorize_share(&user("x"), &direct, ShareRecipient::LocalGroup("fam")),
        refused(PolicyReason::NotShareManager)
    );
    assert_eq!(
        authorize_resource(&user("y"), &direct, Action::Read),
        HIDDEN
    );

    // Group share reaches group members only.
    let group = shared(
        r.clone(),
        Grantee::LocalGroup("fam".into()),
        ResourceAccess::Write,
    );
    let mut member = user("y");
    member.local_groups.insert("fam".into());
    assert_eq!(authorize_resource(&member, &group, Action::Write), ALLOW);
    assert_eq!(authorize_resource(&user("x"), &group, Action::Read), HIDDEN);

    // A project-wide row is meaningless outside a project and grants nothing.
    let wide = shared(r, Grantee::Project, ResourceAccess::Write);
    assert_eq!(
        authorize_resource(&user("own"), &wide, Action::Write),
        ALLOW
    );
    assert_eq!(authorize_resource(&user("x"), &wide, Action::Read), HIDDEN);
    assert_eq!(
        authorize_resource(&admin("adm"), &wide, Action::Read),
        HIDDEN
    );
}

// --- Private-by-default resources -----------------------------------------------------------

#[test]
fn project_items_start_private_to_their_creator() {
    let r = conversation("ed");
    assert_eq!(authorize_resource(&user("ed"), &r, Action::Write), ALLOW);
    for id in ["own", "ed2", "vw", "out"] {
        for a in [
            Action::Read,
            Action::Write,
            Action::Stream,
            Action::Search,
            Action::Download,
        ] {
            assert_eq!(authorize_resource(&user(id), &r, a), HIDDEN, "{id} {a:?}");
        }
    }
}

#[test]
fn account_admin_never_gains_content_access() {
    for kind in [
        ResourceKind::Conversation,
        ResourceKind::Artifact,
        ResourceKind::Memory,
        ResourceKind::Tool,
        ResourceKind::Connection,
    ] {
        for scope in [Scope::Project(project()), personal("ed")] {
            let r = item(kind, "ed", scope.clone());
            for a in ALL {
                assert_eq!(
                    authorize_resource(&admin("adm"), &r, a),
                    HIDDEN,
                    "{kind:?} {a:?}"
                );
            }
            assert_eq!(authorize_revoke(&admin("adm"), &r), HIDDEN);
        }
    }
    // An admin who is a project member gets exactly the member's access.
    let mut proj = project();
    proj.grants.push(grant(u("adm"), ProjectRole::Viewer));
    let r = item(ResourceKind::Conversation, "ed", Scope::Project(proj));
    assert_eq!(authorize_resource(&admin("adm"), &r, Action::Read), HIDDEN);
    let r = shared(r, Grantee::Project, ResourceAccess::Write);
    assert_eq!(authorize_resource(&admin("adm"), &r, Action::Read), ALLOW);
    assert_eq!(
        authorize_resource(&admin("adm"), &r, Action::Write),
        refused(PolicyReason::InsufficientAccess)
    );
}

#[test]
fn even_project_owner_cannot_read_unshared_private_items() {
    for kind in [
        ResourceKind::Conversation,
        ResourceKind::Artifact,
        ResourceKind::Memory,
    ] {
        let r = item(kind, "ed", Scope::Project(project()));
        assert_eq!(authorize_resource(&user("own"), &r, Action::Read), HIDDEN);
        assert_eq!(
            authorize_share(&user("own"), &r, ShareRecipient::Project),
            HIDDEN
        );
    }
}

#[test]
fn shares_grant_exactly_their_access() {
    let r = shared(conversation("ed"), u("ed2"), ResourceAccess::Read);
    for a in READS {
        assert_eq!(authorize_resource(&user("ed2"), &r, a), ALLOW);
    }
    assert_eq!(
        authorize_resource(&user("ed2"), &r, Action::Write),
        refused(PolicyReason::InsufficientAccess)
    );
    assert_eq!(authorize_resource(&user("vw"), &r, Action::Read), HIDDEN);

    let r = shared(conversation("ed"), u("ed2"), ResourceAccess::Write);
    assert_eq!(authorize_resource(&user("ed2"), &r, Action::Write), ALLOW);
    assert_eq!(
        authorize_resource(&user("ed2"), &r, Action::RunExecute),
        ALLOW
    );
}

#[test]
fn group_and_project_wide_shares_reach_members() {
    let mut via_local = user("m1");
    via_local.local_groups.insert("lg".into());
    let mut via_oidc = user("m2");
    via_oidc.oidc_groups.insert("og".into());

    let r = shared(
        conversation("ed"),
        Grantee::LocalGroup("lg".into()),
        ResourceAccess::Write,
    );
    assert_eq!(authorize_resource(&via_local, &r, Action::Write), ALLOW);
    assert_eq!(authorize_resource(&via_oidc, &r, Action::Read), HIDDEN);

    let r = shared(
        conversation("ed"),
        Grantee::OidcGroup("og".into()),
        ResourceAccess::Read,
    );
    assert_eq!(authorize_resource(&via_oidc, &r, Action::Read), ALLOW);
    assert_eq!(authorize_resource(&via_local, &r, Action::Read), HIDDEN);

    let r = shared(conversation("ed"), Grantee::Project, ResourceAccess::Read);
    for id in ["own", "ed2", "vw"] {
        assert_eq!(authorize_resource(&user(id), &r, Action::Read), ALLOW);
    }
    assert_eq!(authorize_resource(&user("out"), &r, Action::Read), HIDDEN);
}

#[test]
fn viewer_access_is_capped_at_read() {
    let r = shared(conversation("ed"), u("vw"), ResourceAccess::Write);
    assert_eq!(authorize_resource(&user("vw"), &r, Action::Read), ALLOW);
    for a in [Action::Write, Action::RunExecute] {
        assert_eq!(
            authorize_resource(&user("vw"), &r, a),
            refused(PolicyReason::InsufficientAccess)
        );
    }
    // A creator demoted to Viewer keeps read access only.
    let mut proj = project();
    proj.grants.retain(|g| g.grantee != u("ed"));
    proj.grants.push(grant(u("ed"), ProjectRole::Viewer));
    let r = item(ResourceKind::Conversation, "ed", Scope::Project(proj));
    assert_eq!(authorize_resource(&user("ed"), &r, Action::Read), ALLOW);
    assert_eq!(
        authorize_resource(&user("ed"), &r, Action::Write),
        refused(PolicyReason::InsufficientAccess)
    );
}

#[test]
fn revoked_or_unconfirmed_shares_confer_nothing() {
    let mut r = shared(conversation("ed"), u("ed2"), ResourceAccess::Write);
    r.shares[0].recorded_active = false;
    assert_eq!(authorize_resource(&user("ed2"), &r, Action::Read), HIDDEN);
    r.shares[0].recorded_active = true;
    r.shares[0].origin = Origin::Mapped(Observation::Stale);
    assert_eq!(authorize_resource(&user("ed2"), &r, Action::Read), HIDDEN);
}

#[test]
fn stale_membership_hides_every_project_item_despite_share_rows() {
    let r = shared(conversation("ed"), u("ed2"), ResourceAccess::Write);
    // Direct removal.
    let mut proj = project();
    proj.grants.retain(|g| g.grantee != u("ed2"));
    let mut removed = r.clone();
    removed.scope = Scope::Project(proj);
    assert_eq!(
        authorize_resource(&user("ed2"), &removed, Action::Read),
        HIDDEN
    );

    // Local group removal: the share names the group, the user left it.
    let r = shared(
        conversation("ed"),
        Grantee::LocalGroup("lg".into()),
        ResourceAccess::Read,
    );
    let mut left = user("m1");
    assert_eq!(authorize_resource(&left, &r, Action::Read), HIDDEN);
    left.local_groups.insert("lg".into());
    assert_eq!(authorize_resource(&left, &r, Action::Read), ALLOW);

    // OIDC staleness: the only membership is mapped and its evidence expired.
    let proj = Project {
        id: "p1".into(),
        grants: vec![
            grant(u("ed"), ProjectRole::Editor),
            Grant {
                origin: Origin::Mapped(Observation::Stale),
                ..grant(u("m3"), ProjectRole::Viewer)
            },
        ],
    };
    let r = shared(
        item(ResourceKind::Artifact, "ed", Scope::Project(proj)),
        u("m3"),
        ResourceAccess::Read,
    );
    assert_eq!(authorize_resource(&user("m3"), &r, Action::Read), HIDDEN);
    // Even the creator loses access to their own item once membership lapses.
    let mut r = r;
    if let Scope::Project(p) = &mut r.scope {
        p.grants.retain(|g| g.grantee != u("ed"));
    }
    assert_eq!(authorize_resource(&user("ed"), &r, Action::Read), HIDDEN);
}

#[test]
fn non_shareable_kinds_ignore_share_rows() {
    for kind in [
        ResourceKind::Memory,
        ResourceKind::Tool,
        ResourceKind::Connection,
    ] {
        let r = shared(
            item(kind, "ed", Scope::Project(project())),
            Grantee::Project,
            ResourceAccess::Write,
        );
        assert_eq!(authorize_resource(&user("ed2"), &r, Action::Read), HIDDEN);
        assert_eq!(authorize_resource(&user("ed"), &r, Action::Write), ALLOW);
        assert_eq!(
            authorize_share(&user("ed"), &r, ShareRecipient::Project),
            refused(PolicyReason::NotShareable)
        );
    }
}

#[test]
fn resource_rejects_actions_outside_its_domain() {
    let r = conversation("ed");
    for a in [
        Action::CreateInScope,
        Action::ShareResource,
        Action::RevokeResourceShare,
        Action::ManageProjectSettings,
        Action::ManageProjectMembers,
        Action::DeleteProject,
        Action::ManageAccounts,
        Action::ManageAccountAdmin,
    ] {
        assert_eq!(
            authorize_resource(&user("ed"), &r, a),
            refused(PolicyReason::NotApplicable)
        );
    }
}

// --- Sharing (2a) and grantee membership (2b) ----------------------------------------------

#[test]
fn creator_editor_or_owner_can_share_own_item() {
    let ed2 = user("ed2");
    for creator in ["ed", "own"] {
        let r = conversation(creator);
        let p = user(creator);
        assert_eq!(authorize_share(&p, &r, ShareRecipient::User(&ed2)), ALLOW);
        assert_eq!(authorize_share(&p, &r, ShareRecipient::Project), ALLOW);
        assert_eq!(
            authorize_share(&p, &r, ShareRecipient::LocalGroup("lg")),
            ALLOW
        );
        assert_eq!(
            authorize_share(&p, &r, ShareRecipient::OidcGroup("og")),
            ALLOW
        );
        assert_eq!(authorize_revoke(&p, &r), ALLOW);
    }
}

#[test]
fn editor_cannot_reshare_someone_elses_item() {
    let r = shared(conversation("ed"), u("ed2"), ResourceAccess::Write);
    let target = user("vw");
    assert_eq!(
        authorize_share(&user("ed2"), &r, ShareRecipient::User(&target)),
        refused(PolicyReason::NotShareManager)
    );
    assert_eq!(
        authorize_revoke(&user("ed2"), &r),
        refused(PolicyReason::NotShareManager)
    );
    // Without a share the item is concealed rather than refused.
    assert_eq!(
        authorize_share(&user("ed2"), &conversation("ed"), ShareRecipient::Project),
        HIDDEN
    );
}

#[test]
fn viewer_cannot_share_anything() {
    let mut proj = project();
    proj.grants.push(grant(u("vw2"), ProjectRole::Viewer));
    // Even an item the viewer created (before a demotion) cannot be shared.
    let own = item(ResourceKind::Conversation, "vw", Scope::Project(proj));
    assert_eq!(
        authorize_share(&user("vw"), &own, ShareRecipient::Project),
        refused(PolicyReason::NotShareManager)
    );
    let r = shared(conversation("ed"), u("vw"), ResourceAccess::Read);
    assert_eq!(
        authorize_share(&user("vw"), &r, ShareRecipient::Project),
        refused(PolicyReason::NotShareManager)
    );
    assert_eq!(
        authorize_revoke(&user("vw"), &r),
        refused(PolicyReason::NotShareManager)
    );
}

#[test]
fn project_owner_manages_shares_on_project_shared_items() {
    let r = shared(conversation("ed"), Grantee::Project, ResourceAccess::Read);
    let vw = user("vw");
    assert_eq!(
        authorize_share(&user("own"), &r, ShareRecipient::User(&vw)),
        ALLOW
    );
    assert_eq!(authorize_revoke(&user("own"), &r), ALLOW);
}

#[test]
fn project_grantees_must_be_active_members() {
    let r = conversation("ed");
    let p = user("ed");
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::User(&user("out"))),
        refused(PolicyReason::GranteeNotMember)
    );
    let mut disabled = user("ed2");
    disabled.account_active = false;
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::User(&disabled)),
        refused(PolicyReason::GranteeNotMember)
    );
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::LocalGroup("other")),
        refused(PolicyReason::GranteeNotMember)
    );
    // A group named like a member group but in the other namespace is not a member.
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::OidcGroup("lg")),
        refused(PolicyReason::GranteeNotMember)
    );
    // A user who is a member only through a group qualifies.
    let mut via_group = user("m1");
    via_group.oidc_groups.insert("og".into());
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::User(&via_group)),
        ALLOW
    );
}

#[test]
fn sharing_with_the_creator_is_refused() {
    let r = conversation("ed");
    assert_eq!(
        authorize_share(&user("ed"), &r, ShareRecipient::User(&user("ed"))),
        refused(PolicyReason::InvalidGrantee)
    );
}

#[test]
fn personal_sharing_by_scope_owner_only() {
    let r = item(ResourceKind::Conversation, "own", personal("own"));
    let p = user("own");
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::User(&user("x"))),
        ALLOW
    );
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::LocalGroup("fam")),
        ALLOW
    );
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::OidcGroup("fam")),
        ALLOW
    );
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::Project),
        refused(PolicyReason::InvalidGrantee)
    );
    let mut inactive = user("x");
    inactive.approval_active = false;
    assert_eq!(
        authorize_share(&p, &r, ShareRecipient::User(&inactive)),
        refused(PolicyReason::InvalidGrantee)
    );
    assert_eq!(
        authorize_share(&user("x"), &r, ShareRecipient::Project),
        HIDDEN
    );
}

// --- Project membership management ----------------------------------------------------------

fn change(grantee: Grantee, role: Option<ProjectRole>) -> MemberChange {
    MemberChange { grantee, role }
}

#[test]
fn only_owners_manage_members() {
    let proj = project();
    let c = change(u("new"), Some(ProjectRole::Viewer));
    assert_eq!(authorize_member_change(&user("own"), &proj, &c), ALLOW);
    for id in ["ed", "vw"] {
        assert_eq!(
            authorize_member_change(&user(id), &proj, &c),
            refused(PolicyReason::InsufficientRole)
        );
    }
    assert_eq!(authorize_member_change(&user("out"), &proj, &c), HIDDEN);
    assert_eq!(authorize_member_change(&admin("adm"), &proj, &c), HIDDEN);
    let mut off = user("own");
    off.provider_active = false;
    assert_eq!(authorize_member_change(&off, &proj, &c), INACTIVE);
    assert_eq!(
        authorize_member_change(&user("own"), &proj, &change(Grantee::Project, None)),
        refused(PolicyReason::InvalidGrantee)
    );
    assert_eq!(
        authorize_member_change(
            &user("own"),
            &proj,
            &change(Grantee::LocalGroup("lg".into()), None)
        ),
        ALLOW
    );
}

#[test]
fn last_direct_owner_cannot_be_removed_or_demoted() {
    let proj = project();
    for role in [None, Some(ProjectRole::Editor), Some(ProjectRole::Viewer)] {
        assert_eq!(
            authorize_member_change(&user("own"), &proj, &change(u("own"), role)),
            refused(PolicyReason::LastProjectOwner),
            "{role:?}"
        );
    }
    assert_eq!(
        authorize_member_change(
            &user("own"),
            &proj,
            &change(u("own"), Some(ProjectRole::Owner))
        ),
        ALLOW
    );

    // Group and mapped owners do not satisfy the invariant.
    let mut weak = project();
    weak.grants
        .push(grant(Grantee::LocalGroup("lg".into()), ProjectRole::Owner));
    weak.grants.push(Grant {
        origin: Origin::Mapped(Observation::Present),
        ..grant(u("m"), ProjectRole::Owner)
    });
    assert_eq!(
        authorize_member_change(&user("own"), &weak, &change(u("own"), None)),
        refused(PolicyReason::LastProjectOwner)
    );

    // Transfer: add a second direct owner, then the first may step down.
    let mut two = project();
    two.grants.push(grant(u("ed"), ProjectRole::Owner));
    assert_eq!(
        authorize_member_change(&user("own"), &two, &change(u("own"), None)),
        ALLOW
    );
    // A duplicate owner row for the same user is still one owner.
    let mut dup = project();
    dup.grants.push(grant(u("own"), ProjectRole::Owner));
    assert_eq!(
        authorize_member_change(&user("own"), &dup, &change(u("own"), None)),
        refused(PolicyReason::LastProjectOwner)
    );
}

// --- Account administration -----------------------------------------------------------------

fn admin_change(action: Action, removes: bool, admins: u32) -> AdminChange {
    AdminChange {
        action,
        removes_enabled_admin: removes,
        enabled_account_admins: admins,
    }
}

#[test]
fn account_admin_manages_accounts_groups_denies_quotas_and_admins() {
    for a in [
        Action::ManageAccounts,
        Action::ManageLocalGroups,
        Action::ManageUserCapabilityDenies,
        Action::ManageQuotas,
        Action::ManageAccountAdmin,
    ] {
        assert_eq!(
            authorize_admin(&admin("adm"), admin_change(a, false, 1)),
            ALLOW
        );
        assert_eq!(
            authorize_admin(&user("own"), admin_change(a, false, 1)),
            refused(PolicyReason::NotAccountAdmin)
        );
        let mut off = admin("adm");
        off.account_active = false;
        assert_eq!(authorize_admin(&off, admin_change(a, false, 2)), INACTIVE);
    }
}

#[test]
fn last_enabled_account_admin_is_protected() {
    for a in [Action::ManageAccountAdmin, Action::ManageAccounts] {
        for count in [0, 1] {
            assert_eq!(
                authorize_admin(&admin("adm"), admin_change(a, true, count)),
                refused(PolicyReason::LastAccountAdmin)
            );
        }
        assert_eq!(
            authorize_admin(&admin("adm"), admin_change(a, true, 2)),
            ALLOW
        );
    }
}

#[test]
fn admin_rejects_content_and_project_actions() {
    for a in [
        Action::Read,
        Action::Write,
        Action::Stream,
        Action::Search,
        Action::Download,
        Action::CreateInScope,
        Action::RunExecute,
        Action::ShareResource,
        Action::RevokeResourceShare,
        Action::ManageProjectSettings,
        Action::ManageProjectMembers,
        Action::DeleteProject,
    ] {
        assert_eq!(
            authorize_admin(&admin("adm"), admin_change(a, false, 3)),
            refused(PolicyReason::NotApplicable)
        );
    }
    // Only lifecycle actions can remove an admin.
    assert_eq!(
        authorize_admin(&admin("adm"), admin_change(Action::ManageQuotas, true, 3)),
        refused(PolicyReason::NotApplicable)
    );
}

// --- Capabilities ---------------------------------------------------------------------------

#[test]
fn capability_denies_win_at_platform_and_user_level() {
    let platform = PlatformPolicy::default();
    let p = user("kid");
    assert_eq!(
        authorize_capability(&p, &platform, "web_search", CapabilityGate::OnByDefault),
        ALLOW
    );
    let mut denied = user("kid");
    denied.denied_capabilities.insert("web_search".into());
    denied.granted_capabilities.insert("web_search".into());
    assert_eq!(
        authorize_capability(
            &denied,
            &platform,
            "web_search",
            CapabilityGate::OnByDefault
        ),
        refused(PolicyReason::CapabilityDenied)
    );
    let platform = PlatformPolicy {
        denied_capabilities: ["web_search".to_string()].into(),
    };
    let mut granted = admin("adm");
    granted.granted_capabilities.insert("web_search".into());
    assert_eq!(
        authorize_capability(&granted, &platform, "web_search", CapabilityGate::OptIn),
        refused(PolicyReason::CapabilityDenied)
    );
    assert_eq!(
        authorize_capability(&p, &platform, "web_search", CapabilityGate::OnByDefault).caller(),
        Caller::Visible(Authorization::Denied)
    );
}

#[test]
fn opt_in_capabilities_need_an_explicit_assignment() {
    let platform = PlatformPolicy::default();
    // account_admin does not imply YOLO.
    assert_eq!(
        authorize_capability(
            &admin("adm"),
            &platform,
            "runs.use_yolo",
            CapabilityGate::OptIn
        ),
        refused(PolicyReason::CapabilityNotGranted)
    );
    let mut p = user("ed");
    p.granted_capabilities.insert("runs.use_yolo".into());
    assert_eq!(
        authorize_capability(&p, &platform, "runs.use_yolo", CapabilityGate::OptIn),
        ALLOW
    );
}

#[test]
fn malformed_capability_names_are_refused() {
    let platform = PlatformPolicy::default();
    for name in [
        "",
        "Web_Search",
        " web_search",
        "web_search\0",
        "web search",
        &"a".repeat(129),
    ] {
        assert_eq!(
            authorize_capability(&user("x"), &platform, name, CapabilityGate::OnByDefault),
            refused(PolicyReason::InvalidCapability),
            "{name:?}"
        );
    }
    let mut off = user("x");
    off.account_active = false;
    assert_eq!(
        authorize_capability(&off, &platform, "web_search", CapabilityGate::OnByDefault),
        INACTIVE
    );
}

// --- Run continuation -----------------------------------------------------------------------

fn run() -> RunAuthority {
    RunAuthority {
        scope: Scope::Project(project()),
        target: Some(conversation("ed")),
        capabilities: vec![
            ("web_search".into(), CapabilityGate::OnByDefault),
            ("runs.use_yolo".into(), CapabilityGate::OptIn),
        ],
        originating_session_active: true,
    }
}

fn runner() -> Principal {
    let mut p = user("ed");
    p.granted_capabilities.insert("runs.use_yolo".into());
    p
}

#[test]
fn single_session_logout_does_not_invalidate_a_run() {
    let platform = PlatformPolicy::default();
    let mut r = run();
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &r),
        RunContinuation::Continue
    );
    r.originating_session_active = false;
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &r),
        RunContinuation::Continue
    );
}

#[test]
fn principal_state_changes_invalidate_runs_immediately() {
    let platform = PlatformPolicy::default();
    for f in [
        |p: &mut Principal| p.account_active = false,
        |p: &mut Principal| p.approval_active = false,
        |p: &mut Principal| p.provider_active = false,
    ] {
        let mut p = runner();
        f(&mut p);
        assert_eq!(
            authorize_run_continuation(&p, &platform, &run()),
            RunContinuation::Invalidate(DenialReason::InactivePrincipal)
        );
    }
}

#[test]
fn capability_changes_invalidate_runs() {
    let mut p = runner();
    p.denied_capabilities.insert("web_search".into());
    assert_eq!(
        authorize_run_continuation(&p, &PlatformPolicy::default(), &run()),
        RunContinuation::Invalidate(DenialReason::Policy(PolicyReason::CapabilityDenied))
    );
    let platform = PlatformPolicy {
        denied_capabilities: ["runs.use_yolo".to_string()].into(),
    };
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &run()),
        RunContinuation::Invalidate(DenialReason::Policy(PolicyReason::CapabilityDenied))
    );
    let mut p = runner();
    p.granted_capabilities.clear();
    assert_eq!(
        authorize_run_continuation(&p, &PlatformPolicy::default(), &run()),
        RunContinuation::Invalidate(DenialReason::Policy(PolicyReason::CapabilityNotGranted))
    );
}

#[test]
fn grant_and_membership_revocation_invalidate_runs() {
    let platform = PlatformPolicy::default();
    // Membership removed.
    let mut r = run();
    let mut proj = project();
    proj.grants.retain(|g| g.grantee != u("ed"));
    r.scope = Scope::Project(proj.clone());
    r.target.as_mut().unwrap().scope = Scope::Project(proj);
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &r),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );
    // Demoted to Viewer.
    let mut proj = project();
    proj.grants.retain(|g| g.grantee != u("ed"));
    proj.grants.push(grant(u("ed"), ProjectRole::Viewer));
    let mut r = run();
    r.scope = Scope::Project(proj.clone());
    r.target.as_mut().unwrap().scope = Scope::Project(proj);
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &r),
        RunContinuation::Invalidate(DenialReason::Policy(PolicyReason::InsufficientRole))
    );
    // A shared conversation whose share was revoked.
    let mut r = run();
    let mut target = shared(conversation("own"), u("ed"), ResourceAccess::Write);
    r.target = Some(target.clone());
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &r),
        RunContinuation::Continue
    );
    target.shares[0].recorded_active = false;
    r.target = Some(target);
    assert_eq!(
        authorize_run_continuation(&runner(), &platform, &r),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );
}

#[test]
fn run_target_must_belong_to_the_run_scope() {
    let mut r = run();
    r.scope = personal("ed");
    assert_eq!(
        authorize_run_continuation(&runner(), &PlatformPolicy::default(), &r),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );
    r.target = Some(item(ResourceKind::Conversation, "ed", personal("ed")));
    assert_eq!(
        authorize_run_continuation(&runner(), &PlatformPolicy::default(), &r),
        RunContinuation::Continue
    );
    // A different project with the same members is still a different scope.
    let mut other = project();
    other.id = "p2".into();
    let mut r = run();
    r.scope = Scope::Project(other);
    assert_eq!(
        authorize_run_continuation(&runner(), &PlatformPolicy::default(), &r),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );
}

#[test]
fn account_admin_cannot_run_in_anothers_scope() {
    let mut adm = admin("adm");
    adm.granted_capabilities.insert("runs.use_yolo".into());
    assert_eq!(
        authorize_run_continuation(&adm, &PlatformPolicy::default(), &run()),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );
}

#[test]
fn project_role_of_returns_none_for_inactive_principals() {
    let proj = project();
    assert_eq!(proj.role_of(&user("own")), Some(ProjectRole::Owner));

    let mut disabled = user("own");
    disabled.account_active = false;
    assert_eq!(proj.role_of(&disabled), None);

    let mut unapproved = user("own");
    unapproved.approval_active = false;
    assert_eq!(proj.role_of(&unapproved), None);

    let mut retired = user("own");
    retired.provider_active = false;
    assert_eq!(proj.role_of(&retired), None);
}

#[test]
fn removed_or_stale_project_group_cuts_off_group_shares_even_for_direct_members() {
    let mut alice = user("ed2");
    alice.local_groups.insert("lg".into());
    alice.oidc_groups.insert("og".into());

    // LocalGroup removed from project.grants: Alice still has direct Editor on p1,
    // but must lose access via the stale LocalGroup share row.
    let mut proj_no_lg = project();
    proj_no_lg
        .grants
        .retain(|g| g.grantee != Grantee::LocalGroup("lg".into()));
    let r_lg = shared(
        item(ResourceKind::Conversation, "ed", Scope::Project(proj_no_lg)),
        Grantee::LocalGroup("lg".into()),
        ResourceAccess::Write,
    );
    assert_eq!(authorize_resource(&alice, &r_lg, Action::Read), HIDDEN);
    assert_eq!(authorize_resource(&alice, &r_lg, Action::Write), HIDDEN);

    // Same for an Owner holding a direct grant: stale group share does not make item visible.
    let mut own = user("own");
    own.local_groups.insert("lg".into());
    assert_eq!(
        authorize_share(&own, &r_lg, ShareRecipient::Project),
        HIDDEN
    );
    assert_eq!(authorize_revoke(&own, &r_lg), HIDDEN);

    // LocalGroup grant recorded_active = false also cuts off access and new shares.
    let mut proj_inactive_lg = project();
    for g in &mut proj_inactive_lg.grants {
        if g.grantee == Grantee::LocalGroup("lg".into()) {
            g.recorded_active = false;
        }
    }
    let r_inactive_lg = shared(
        item(
            ResourceKind::Conversation,
            "ed",
            Scope::Project(proj_inactive_lg.clone()),
        ),
        Grantee::LocalGroup("lg".into()),
        ResourceAccess::Read,
    );
    assert_eq!(
        authorize_resource(&alice, &r_inactive_lg, Action::Read),
        HIDDEN
    );
    let own_item_inactive = item(
        ResourceKind::Conversation,
        "ed",
        Scope::Project(proj_inactive_lg),
    );
    assert_eq!(
        authorize_share(
            &user("ed"),
            &own_item_inactive,
            ShareRecipient::LocalGroup("lg")
        ),
        refused(PolicyReason::GranteeNotMember)
    );

    // OidcGroup grant becoming Stale cuts off access and new shares even for direct members.
    let mut proj_stale_og = project();
    for g in &mut proj_stale_og.grants {
        if g.grantee == Grantee::OidcGroup("og".into()) {
            g.origin = Origin::Mapped(Observation::Stale);
        }
    }
    let r_stale_og = shared(
        item(
            ResourceKind::Conversation,
            "ed",
            Scope::Project(proj_stale_og.clone()),
        ),
        Grantee::OidcGroup("og".into()),
        ResourceAccess::Read,
    );
    assert_eq!(
        authorize_resource(&alice, &r_stale_og, Action::Read),
        HIDDEN
    );
    let own_item_stale = item(
        ResourceKind::Conversation,
        "ed",
        Scope::Project(proj_stale_og),
    );
    assert_eq!(
        authorize_share(
            &user("ed"),
            &own_item_stale,
            ShareRecipient::OidcGroup("og")
        ),
        refused(PolicyReason::GranteeNotMember)
    );
}

#[test]
fn shared_personal_item_denies_non_owner_run_execute_and_forged_scope_owner() {
    let conv = shared(
        item(ResourceKind::Conversation, "own", personal("own")),
        u("bob"),
        ResourceAccess::Write,
    );
    // Bob can read and write the shared personal conversation, but cannot execute runs
    // inside Alice's personal scope (accounting ownership remains with Alice).
    assert_eq!(authorize_resource(&user("bob"), &conv, Action::Read), ALLOW);
    assert_eq!(
        authorize_resource(&user("bob"), &conv, Action::Write),
        ALLOW
    );
    assert_eq!(
        authorize_resource(&user("bob"), &conv, Action::RunExecute),
        refused(PolicyReason::InsufficientAccess)
    );
    let r = RunAuthority {
        scope: personal("own"),
        target: Some(conv.clone()),
        capabilities: vec![],
        originating_session_active: true,
    };
    assert_eq!(
        authorize_run_continuation(&user("bob"), &PlatformPolicy::default(), &r),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );

    // Forged personal scope with the same scope_id but different owner_user_id must not
    // pass same_scope matching in authorize_run_continuation.
    let forged_scope = Scope::Personal {
        scope_id: "scope-bob".into(),
        owner_user_id: "own".into(),
    };
    let forged_target = shared(
        item(ResourceKind::Conversation, "own", forged_scope),
        u("bob"),
        ResourceAccess::Write,
    );
    let r_forged = RunAuthority {
        scope: personal("bob"),
        target: Some(forged_target),
        capabilities: vec![],
        originating_session_active: true,
    };
    assert_eq!(
        authorize_run_continuation(&user("bob"), &PlatformPolicy::default(), &r_forged),
        RunContinuation::Invalidate(DenialReason::NotFound)
    );
}

#[test]
fn owner_cannot_see_or_revoke_unshared_or_third_party_one_to_one_shares() {
    let unshared = conversation("ed");
    assert_eq!(authorize_revoke(&user("own"), &unshared), HIDDEN);

    // Shared 1:1 between two other editors: still invisible to the project owner.
    let peer_share = shared(conversation("ed"), u("ed2"), ResourceAccess::Write);
    assert_eq!(
        authorize_resource(&user("own"), &peer_share, Action::Read),
        HIDDEN
    );
    assert_eq!(
        authorize_share(&user("own"), &peer_share, ShareRecipient::Project),
        HIDDEN
    );
    assert_eq!(authorize_revoke(&user("own"), &peer_share), HIDDEN);
}

#[test]
fn run_continuation_handles_no_target_and_share_downgrade_to_read() {
    let mut r = run();
    r.target = None;
    assert_eq!(
        authorize_run_continuation(&runner(), &PlatformPolicy::default(), &r),
        RunContinuation::Continue
    );

    // Target share downgraded from Write to Read must invalidate immediately.
    let mut r_downgraded = run();
    r_downgraded.target = Some(shared(conversation("own"), u("ed"), ResourceAccess::Read));
    assert_eq!(
        authorize_run_continuation(&runner(), &PlatformPolicy::default(), &r_downgraded),
        RunContinuation::Invalidate(DenialReason::Policy(PolicyReason::InsufficientAccess))
    );
}
