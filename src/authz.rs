//! Pure central authorization policy (ADR 0027). No I/O, persistence, routes or enforcement.
//!
//! Every input is server state hydrated from the primary database for one request or one
//! execution-time recheck, never a client claim, cookie or cached token. Callers must map a
//! [`Decision`] to the ADR 0007 problem codes with [`DenialReason::status`] and
//! [`DenialReason::code`] and must not reveal the internal [`PolicyReason`].
use crate::{
    capabilities::{Authorization, Caller},
    membership::Observation,
    runs::is_canonical_uuid,
};
use std::collections::BTreeSet;

/// The authenticated caller at one primary-database observation. It carries stable internal
/// identifiers only: no email, display name or raw identity-provider claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Principal {
    pub user_id: String,
    pub personal_scope_id: String,
    /// The user row is enabled.
    pub account_active: bool,
    /// The exact identity approval admitting this principal is active and unexpired.
    pub approval_active: bool,
    /// The login provider of that approval is not retired at its current authority epoch.
    pub provider_active: bool,
    /// Account administration only. Never consulted for content access.
    pub account_admin: bool,
    /// Explicit, non-nested local groups. No group is ever a member of another group.
    pub local_groups: BTreeSet<String>,
    /// Groups with current (`Present`) ADR 0021 membership evidence. Non-nested.
    pub oidc_groups: BTreeSet<String>,
    /// Opt-in capabilities assigned to this user, for example `runs.use_yolo`.
    pub granted_capabilities: BTreeSet<String>,
    /// User-level capability denies, for example family restrictions on `web_search`.
    pub denied_capabilities: BTreeSet<String>,
}

impl Principal {
    /// Disablement, approval withdrawal and provider retirement all fail closed.
    pub fn is_active(&self) -> bool {
        self.account_active && self.approval_active && self.provider_active
    }

    fn matches(&self, grantee: &Grantee) -> bool {
        match grantee {
            Grantee::User(id) => *id == self.user_id,
            Grantee::LocalGroup(id) => self.local_groups.contains(id),
            Grantee::OidcGroup(id) => self.oidc_groups.contains(id),
            Grantee::Project => false,
        }
    }
}

/// Reject a request without a hydrated principal before any grant is evaluated.
pub fn require(principal: Option<&Principal>) -> Result<&Principal, DenialReason> {
    let principal = principal.ok_or(DenialReason::Unauthenticated)?;
    if !principal.is_active() {
        return Err(DenialReason::InactivePrincipal);
    }
    Ok(principal)
}

/// Every operation the policy can decide. Each `authorize_*` function accepts only the
/// actions in its domain; any other action is refused, never inferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Stream,
    Search,
    Download,
    CreateInScope,
    RunExecute,
    ShareResource,
    RevokeResourceShare,
    ManageProjectSettings,
    ManageProjectMembers,
    DeleteProject,
    ManageLocalGroups,
    ManageUserCapabilityDenies,
    ManageQuotas,
    ManageFamilyPolicies,
    InspectCapacity,
    ManageAccountAdmin,
    ManageAccounts,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenialReason),
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        self == Self::Allow
    }

    /// Bridge to the capability evaluator: concealed or unauthenticated outcomes are hidden,
    /// a visible policy refusal is `Denied`.
    pub fn caller(self) -> Caller {
        match self {
            Self::Allow => Caller::Visible(Authorization::Allowed),
            Self::Deny(DenialReason::Policy(_)) => Caller::Visible(Authorization::Denied),
            Self::Deny(_) => Caller::Hidden,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialReason {
    /// No principal was supplied.
    Unauthenticated,
    /// Disabled account, withdrawn approval or retired provider.
    InactivePrincipal,
    /// Concealment: the caller may not learn that the scope or resource exists.
    NotFound,
    /// The caller may know the target exists but lacks permission.
    Policy(PolicyReason),
}

impl DenialReason {
    /// ADR 0007 HTTP status.
    pub fn status(self) -> u16 {
        match self {
            Self::Unauthenticated | Self::InactivePrincipal => 401,
            Self::NotFound => 404,
            Self::Policy(_) => 403,
        }
    }

    /// ADR 0007 stable problem code. The internal reason never reaches the wire.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated | Self::InactivePrincipal => "unauthenticated",
            Self::NotFound => "not_found",
            Self::Policy(_) => "policy",
        }
    }
}

/// Internal explanation for audit and tests only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyReason {
    /// The action does not belong to the evaluated domain.
    NotApplicable,
    InsufficientRole,
    InsufficientAccess,
    NotAccountAdmin,
    CapabilityDenied,
    CapabilityNotGranted,
    InvalidCapability,
    FamilyPolicy,
    LastAccountAdmin,
    LastProjectOwner,
    NotShareable,
    NotShareManager,
    GranteeNotMember,
    InvalidGrantee,
}

use DenialReason::{InactivePrincipal, NotFound};

fn policy(reason: PolicyReason) -> Decision {
    Decision::Deny(DenialReason::Policy(reason))
}

/// `Owner > Editor > Viewer`; the derived order is the precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectRole {
    Viewer,
    Editor,
    Owner,
}

/// `Write` implies `Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantPermission {
    ProjectRole(ProjectRole),
    Resource(ResourceAccess),
}

impl GrantPermission {
    pub fn project_role(self) -> Result<ProjectRole, VocabularyError> {
        match self {
            Self::ProjectRole(role) => Ok(role),
            Self::Resource(_) => Err(VocabularyError::WrongTarget),
        }
    }

    pub fn resource_access(self) -> Result<ResourceAccess, VocabularyError> {
        match self {
            Self::Resource(access) => Ok(access),
            Self::ProjectRole(_) => Err(VocabularyError::WrongTarget),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VocabularyError {
    UnknownFormat,
    UnsupportedVersion,
    UnknownKey,
    /// A known permission stored on a target kind it does not apply to.
    WrongTarget,
}

pub const PROJECT_MEMBER: &str = "openmettle.project-member";
pub const PROJECT_ROLE: &str = "openmettle.project-role";
pub const RESOURCE_GRANT: &str = "openmettle.resource-grant";

/// The only interpretation of ADR 0006 `(assignment_format, assignment_version,
/// assignment_key)`. Matching is exact: no trimming, case folding or prefix matching.
pub struct GrantVocabulary;

impl GrantVocabulary {
    pub fn parse(
        format: &str,
        version: i32,
        key: &str,
    ) -> Result<GrantPermission, VocabularyError> {
        let known = [PROJECT_MEMBER, PROJECT_ROLE, RESOURCE_GRANT];
        if !known.contains(&format) {
            return Err(VocabularyError::UnknownFormat);
        }
        if version != 1 {
            return Err(VocabularyError::UnsupportedVersion);
        }
        let permission = match (format, key) {
            // ADR 0021 stores the approval UUID as the key; it never names a role.
            (PROJECT_MEMBER, key) if is_canonical_uuid(key) => {
                GrantPermission::ProjectRole(ProjectRole::Viewer)
            }
            (PROJECT_ROLE, "viewer") => GrantPermission::ProjectRole(ProjectRole::Viewer),
            (PROJECT_ROLE, "editor") => GrantPermission::ProjectRole(ProjectRole::Editor),
            (PROJECT_ROLE, "owner") => GrantPermission::ProjectRole(ProjectRole::Owner),
            (RESOURCE_GRANT, "read") => GrantPermission::Resource(ResourceAccess::Read),
            (RESOURCE_GRANT, "write") => GrantPermission::Resource(ResourceAccess::Write),
            _ => return Err(VocabularyError::UnknownKey),
        };
        Ok(permission)
    }
}

/// Grant recipients. Local and OIDC groups are separate namespaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grantee {
    User(String),
    LocalGroup(String),
    OidcGroup(String),
    /// Every active member of the containing project. Valid only for project-scoped shares.
    Project,
}

/// Provenance of one ADR 0006 assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Direct,
    /// Directory-mapped. Effective only with current `Present` ADR 0021 evidence.
    Mapped(Observation),
}

/// One assignment with already-parsed vocabulary. Rows that failed
/// [`GrantVocabulary::parse`] must be omitted, never defaulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant<P> {
    pub grantee: Grantee,
    pub permission: P,
    pub origin: Origin,
    /// The current ADR 0006 head is a grant with a live cycle.
    pub recorded_active: bool,
}

impl<P> Grant<P> {
    fn effective(&self) -> bool {
        self.recorded_active
            && match self.origin {
                Origin::Direct => true,
                Origin::Mapped(evidence) => evidence == Observation::Present,
            }
    }
}

pub type ProjectGrant = Grant<ProjectRole>;
pub type ResourceShare = Grant<ResourceAccess>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    pub id: String,
    pub grants: Vec<ProjectGrant>,
}

impl Project {
    /// Highest active role across direct, local-group and OIDC-mapped grants, if any.
    /// Always returns `None` for an inactive principal.
    pub fn role_of(&self, principal: &Principal) -> Option<ProjectRole> {
        if !principal.is_active() {
            return None;
        }
        self.grants
            .iter()
            .filter(|g| g.effective() && principal.matches(&g.grantee))
            .map(|g| g.permission)
            .max()
    }

    fn group_is_member(&self, grantee: &Grantee) -> bool {
        self.grants
            .iter()
            .any(|g| g.effective() && g.grantee == *grantee)
    }

    /// Distinct users holding an active direct owner grant. Group and mapped owners do not
    /// count toward the last-owner invariant because they can lapse without an owner action.
    fn direct_owners(&self) -> BTreeSet<&str> {
        self.grants
            .iter()
            .filter(|g| {
                g.effective() && g.origin == Origin::Direct && g.permission == ProjectRole::Owner
            })
            .filter_map(|g| match &g.grantee {
                Grantee::User(id) => Some(id.as_str()),
                _ => None,
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// A user's personal scope. Only its owner has access.
    Personal {
        scope_id: String,
        owner_user_id: String,
    },
    Project(Project),
}

fn same_scope(a: &Scope, b: &Scope) -> bool {
    match (a, b) {
        (
            Scope::Personal {
                scope_id: a_id,
                owner_user_id: a_owner,
            },
            Scope::Personal {
                scope_id: b_id,
                owner_user_id: b_owner,
            },
        ) => a_id == b_id && a_owner == b_owner,
        (Scope::Project(a), Scope::Project(b)) => a.id == b.id,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Conversation,
    Artifact,
    Memory,
    Tool,
    Connection,
}

impl ResourceKind {
    /// Only conversations and artifacts accept `openmettle.resource-grant` in V1-05.
    pub fn shareable(self) -> bool {
        matches!(self, Self::Conversation | Self::Artifact)
    }
}

/// A resource is private to its creator until explicitly shared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub kind: ResourceKind,
    pub id: String,
    pub creator_user_id: String,
    pub scope: Scope,
    pub shares: Vec<ResourceShare>,
}

fn is_read(action: Action) -> bool {
    matches!(
        action,
        Action::Read | Action::Stream | Action::Search | Action::Download
    )
}

/// Effective role in a scope: personal owner is treated as `Owner`. `None` conceals the scope.
fn scope_role(principal: &Principal, scope: &Scope) -> Option<ProjectRole> {
    match scope {
        Scope::Personal {
            scope_id,
            owner_user_id,
        } => (*scope_id == principal.personal_scope_id && *owner_user_id == principal.user_id)
            .then_some(ProjectRole::Owner),
        Scope::Project(project) => project.role_of(principal),
    }
}

/// Decide a scope-level action: project metadata reads, creation, runs and owner management.
/// Never consults `account_admin`.
pub fn authorize_scope(principal: &Principal, scope: &Scope, action: Action) -> Decision {
    if !principal.is_active() {
        return Decision::Deny(InactivePrincipal);
    }
    let Some(role) = scope_role(principal, scope) else {
        return Decision::Deny(NotFound);
    };
    let required = match action {
        a if is_read(a) => ProjectRole::Viewer,
        Action::Write | Action::CreateInScope | Action::RunExecute => ProjectRole::Editor,
        Action::ManageProjectSettings | Action::ManageProjectMembers | Action::DeleteProject
            if matches!(scope, Scope::Project(_)) =>
        {
            ProjectRole::Owner
        }
        _ => return policy(PolicyReason::NotApplicable),
    };
    if role < required {
        return policy(PolicyReason::InsufficientRole);
    }
    Decision::Allow
}

/// Effective access to a resource, or `None` when it must stay concealed.
fn resource_access(principal: &Principal, resource: &Resource) -> Option<ResourceAccess> {
    let cap = match &resource.scope {
        // The scope owner has full access; anyone else only what a share grants.
        Scope::Personal { .. } if scope_role(principal, &resource.scope).is_some() => {
            return Some(ResourceAccess::Write);
        }
        Scope::Personal { .. } => ResourceAccess::Write,
        Scope::Project(project) => {
            // Gate 2b: an inactive project membership hides every item, whatever shares remain.
            let role = project.role_of(principal)?;
            // A viewer can never edit, whatever a share row says.
            let cap = if role >= ProjectRole::Editor {
                ResourceAccess::Write
            } else {
                ResourceAccess::Read
            };
            if resource.creator_user_id == principal.user_id {
                return Some(cap);
            }
            cap
        }
    };
    if !resource.kind.shareable() {
        return None;
    }
    let access = resource
        .shares
        .iter()
        .filter(|s| s.effective())
        .filter(|s| match (&resource.scope, &s.grantee) {
            (Scope::Project(_), Grantee::Project) => true,
            (Scope::Personal { .. }, Grantee::Project) => false,
            // Gate 2b: a group share inside a project is effective only while that group still
            // holds active project membership, even if the caller has another direct project grant.
            (Scope::Project(project), g @ (Grantee::LocalGroup(_) | Grantee::OidcGroup(_))) => {
                project.group_is_member(g) && principal.matches(g)
            }
            (_, g) => principal.matches(g),
        })
        .map(|s| s.permission)
        .max()?;
    Some(access.min(cap))
}

/// Decide read, stream, search, download, write or run on one resource.
pub fn authorize_resource(principal: &Principal, resource: &Resource, action: Action) -> Decision {
    if !principal.is_active() {
        return Decision::Deny(InactivePrincipal);
    }
    let Some(access) = resource_access(principal, resource) else {
        return Decision::Deny(NotFound);
    };
    let required = match action {
        a if is_read(a) => ResourceAccess::Read,
        Action::Write => ResourceAccess::Write,
        Action::RunExecute => {
            // Runs charge the scope owner's accounting boundary, so a non-owner cannot execute
            // runs inside another user's personal scope even with a Write share.
            if matches!(resource.scope, Scope::Personal { .. })
                && scope_role(principal, &resource.scope).is_none()
            {
                return policy(PolicyReason::InsufficientAccess);
            }
            ResourceAccess::Write
        }
        _ => return policy(PolicyReason::NotApplicable),
    };
    if access < required {
        return policy(PolicyReason::InsufficientAccess);
    }
    Decision::Allow
}

/// Creator (Editor or Owner) of the item, or a project owner on an item visible to them.
fn manages_shares(principal: &Principal, resource: &Resource) -> Result<(), Decision> {
    if !principal.is_active() {
        return Err(Decision::Deny(InactivePrincipal));
    }
    if resource_access(principal, resource).is_none() {
        return Err(Decision::Deny(NotFound));
    }
    if !resource.kind.shareable() {
        return Err(policy(PolicyReason::NotShareable));
    }
    let role = scope_role(principal, &resource.scope);
    let creator = resource.creator_user_id == principal.user_id;
    let scope_owner = role == Some(ProjectRole::Owner);
    if (creator && role >= Some(ProjectRole::Editor)) || scope_owner {
        Ok(())
    } else {
        Err(policy(PolicyReason::NotShareManager))
    }
}

/// The recipient of a new share. A user recipient is the grantee's own hydrated principal.
#[derive(Clone, Copy, Debug)]
pub enum ShareRecipient<'a> {
    User(&'a Principal),
    LocalGroup(&'a str),
    OidcGroup(&'a str),
    Project,
}

/// Decide whether `principal` may share `resource` with `recipient`.
pub fn authorize_share(
    principal: &Principal,
    resource: &Resource,
    recipient: ShareRecipient<'_>,
) -> Decision {
    if let Err(denied) = manages_shares(principal, resource) {
        return denied;
    }
    match (&resource.scope, recipient) {
        (Scope::Personal { owner_user_id, .. }, ShareRecipient::User(grantee))
            if grantee.user_id == resource.creator_user_id || grantee.user_id == *owner_user_id =>
        {
            policy(PolicyReason::InvalidGrantee)
        }
        (Scope::Project(_), ShareRecipient::User(grantee))
            if grantee.user_id == resource.creator_user_id =>
        {
            policy(PolicyReason::InvalidGrantee)
        }
        (Scope::Personal { .. }, ShareRecipient::Project) => policy(PolicyReason::InvalidGrantee),
        (Scope::Personal { .. }, ShareRecipient::User(grantee)) if !grantee.is_active() => {
            policy(PolicyReason::InvalidGrantee)
        }
        (Scope::Personal { .. }, _) | (Scope::Project(_), ShareRecipient::Project) => {
            Decision::Allow
        }
        (Scope::Project(project), ShareRecipient::User(grantee)) => {
            if grantee.is_active() && project.role_of(grantee).is_some() {
                Decision::Allow
            } else {
                policy(PolicyReason::GranteeNotMember)
            }
        }
        (Scope::Project(project), ShareRecipient::LocalGroup(id)) => {
            group_share(project, Grantee::LocalGroup(id.to_owned()))
        }
        (Scope::Project(project), ShareRecipient::OidcGroup(id)) => {
            group_share(project, Grantee::OidcGroup(id.to_owned()))
        }
    }
}

fn group_share(project: &Project, group: Grantee) -> Decision {
    if project.group_is_member(&group) {
        Decision::Allow
    } else {
        policy(PolicyReason::GranteeNotMember)
    }
}

/// Decide whether `principal` may revoke an existing share. Revocation never requires the
/// grantee to remain a member, so stale rows can always be retired by a share manager.
pub fn authorize_revoke(principal: &Principal, resource: &Resource) -> Decision {
    match manages_shares(principal, resource) {
        Ok(()) => Decision::Allow,
        Err(denied) => denied,
    }
}

/// A change to project membership. `role: None` removes the grantee's direct grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberChange {
    pub grantee: Grantee,
    pub role: Option<ProjectRole>,
}

/// Decide a membership change, keeping at least one active direct user owner.
pub fn authorize_member_change(
    principal: &Principal,
    project: &Project,
    change: &MemberChange,
) -> Decision {
    if !principal.is_active() {
        return Decision::Deny(InactivePrincipal);
    }
    match project.role_of(principal) {
        None => return Decision::Deny(NotFound),
        Some(role) if role < ProjectRole::Owner => return policy(PolicyReason::InsufficientRole),
        Some(_) => {}
    }
    let Grantee::User(target) = &change.grantee else {
        return match change.grantee {
            Grantee::Project => policy(PolicyReason::InvalidGrantee),
            _ => Decision::Allow,
        };
    };
    let owners = project.direct_owners();
    if change.role != Some(ProjectRole::Owner)
        && owners.contains(target.as_str())
        && owners.len() <= 1
    {
        return policy(PolicyReason::LastProjectOwner);
    }
    Decision::Allow
}

/// One account-administration request. `enabled_account_admins` is counted on the primary
/// inside the same transaction that applies the change, under the lock that serializes admin
/// changes. `removes_enabled_admin` is true when the change demotes or disables a currently
/// enabled `account_admin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminChange {
    pub action: Action,
    pub removes_enabled_admin: bool,
    pub enabled_account_admins: u32,
}

/// Decide an account-administration action. Grants no content access.
pub fn authorize_admin(principal: &Principal, change: AdminChange) -> Decision {
    if !principal.is_active() {
        return Decision::Deny(InactivePrincipal);
    }
    let lifecycle = matches!(
        change.action,
        Action::ManageAccountAdmin | Action::ManageAccounts
    );
    let admin = lifecycle
        || matches!(
            change.action,
            Action::ManageLocalGroups
                | Action::ManageUserCapabilityDenies
                | Action::ManageQuotas
                | Action::ManageFamilyPolicies
                | Action::InspectCapacity
        );
    if !admin || (change.removes_enabled_admin && !lifecycle) {
        return policy(PolicyReason::NotApplicable);
    }
    if !principal.account_admin {
        return policy(PolicyReason::NotAccountAdmin);
    }
    if change.removes_enabled_admin && change.enabled_account_admins <= 1 {
        return policy(PolicyReason::LastAccountAdmin);
    }
    Decision::Allow
}

/// Opt-in operator capability granting read-only inspection of detailed capacity group and
/// device observations without account-admin privileges (ADR 0042). Grants no content access.
pub const CAPABILITY_INSPECT_CAPACITY: &str = "capacity.inspect";

/// Decide whether `principal` may inspect detailed managed GPU group and device observations
/// (ADR 0042): active `account_admin` (`Action::InspectCapacity`) or an active principal granted
/// the opt-in `capacity.inspect` capability (subject to platform and user denies). Grants no
/// content access.
pub fn authorize_capacity_inspection(principal: &Principal, platform: &PlatformPolicy) -> Decision {
    if !principal.is_active() {
        return Decision::Deny(InactivePrincipal);
    }
    if authorize_admin(
        principal,
        AdminChange {
            action: Action::InspectCapacity,
            removes_enabled_admin: false,
            enabled_account_admins: 1,
        },
    )
    .is_allowed()
    {
        return Decision::Allow;
    }
    authorize_capability(
        principal,
        platform,
        CAPABILITY_INSPECT_CAPACITY,
        CapabilityGate::OptIn,
    )
}

/// Platform-wide capability policy for the installation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformPolicy {
    pub denied_capabilities: BTreeSet<String>,
}

/// Whether a capability is available unless denied, or requires an explicit assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityGate {
    OnByDefault,
    /// For example `runs.use_yolo`: off unless assigned to the user.
    OptIn,
}

/// The capability name rule, mirrored exactly by the migration 15 `CHECK` constraints.
pub fn valid_capability(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Capability decision. A platform or user deny always wins. Use [`Decision::caller`] to
/// feed `crate::capabilities::Input`.
pub fn authorize_capability(
    principal: &Principal,
    platform: &PlatformPolicy,
    capability: &str,
    gate: CapabilityGate,
) -> Decision {
    if !principal.is_active() {
        return Decision::Deny(InactivePrincipal);
    }
    if !valid_capability(capability) {
        return policy(PolicyReason::InvalidCapability);
    }
    if platform.denied_capabilities.contains(capability)
        || principal.denied_capabilities.contains(capability)
    {
        return policy(PolicyReason::CapabilityDenied);
    }
    if gate == CapabilityGate::OptIn && !principal.granted_capabilities.contains(capability) {
        return policy(PolicyReason::CapabilityNotGranted);
    }
    Decision::Allow
}

/// Authority a queued or running run needs at every execution-time recheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunAuthority {
    pub scope: Scope,
    /// The conversation or other resource the run writes to, if any.
    pub target: Option<Resource>,
    pub capabilities: Vec<(String, CapabilityGate)>,
    /// Deliberately ignored: logging out of one session never cancels background work.
    pub originating_session_active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunContinuation {
    Continue,
    /// The worker must stop the run and record the reason; it is not retried.
    Invalidate(DenialReason),
}

/// Recheck a run against the owner's freshly hydrated principal.
pub fn authorize_run_continuation(
    owner: &Principal,
    platform: &PlatformPolicy,
    run: &RunAuthority,
) -> RunContinuation {
    let mut decisions = vec![authorize_scope(owner, &run.scope, Action::RunExecute)];
    if let Some(target) = &run.target {
        decisions.push(if same_scope(&target.scope, &run.scope) {
            authorize_resource(owner, target, Action::RunExecute)
        } else {
            Decision::Deny(NotFound)
        });
    }
    for (capability, gate) in &run.capabilities {
        decisions.push(authorize_capability(owner, platform, capability, *gate));
    }
    match decisions.into_iter().find(|d| *d != Decision::Allow) {
        Some(Decision::Deny(reason)) => RunContinuation::Invalidate(reason),
        _ => RunContinuation::Continue,
    }
}

pub mod approvals;
pub mod branches;
pub mod gateway;
pub mod leases;
pub mod projects;
pub mod runs;
pub mod store;

#[cfg(test)]
mod tests;
