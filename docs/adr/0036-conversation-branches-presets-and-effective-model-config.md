# 0036 — Conversation branches, presets and effective model configuration

Proposed for V1-07 PR1, 21 November 2026. [Core #8](https://github.com/OpenMettle/openmettle-core/issues/8)
depends on the V1-03 application contract and V1-05 resource authorization. PR1 records the
design. The schema, routes and provider qualification below have separate delivery gates.

## Decision

A branch names a path through immutable messages. Edit and retry fork that path. A run pins
its input message, attachment revisions and resolved model configuration at admission. The
server uses the same resolver for a context preview and a new admission. Only execution can
produce a provider measurement. These requirements come from the [architecture baseline](../../ARCHITECTURE-v1.md)
and its [source pins](../../SOURCE-REFERENCES.md#s15). A pinned deployment or a model name
alone establishes neither context capacity nor reasoning compatibility.

### Graph and storage

Migration 0002 owns `conversations(id, scope_id, scope_kind, owner_user_id, …)` and
`messages(id, scope_id, conversation_id, parent_message_id, …)`. The parent FK already
requires the same conversation. Migration 0003 owns `conversation_branches` with immutable
`id, scope_id, conversation_id, fork_message_id, created_at`. Its `runs` row references
`(scope_id, conversation_id, branch_id)` and `(conversation_id, input_message_id)` and
stores versioned input/configuration bytes. Migrations 0019 and 0020 add admission, queue
and lease state. None of these keys identifies a branch head. [ADR 0003](0003-schema-migrations.md)
and [ADR 0004](0004-run-persistence.md).

PR2 adds one forward migration in schema `openmettle`. The following are the new relations.
IDs and references are UUIDs. Foreign keys use `NO ACTION`.

| Relation and columns | Keys and invariants |
| --- | --- |
| `branch_heads(scope_id, conversation_id, branch_id, parent_branch_id, head_message_id)` | Primary key `branch_id`. Both branch references use the existing scoped branch triple. The head references `messages(conversation_id, id)`. One root per conversation (unique where `parent_branch_id IS NULL`). Only the head can change. A new child records its source branch permanently and starts at its immutable `fork_message_id`. A null head is the empty path. |
| `message_turns(scope_id, conversation_id, message_id, author_user_id, run_id, reasoning_blocks, input_count, output_count)` | Primary key `message_id`. Add `UNIQUE (scope_id, conversation_id, id)` to `messages` and `runs` for the scoped FKs. Exactly one of `author_user_id` (FK to `users.id`, role `user`) and `run_id` (role `assistant`) is set. Unique `run_id` permits one final answer per run. Only assistant rows may carry a bounded array of structured reasoning blocks or nullable, nonnegative bigint provider counts. The run pins the producing profile and the input to which the assistant replies. |
| `message_parts(id, scope_id, conversation_id, message_id, ordinal, kind, text_value, artifact_revision_id)` | Primary key `id` defaults to a random UUID. Unique `(message_id, ordinal)` preserves visible part order. A scoped FK to `message_turns(scope_id, conversation_id, message_id)` uses a matching unique key. A `text` part carries only bounded UTF-8 text. An `attachment` carries only a revision, with FK `(scope_id, artifact_revision_id)` to `artifact_revisions(scope_id, id)`. Check the discriminator, exclusive payloads and nonnegative ordinal in SQL. |

Use integer ordinals 0–127, text for the part kind and value, and JSONB for reasoning.
Limit visible text to 64 KiB per message and the serialized reasoning array to 64 KiB and
128 blocks. These are storage bounds. A user turn needs nonempty text or an attachment.
The writer inserts the message, turn and all parts in one transaction with contiguous
ordinals from zero. Publishing the head seals the turn. Each new parent link must point to
an existing ancestor on the selected path. The FKs enforce scope and conversation. The
writer enforces ancestry, acyclicity and complete publication. Tool calls and outcomes
keep their own ADR 0004 operation records.

Creating a conversation creates its empty root. A branch without a `branch_heads` row
predates managed history. Preserve that ID, its fork, messages and run references. Report
its head and history as unavailable. Never infer the head from the newest message or assign
a speaker to a skeleton row. An authorized writer can create an empty root for an older
conversation that has none. Old binaries can still insert their original rows during rollout.

| Turn on source path | Destination and input |
| --- | --- |
| Append | Lock the selected head and compare it with `expected_head_message_id`, including null. Insert a new user message parented to that head and advance the same branch. |
| Edit user message U | Verify U is a user message on the selected path. Create a child branch with fork at U's parent (possibly null). Insert the replacement with a fresh ID, that same parent and its explicit ordered parts. Advance only the child. |
| Retry assistant message A | Verify A is on the selected path and its parent U is the producing run's user input. Fork at U and reuse U as the new run's input. The new answer will be another child of U. A and all its descendants stay on the original path. |

For example, editing U in `P → U → A` yields `P → U′` on a second branch. Retrying A
yields a third branch at U. Both paths through U reference the same U, part IDs and revision
IDs. An explicitly retained attachment on U′ has a new part ID and the original revision ID.
No bytes move and no second storage charge accrues. Resolve the owning artifact from the
revision, check the actor's current artifact access and require `active` for attachment or
provider input. Reject a foreign scope even if the actor can read both. Recheck on history
projection, download and execution. Conceal inaccessible references and metadata. A visible
retained revision can show its state but cannot supply bytes. [ADR 0005](0005-artifact-storage-accounting.md)
and [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md).

Keep structured reasoning exclusively in `reasoning_blocks` with its versioned block format
and producing profile revision. A reasoning-only answer may have zero visible text parts.
History projects visible parts. The executor sends blocks upstream only if the **target**
provider/model profile explicitly qualifies later-turn replay for that source format,
template and parser revision. Otherwise omit the blocks, including on same-model retries.
Never concatenate them into visible text. Prompts, project/preset instructions, message
text, blocks and upstream bodies stay out of problems, run-event projections, logs, traces,
metric labels and audit details. [ADR 0024](0024-process-telemetry-and-redaction.md) and
[ADR 0034](0034-ordered-events-and-replayable-sse.md).

### Database privileges

Gate each addition to `contract` or `column_contract` in `src/boundaries.sql` on the
successful PR2 migration version. Keep existing table grants on skeletons and branch
identities. New typed fields live on separate relations so those grants cannot expose
reasoning or let an old writer forge its producer.

| Relation | `openmettle_api` | `openmettle_worker` |
| --- | --- | --- |
| `branch_heads` | SELECT, INSERT on the five named columns, UPDATE only `head_message_id` | SELECT, UPDATE only `head_message_id` for fenced completion |
| `message_turns` | SELECT all listed columns except `reasoning_blocks` by column. INSERT only `scope_id, conversation_id, message_id, author_user_id` | SELECT. INSERT only `scope_id, conversation_id, message_id, run_id, reasoning_blocks, input_count, output_count` |
| `message_parts` | SELECT, INSERT only `scope_id, conversation_id, message_id, ordinal, kind, text_value, artifact_revision_id` | Same, for assistant output |

Neither runtime role gets UPDATE on turn content or parts, DELETE, DDL or grant options.
The issuance role and PUBLIC need no new privileges. Reuse the existing API-only project-settings
reader and the existing artifact, run and event grants. Extend the `authorization_audit`
action check for `conversation.create` and `branch.create`. Use the existing user-actor
request key, conversation target, fixed reason, request fingerprint and resulting branch ID
to replay standalone creates. No audit row stores message or preset contents.

### Catalog, presets and context budget

The API loads a versioned, server-controlled catalog. A descriptor binds an opaque model
ID to a specific provider/profile revision, checkpoint, template, parser, runtime and
gateway revision. It declares context and output limits or `unknown`, supported controls
and ranges, usage semantics and replay qualification. A versioned preset names exactly one
base descriptor and carries optional instructions and control defaults. A hints-before-answers
study preset uses this same representation. Selecting it grants no tool, model or family
policy permission. PR2 uses synthetic catalog fixtures. V1-08 supplies qualified profiles.

1. Select the requested preset/model, falling back to the project selection. A preset
   supplies its base model. Reject a mismatched explicit model, missing descriptor or
   unauthorized selection. Apply each field in order **model → preset → project → request**.
   An absent field inherits. Read project overrides from a typed `defaults.model_config`
   object in `project_settings`. Absence means empty overrides, including pre-0015 projects.
   Preserve unrelated defaults. Project owners maintain these fields through the existing
   settings operation. Compose instructions in layer order using the existing project
   `instructions` column, and pin their order and revisions.
2. Validate each selected control against that descriptor. For example, accept
   `temperature` and `top_p` only when declared, finite and within their declared bounds.
   Validate combinations, reasoning effort levels and output ceilings. Profiles with
   unknown support cannot accept an explicit control. Never infer support from a model ID
   substring, vendor name or protocol. Advertising a default effort does not select it.
   A preset or request may explicitly select that default. Resolve it to a declared level,
   report its selecting layer and send the level. If every layer omits effort, omit the
   upstream field, return a null value with `source=gateway_default` and leave the
   gateway's actual choice unknown.
3. Resolve capacity from the base descriptor. A preset without a window inherits it.
   Lower layers may restrict a known limit within the declared bounds. They cannot turn an
   unknown physical window into a known one. Return `context_window` with `state=unknown`
   and null value when capacity is unknown. A separately qualified conservative total
   ceiling for that exact profile may bound admission while the window remains unknown.
   Without a safe ceiling, preview still works and admission returns `503 provisioning`.
4. Return the effective window or safe ceiling, configured `output_reserve` and
   `usable_input` in tokens. For a known ceiling C and reserve R, require
   `0 < R <= C` and R within the profile's output limit. Usable input is `C − R`.
   A missing safe reserve leaves the budget unknown. For each resolved field return its
   value and `source` (`model`, `preset`, `project`, `request` or `gateway_default`).
   Attribute an inherited window to the layer that declared it. Derived fields identify
   their operands. Report the source revisions used by the resolver.
5. Walk from the selected head towards its ancestors. Report the latest provider-measured
   usage on that path with its message/run ID, profile revision and available input and
   output counts for the final model call. Never borrow a sibling's counts or add usage
   across turns. Missing usage stays null. Separately report the current assembled prompt's
   count as `estimated` with the estimator revision, or `unknown` when unavailable.
   Budget for instructions, history, eligible replay, tool declarations and attachment
   inputs. For opaque blocks the estimator may use the per-message storage bound and the
   qualified target encoding's worst-case overhead. A measurement for an earlier prompt
   stays labeled with that turn. Admit only if a profile-qualified count or conservative
   upper bound fits `usable_input`. An over-budget request fails validation. An unknown
   bound cannot authorize dispatch. Preview never truncates history silently.

For a synthetic model with an 8,192-token window and a preset reserving 1,024 for output,
the preview returns 8,192 (`model`), 1,024 (`preset`) and 7,168 usable input tokens.
Removing the descriptor's window and conservative ceiling makes both capacity and usable
input unknown. Neither the reserve nor a previous successful call establishes a window.

### Application API

Use the authenticated `/v1` mount in `src/v1.rs` and the canonical OpenAPI 3.2.1 document.
The following are PR3 operations. `C` denotes `/v1/conversations/{conversation_id}` and
`B` denotes `C/branches/{branch_id}`.

| Method and path | Result |
| --- | --- |
| `POST /v1/conversations` | `201` private conversation and root branch. Default to the actor's personal scope or accept an explicit authorized project scope. |
| `GET /v1/conversations` | Visible conversations in the requested scope, including only effective shares and the caller's own visible items. |
| `GET C/branches`, `GET B`, `GET B/messages` | List branches, select one by ID, or page its head-to-root history. Selection is per request. Readers never move another reader's head. |
| `POST C/branches` | `201` child at an explicit ancestor of the source branch, or the first empty root for a legacy conversation. |
| `GET /v1/models`, `GET /v1/presets`, `GET /v1/presets/{preset_id}` | Authorized catalog and preset descriptors. Keep installed, authorized and ready distinct. An empty catalog is valid. |
| `POST B/effective-configuration` | Read-only `200` preview for this branch, the proposed input and overrides. No message, reservation or run. |
| `POST /v1/runs` | Submit an append, edit or retry. `201` on admission, `200` on exact replay. Both return `Run`. |
| `POST /v1/runs/{run_id}/cancel` | Actor cancellation with an empty body. `200` or `202` with `Run` as specified below. |

Keep the existing `GET C` (`ConversationAccess`), share/revoke, `getRun` and
`streamRunEvents` contracts. Use browser or native sessions, the existing Origin rule,
version and no-store headers, closed bounded request objects and extensible response objects
and vocabularies. Use `Uuid`, `Timestamp`, `NonNegativeDecimal` for counts and RFC 9457
`Problem`. Lists use `limit` (default 50, maximum 100) and `PageInfo.next_cursor`.
Order conversation and branch lists by `(created_at, id)`, catalogs by ID. Bind opaque
authenticated cursors to caller, operation, scope, filters, order and position. Pin the
history head and next ancestor, or the catalog revision, as applicable. Domain-separate page
cursors from SSE cursors. Reauthorize every page. Bad bindings yield `400 invalid_cursor`.
[ADR 0007](0007-application-api-contract.md).

Apply `authorize_create_in_scope` to conversation creation and `read_resource` to
conversation reads. Project membership and account administration alone confer no access to
another person's private conversation. A viewer may read an explicitly shared conversation.
Forking needs resource Write. Submitting also needs scope RunExecute and each effective
capability. A personal Write share cannot execute against its owner's scope. Rehydrate
current grants on every request. Use `401 unauthenticated` for inactive sessions,
`404 not_found` for absent, hidden or wrong-parent IDs, and `403 policy` for a visible
target with insufficient permission. Authorized new writes to an archived project get
`409 conflict`. [ADR 0027](0027-authorization-and-private-projects.md).

### Atomic admission and cancellation

1. Require one ADR 0007 `Idempotency-Key` for each mutation. Derive its stored key with
   the operation and authorized target. Resolve the scope, actor and approval on the server.
   Require validated admission limits for the create route and a configured ADR 0034
   signing key before a run mutation can return a snapshot. Open one bounded READ COMMITTED
   `WriteTransaction`. Take ADR 0032's scope lock, then the actor lock, before branch locks
   or writes. Recheck access and call `find_run` on that connection **before** allocating
   a branch or inserting a message.
2. Store the normalized client intent in the versioned input snapshot (operation mode,
   source branch, expected head, edit/retry target, ordered input, requested model/preset,
   overrides and requested rounds). Preserve a client-chosen input UUID on append/edit
   across retries. Pin the effective branch path and attachment revision IDs. Reference
   reasoning by its immutable message ID so the API never needs to read the blocks. The config
   snapshot pins the effective fields, sources, instruction bytes, omission decisions and
   profile/policy revisions. Use one deterministic encoding per version and enforce the
   existing combined 256 KiB bound. Keep credentials out of both. On a hit compare the
   submitted intent, reuse the stored branch, input UUID and original snapshot bytes, and
   pass that identity through `admit_run` for its locked authorization and replay check.
   Changed intent is `409 idempotency_conflict`. An exact replay survives changed defaults,
   limits, head movement or archive while the caller retains authority for the pinned
   capabilities. Recheck those capabilities on replay.
3. On a miss lock the source head, verify the expected head and target ancestry, and
   validate the proposed input, attachments, effective configuration and budget. Refuse a
   stale head, or an append to a branch with a nonterminal run, with `409 conflict`.
   Apply the graph operation above. Build `RunAdmission` with the destination branch and
   stable user input, session approval, required capabilities and requested rounds, then
   call `admit_run` in the same transaction. It repeats the replay
   lookup under its locks. Commit **only** `Admission::Admitted` with the graph writes,
   queued run and sequence-one `run-created` event. Roll back the whole transaction on
   replay, refusal, conflict or error. An uncertain commit is retried with the original
   intent and key. Actor/scope limits map to `429 rate_limited`, a full queue to
   `503 unavailable` with `Retry-After`. [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md).
4. Cancellation hydrates the current principal, derives the run scope and checks current
   conversation visibility. Conceal a run belonging to another actor even when the
   conversation is shared. Call `cancel_run`.
   `CancelOutcome::Cancelled` (queued/waiting) and `Terminal { state }` return `200`.
   `Requested { state }` returns `202` while the lease holder settles executing work.
   Repeats preserve the first reason and append no second cancellation event. For creation,
   replay and cancellation reuse the authorized, consistent ADR 0034 `Run` projection in
   `src/v1/runs.rs`, including its resume cursor and terminal projection. Add optional
   `branch_id` and `input_message_id` to that schema so a caller can select a fork.
   [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md).

## Delivery and verification

| Slice | Evidence required |
| --- | --- |
| PR1 (this record) | ADR 0036 and the pointer in ADR 0007. Existing contract and hygiene checks only. |
| PR2 · persistence and resolver | Apply the new migration on fresh and populated PostgreSQL 18. Exercise old writers and pre-migration skeletons. Test root/append/edit/retry, shared ancestry, ordered parts, stable revision IDs and unchanged charges. Reject foreign parents, revisions and forged producers. Exercise actual allowed and denied SQL under both roles, including API reasoning reads and content updates. Race two writers at one head. |
| PR2 · configuration fixtures | Check inheritance at all four layers, study instructions, source attribution, explicit default effort versus omission, undeclared effort/sampling, inherited and unknown capacity with/without a qualified ceiling, reserve exhaustion and exact-fit input. Fork a measured path, change profile and append an unmeasured turn. Verify measured, estimated and unknown fields independently. Exercise the replay decision with a qualified fixture, a mismatched format and an undeclared target. |
| PR3 · API and contract | Serve the operations, supply admission limits, update OpenAPI 3.2.1, regenerate fixtures and exercise the independent consumer. Test both session channels, concealment before/after revocation, personal Write versus RunExecute, stale/tampered cursors, ordered history, extensible responses and redaction canaries. Concurrent identical and changed submissions, a lost response, changed defaults, archive, actor/scope limits, a full queue and cancellation must yield the specified statuses, graph and event counts on PostgreSQL 18. |
| PR4 · live turn executor | After V1-08 supplies a qualified gateway/provider adapter and ADR 0033's worker loop lands, wire the model/tool turn into `src/worker.rs`. Use the pinned snapshot, recheck current authority before every provider/tool step, honor cancellation and deadlines, and fence result writes on the live claim. Atomically publish the assistant child, parts, reasoning, usage and head advance with successful settlement. A lost lease or failed settlement cannot publish an answer. Test restart and cancellation races, reasoning-only output, qualified and refused replay, and actual provider usage. |

V1-07 PR2/PR3 use fixtures and durable admission without a live provider. V1-08 owns
protocol translation, conformance fixtures and qualification of the pinned SGLang and
external profiles. The PR4 integration consumes that adapter once. Only its live evidence
can establish end-to-end execution, usage accuracy or replay compatibility.
