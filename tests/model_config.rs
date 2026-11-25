use openmettle_core::{
    authz::projects::ProjectSettings,
    model_config::{
        Catalog, Effective, Error, PathTurn, PromptEstimate, ReplaySource, Selection, Source,
    },
};
use serde_json::{Value, json};

const FIXTURE: &[u8] = include_bytes!("fixtures/conversation-catalog-v1.json");

fn catalog(edit: impl FnOnce(&mut Value)) -> Result<Catalog, Error> {
    let mut doc: Value = serde_json::from_slice(FIXTURE).unwrap();
    edit(&mut doc);
    Catalog::load(&serde_json::to_vec(&doc).unwrap())
}
fn selection(value: Value) -> Selection {
    serde_json::from_value(value).unwrap()
}
fn study() -> Selection {
    selection(json!({"preset":"study"}))
}
fn permit(_: &str, _: Option<&str>) -> bool {
    true
}

fn omissions(e: &Effective) -> Vec<(Source, &str, &str)> {
    e.omissions
        .iter()
        .map(|o| (o.source, o.control.as_str(), o.reason.as_str()))
        .collect()
}

#[test]
fn catalog_roundtrip_and_validation() {
    let c = Catalog::load(FIXTURE).unwrap();
    assert_eq!(Catalog::load(&c.bytes()).unwrap().bytes(), c.bytes());
    for (path, value) in [
        ("/version", json!(2)),
        ("/presets/study/model", json!("missing")),
        ("/models/a/default_effort", json!("undeclared")),
        ("/models/a/pin/parser", json!("")),
        ("/models/a/temperature/min", json!(3)),
        ("/models/a/context_window", json!(0)),
        ("/models/b/replay/0/max_tokens_per_byte", json!(0)),
    ] {
        assert!(
            catalog(|d| *d.pointer_mut(path).unwrap() = value).is_err(),
            "{path}"
        );
    }
    assert!(Catalog::load(br#"{"version":1,"revision":"empty","models":{},"presets":{}}"#).is_ok());
}

/// A JSON object keeps its last repeated member, so every catalog map refuses repeats instead
/// of silently selecting one profile, preset or capability gate.
#[test]
fn repeated_map_members_are_refused() {
    let mut doc: Value = serde_json::from_slice(FIXTURE).unwrap();
    doc["models"]["a"]["required_capabilities"] = json!({"model.a": "on_by_default"});
    let text = doc.to_string();
    assert!(Catalog::load(text.as_bytes()).is_ok());
    let mut other = doc["models"]["a"].clone();
    other["pin"]["revision"] = json!("profile-a/2");
    for (object, member, value) in [
        ("models", "a", other.to_string()),
        ("presets", "study", doc["presets"]["study"].to_string()),
        ("required_capabilities", "model.a", "\"opt_in\"".to_owned()),
    ] {
        let opening = format!("\"{object}\":{{");
        let repeated = text.replacen(&opening, &format!("{opening}\"{member}\":{value},"), 1);
        assert_ne!(repeated, text, "{object}");
        assert!(
            matches!(Catalog::load(repeated.as_bytes()), Err(Error::Invalid(_))),
            "{object}"
        );
    }
}

#[test]
fn sources_instructions_selection_and_typed_project_settings() {
    let c = Catalog::load(FIXTURE).unwrap();
    let mut settings = ProjectSettings {
        project_id: "p".into(),
        scope_id: "s".into(),
        name: "Synthetic".into(),
        defaults: json!({"other":true}),
        instructions: "Project instruction.".into(),
        revision: 3,
        archived: false,
        deleted: false,
    };
    let legacy = Selection::project(&settings).unwrap();
    assert!(legacy.preset.is_none() && legacy.layer.controls.output_reserve.is_none());
    settings.defaults["model_config"] = json!({"preset":"study","controls":{"top_p":0.8}});
    let project = Selection::project(&settings).unwrap();
    let request = selection(
        json!({"layer":{"instructions":"Request instruction.","controls":{"temperature":0.9}}}),
    );
    let e = c.resolve(&project, &request, Some(3), permit).unwrap();
    assert_eq!(
        e.instructions
            .iter()
            .map(|i| (i.source, i.text.as_str()))
            .collect::<Vec<_>>(),
        [
            (Source::Model, "Base guidance."),
            (Source::Preset, "Give a hint before the answer."),
            (Source::Project, "Project instruction."),
            (Source::Request, "Request instruction.")
        ]
    );
    assert_eq!(
        (e.context_window.value, e.context_window.source),
        (Some(8192), Source::Model)
    );
    assert_eq!(
        (e.output_reserve.value, e.output_reserve.source),
        (Some(1024), Source::Preset)
    );
    assert_eq!(e.usable_input(), Some(7168));
    assert_eq!(
        (e.temperature.value, e.temperature.source),
        (Some(0.9), Source::Request)
    );
    assert_eq!(
        (e.top_p.value, e.top_p.source),
        (Some(0.8), Source::Project)
    );
    assert_eq!(
        (
            e.project_revision,
            e.preset_revision.as_deref(),
            e.catalog_revision.as_str()
        ),
        (Some(3), Some("study/1"), "catalog/1")
    );
    assert!(matches!(
        c.resolve(&project, &request, None, |_, _| false),
        Err(Error::Unauthorized)
    ));
    let mut invalid = project.clone();
    invalid.layer.instructions = Some("invalid\0instruction".into());
    assert!(matches!(
        c.resolve(&invalid, &request, None, permit),
        Err(Error::Invalid("instructions"))
    ));
    assert!(
        c.resolve(
            &project,
            &selection(json!({"preset":"study","model":"b"})),
            None,
            permit
        )
        .is_err()
    );
    settings.defaults["model_config"] = json!({"unknown":true});
    assert!(Selection::project(&settings).is_err());
}

#[test]
fn omission_explicit_default_unsupported_controls_and_switches() {
    let c = Catalog::load(FIXTURE).unwrap();
    let empty = Selection::default();
    let project =
        selection(json!({"preset":"study","layer":{"controls":{"reasoning_effort":"high"}}}));
    let e = c.resolve(&empty, &study(), None, permit).unwrap();
    assert_eq!(
        (e.reasoning_effort.value, e.reasoning_effort.source),
        (None, Source::GatewayDefault)
    );
    let e = c
        .resolve(
            &project,
            &selection(json!({"layer":{"controls":{"reasoning_effort":"default"}}})),
            None,
            permit,
        )
        .unwrap();
    assert_eq!(
        (
            e.reasoning_effort.value.as_deref(),
            e.reasoning_effort.source
        ),
        (Some("medium"), Source::Request)
    );
    let preset_default = catalog(|d| {
        d["presets"]["study"]["defaults"]["controls"]["reasoning_effort"] = json!("default")
    })
    .unwrap();
    let e = preset_default
        .resolve(&empty, &study(), None, permit)
        .unwrap();
    assert_eq!(
        (
            e.reasoning_effort.value.as_deref(),
            e.reasoning_effort.source
        ),
        (Some("medium"), Source::Preset)
    );
    for controls in [
        json!({"temperature":0.2}),
        json!({"top_p":0.7}),
        json!({"reasoning_effort":"default"}),
        json!({"reasoning_effort":"high"}),
    ] {
        assert!(
            c.resolve(
                &project,
                &selection(json!({"model":"b","layer":{"controls":controls}})),
                None,
                permit
            )
            .is_err()
        );
    }
    let e = c
        .resolve(&project, &selection(json!({"model":"b"})), None, permit)
        .unwrap();
    assert_eq!(
        omissions(&e),
        [
            (Source::Preset, "temperature", "unsupported_by_target"),
            (Source::Project, "reasoning_effort", "unsupported_by_target")
        ]
    );
    for control in [
        json!({"top_p":0}),
        json!({"reasoning_effort":"invented"}),
        json!({"temperature":2}),
    ] {
        assert!(
            c.resolve(
                &empty,
                &selection(json!({"model":"a","layer":{"controls":control}})),
                None,
                permit
            )
            .is_err()
        );
    }
    let c = catalog(|d| d["models"]["a"]["joint_sampling"] = false.into()).unwrap();
    let mut r = selection(json!({"model":"a","layer":{"controls":{"top_p":0.8}}}));
    assert!(c.resolve(&empty, &r, None, permit).is_err());
    r.layer.controls.top_p = Some(f64::NAN);
    assert!(c.resolve(&empty, &r, None, permit).is_err());
}

#[test]
fn model_switch_validates_only_winning_values_against_target_bounds() {
    let c = catalog(|d| {
        let b = &mut d["models"]["b"];
        b["temperature"] = json!({"min":0.0,"max":1.0});
        b["top_p"] = json!({"min":0.1,"max":0.8});
        b["joint_sampling"] = json!(true);
    })
    .unwrap();
    let inherited = json!({
        "temperature":1.5, "top_p":0.9, "context_window":7000, "output_reserve":3000
    });
    let project = selection(json!({"model":"a","layer":{"controls":inherited}}));
    c.resolve(&project, &Selection::default(), None, permit)
        .unwrap();
    let request = selection(json!({"model":"b","layer":{"controls":{
        "temperature":0.7, "top_p":0.6, "context_window":5000, "output_reserve":1024
    }}}));
    let e = c.resolve(&project, &request, None, permit).unwrap();
    assert_eq!(
        (e.temperature.value, e.temperature.source),
        (Some(0.7), Source::Request)
    );
    assert_eq!(
        (e.top_p.value, e.top_p.source),
        (Some(0.6), Source::Request)
    );
    assert_eq!(
        (e.ceiling.value, e.ceiling.source),
        (Some(5000), Source::Request)
    );
    assert_eq!(e.context_window.value, None);
    assert_eq!(
        (e.output_reserve.value, e.output_reserve.source),
        (Some(1024), Source::Request)
    );
    assert!(e.omissions.is_empty());

    let switch = selection(json!({"model":"b"}));
    for control in ["temperature", "top_p", "context_window", "output_reserve"] {
        let project =
            selection(json!({"model":"a","layer":{"controls":{(control):inherited[control]}}}));
        assert_eq!(
            c.resolve(&project, &switch, None, permit).err(),
            Some(Error::Invalid(control))
        );
    }
}

#[test]
fn model_switch_omits_unsupported_effort_only_until_a_layer_supplies_it() {
    let c = catalog(|d| {
        d["models"]["b"]["efforts"] = json!(["low", "medium"]);
        d["models"]["b"]["defaults"]["controls"] = json!({"reasoning_effort":"low"});
        d["presets"]["high-a"] = json!({"model":"a", "revision":"a/1",
            "defaults":{"controls":{"reasoning_effort":"high"}}});
        d["presets"]["medium-b"] = json!({"model":"b", "revision":"b/1",
            "defaults":{"controls":{"reasoning_effort":"medium"}}});
    })
    .unwrap();
    let project =
        selection(json!({"preset":"high-a","layer":{"controls":{"reasoning_effort":"high"}}}));
    let dropped = |source| (source, "reasoning_effort", "unsupported_by_target");
    for (request, effort, source, expected_omissions) in [
        (
            json!({"model":"b","layer":{"controls":{"reasoning_effort":"low"}}}),
            "low",
            Source::Request,
            vec![],
        ),
        (
            json!({"preset":"medium-b"}),
            "medium",
            Source::Preset,
            vec![dropped(Source::Project)],
        ),
        (
            json!({"model":"b"}),
            "low",
            Source::Model,
            vec![dropped(Source::Preset), dropped(Source::Project)],
        ),
    ] {
        let e = c
            .resolve(&project, &selection(request), None, permit)
            .unwrap();
        assert_eq!(
            (
                e.reasoning_effort.value.as_deref(),
                e.reasoning_effort.source
            ),
            (Some(effort), source)
        );
        assert_eq!(omissions(&e), expected_omissions);
    }
}

#[test]
fn model_switch_to_unknown_capacity_omits_only_inherited_window() {
    let c = catalog(|d| d["models"]["b"]["conservative_ceiling"] = Value::Null).unwrap();
    let project = selection(json!({"model":"a","layer":{"controls":{"context_window":7000}}}));
    let mut request = selection(json!({"model":"b"}));
    let e = c.resolve(&project, &request, None, permit).unwrap();
    assert_eq!((e.context_window.value, e.ceiling.value), (None, None));
    assert_eq!(
        omissions(&e),
        [(Source::Project, "context_window", "unsupported_by_target")]
    );
    request.layer.controls.context_window = Some(5000);
    assert!(matches!(
        c.resolve(&project, &request, None, permit),
        Err(Error::Invalid("context_window"))
    ));
}

#[test]
fn request_window_can_replace_a_preset_limit_within_the_target_profile() {
    let c = catalog(|d| {
        d["presets"]["compact"] = json!({
            "model":"a", "revision":"compact/1", "defaults":{"controls":{"context_window":4096}}
        });
    })
    .unwrap();
    let project = selection(json!({"preset":"compact"}));
    let mut request = selection(json!({"layer":{"controls":{"context_window":6144}}}));
    let e = c.resolve(&project, &request, None, permit).unwrap();
    assert_eq!(
        (e.context_window.value, e.context_window.source),
        (Some(6144), Source::Request)
    );
    assert_eq!(
        (e.ceiling.value, e.ceiling.source),
        (Some(6144), Source::Request)
    );

    request.model = Some("b".into());
    request.layer.controls.context_window = Some(5000);
    let e = c.resolve(&project, &request, None, permit).unwrap();
    assert_eq!(
        (e.model.as_str(), e.preset.as_deref()),
        ("b", Some("compact"))
    );
    assert_eq!(e.context_window.value, None);
    assert_eq!(
        (e.ceiling.value, e.ceiling.source),
        (Some(5000), Source::Request)
    );
    request.layer.controls.context_window = Some(6145);
    assert!(matches!(
        c.resolve(&project, &request, None, permit),
        Err(Error::Invalid("context_window"))
    ));
}

#[test]
fn request_preset_can_replace_a_retired_project_preset() {
    let c = Catalog::load(FIXTURE).unwrap();
    let project = selection(
        json!({"preset":"retired_preset", "layer":{"controls":{"reasoning_effort":"retired_level"}}}),
    );
    let e = c
        .resolve(&project, &study(), None, |model, preset| {
            model == "a" && preset == Some("study")
        })
        .unwrap();
    assert_eq!(e.preset_source, Some(Source::Request));
    assert_eq!(e.reasoning_effort.value, None);
    assert_eq!(e.omissions.len(), 1);
    assert_eq!(
        (e.omissions[0].source, e.omissions[0].control.as_str()),
        (Source::Project, "reasoning_effort")
    );
    for request in [Selection::default(), selection(json!({"model":"b"}))] {
        assert!(matches!(
            c.resolve(&project, &request, None, permit),
            Err(Error::Invalid("preset"))
        ));
    }
}

#[test]
fn explicit_selection_omits_unsupported_unpinned_project_controls() {
    let c = catalog(|d| {
        d["presets"]["b-preset"] = json!({"model":"b","revision":"b/1","defaults":{}});
    })
    .unwrap();
    let project = selection(json!({"layer":{"controls":{"temperature":0.5}}}));
    for request in [
        selection(json!({"model":"b"})),
        selection(json!({"preset":"b-preset"})),
    ] {
        let e = c.resolve(&project, &request, None, permit).unwrap();
        assert_eq!(e.temperature.value, None);
        assert_eq!(e.omissions.len(), 1);
        let omission = &e.omissions[0];
        assert_eq!(
            (
                omission.source,
                omission.control.as_str(),
                omission.reason.as_str()
            ),
            (Source::Project, "temperature", "unsupported_by_target")
        );
    }
}

#[test]
fn inherited_preset_requires_a_matching_project_model() {
    let c = Catalog::load(FIXTURE).unwrap();
    let project = selection(json!({"preset":"study","model":"b"}));
    assert!(matches!(
        c.resolve(&project, &Selection::default(), None, permit),
        Err(Error::Invalid("preset base model"))
    ));
}

#[test]
fn capacity_reserve_qualified_estimates_and_exact_fit() {
    let empty = Selection::default();
    for (window, safe, usable) in [
        (Some(8192), None, Some(7168)),
        (None, None, None),
        (None, Some(4096), Some(3072)),
    ] {
        let c = catalog(|d| {
            d["models"]["a"]["context_window"] = json!(window);
            d["models"]["a"]["conservative_ceiling"] = json!(safe);
        })
        .unwrap();
        let e = c.resolve(&empty, &study(), None, permit).unwrap();
        assert_eq!(
            (e.context_window.value, e.ceiling.value, e.usable_input()),
            (window, window.or(safe), usable)
        );
        let mut p = PromptEstimate {
            profile: &e.profile,
            revision: "fixture-bound/1",
            history: Some(usable.unwrap_or(10) - 4),
            instructions: Some(1),
            proposed_input: Some(1),
            tools: Some(1),
            attachments: Some(1),
        };
        assert_eq!(
            c.budget(&e, &[], Some(&p)).unwrap().admit(),
            usable.map_or(Err(Error::Provisioning), |_| Ok(()))
        );
        p.instructions = Some(2);
        assert!(c.budget(&e, &[], Some(&p)).unwrap().admit().is_err());
        p.attachments = None;
        assert_eq!(
            c.budget(&e, &[], Some(&p)).unwrap().admit(),
            Err(Error::Provisioning)
        );
    }
    let c = Catalog::load(FIXTURE).unwrap();
    let e = c
        .resolve(&empty, &selection(json!({"model":"a"})), None, permit)
        .unwrap();
    assert!(e.usable_input().is_none());
    for controls in [
        json!({"context_window":512,"output_reserve":513}),
        json!({"output_reserve":4097}),
        json!({"output_reserve":0}),
        json!({"context_window":8193}),
    ] {
        assert!(
            c.resolve(
                &empty,
                &selection(json!({"model":"a","layer":{"controls":controls}})),
                None,
                permit
            )
            .is_err()
        );
    }
    let r = selection(json!({"layer":{"controls":{"context_window":1024,"output_reserve":1024}}}));
    let e = c.resolve(&study(), &r, None, permit).unwrap();
    assert_eq!(
        (e.usable_input(), e.context_window.source),
        (Some(0), Source::Request)
    );
}

#[test]
fn measured_path_profile_switch_and_replay_gate() {
    let c = Catalog::load(FIXTURE).unwrap();
    let a = c.model("a").unwrap();
    let b = c.model("b").unwrap();
    let src = ReplaySource {
        profile: a.pin.clone(),
        format: "blocks/1".into(),
    };
    let blocks = vec![serde_json::from_value(json!({"fixture":"private block"})).unwrap()];
    assert!(b.replay_blocks(Some(&src), Some(&blocks)).is_some());
    assert!(a.replay_blocks(Some(&src), Some(&blocks)).is_none());
    let mut changed = src.clone();
    changed.format = "other".into();
    assert!(b.replay_blocks(Some(&changed), Some(&blocks)).is_none());
    changed = src.clone();
    changed.profile.parser = "other".into();
    assert!(b.replay_blocks(Some(&changed), Some(&blocks)).is_none());
    assert!(b.replay_blocks(None, Some(&blocks)).is_none());
    let measured = PathTurn {
        message_id: "m".into(),
        run_id: Some("r".into()),
        profile: Some(a.pin.clone()),
        reasoning_format: Some(src.format),
        reasoning_bytes: 11,
        input_count: Some(92),
        output_count: None,
    };
    let sibling = PathTurn {
        message_id: "sibling".into(),
        input_count: Some(945),
        ..measured.clone()
    };
    let fork = PathTurn {
        message_id: "new".into(),
        input_count: None,
        output_count: None,
        reasoning_bytes: 0,
        ..measured.clone()
    };
    let original = [sibling, measured.clone()];
    let path = [fork, measured];
    let e = c
        .resolve(&study(), &selection(json!({"model":"b"})), None, permit)
        .unwrap();
    let mut p = PromptEstimate {
        profile: &b.pin,
        revision: "fixture-bound/2",
        instructions: Some(1),
        history: Some(15),
        proposed_input: Some(1),
        tools: Some(2),
        attachments: Some(1),
    };
    assert_eq!(
        c.budget(&e, &original, None)
            .unwrap()
            .measured
            .unwrap()
            .input_count,
        Some(945)
    );
    let budget = c.budget(&e, &path, Some(&p)).unwrap();
    let m = budget.measured.unwrap();
    assert_eq!(
        (
            m.message_id.as_str(),
            m.run_id.as_deref(),
            m.input_count,
            m.output_count
        ),
        ("m", Some("r"), Some(92), None)
    );
    assert_eq!(m.profile.as_ref().unwrap().revision, a.pin.revision);
    assert_eq!(budget.estimated.unwrap().upper_bound, 20 + 22 + 7);
    p.revision = "unqualified";
    let budget = c.budget(&e, &path, Some(&p)).unwrap();
    assert!(budget.measured.is_some() && budget.estimated.is_none());
    assert_eq!(budget.admit(), Err(Error::Provisioning));
    assert!(c.budget(&e, &path[..1], None).unwrap().measured.is_none());
}

#[test]
fn cost_bound_and_device_slot_catalog_rules() {
    let base = Catalog::load(FIXTURE).unwrap();
    let a = base.model("a").unwrap();
    assert!(a.cost_bound.is_none());
    assert!(!a.requires_device_slot);
    assert_eq!(a.round_cost_ceiling(8192), Ok(None));

    // Invalid cost_bound configurations are rejected at catalog load time.
    for invalid in [
        json!({"fixed_micros": 0, "micros_per_token": 0}),
        json!({"fixed_micros": (i64::MAX as u64) + 1, "micros_per_token": 1}),
        json!({"fixed_micros": 0, "micros_per_token": (i64::MAX as u64) + 1}),
        json!({"fixed_micros": 1, "micros_per_token": 1, "extra": true}),
    ] {
        assert!(
            catalog(|d| d["models"]["a"]["cost_bound"] = invalid.clone()).is_err(),
            "{invalid}"
        );
    }

    let c = catalog(|d| {
        d["models"]["a"]["cost_bound"] = json!({"fixed_micros": 50, "micros_per_token": 2});
        d["models"]["a"]["requires_device_slot"] = json!(true);
    })
    .unwrap();
    let p = c.model("a").unwrap();
    assert!(p.requires_device_slot);
    assert_eq!(p.round_cost_ceiling(600), Ok(Some(1250)));
    assert_eq!(
        p.round_cost_ceiling(u64::MAX),
        Ok(Some(u128::from(u64::MAX) * 2 + 50))
    );
    let huge = catalog(|d| {
        d["models"]["a"]["cost_bound"] = json!({"fixed_micros": i64::MAX, "micros_per_token": 1});
    })
    .unwrap();
    assert_eq!(
        huge.model("a").unwrap().round_cost_ceiling(600),
        Ok(Some(u128::from(i64::MAX as u64) + 600))
    );

    let e = c
        .resolve(
            &Selection::default(),
            &selection(json!({"model": "a", "layer": {"controls": {"context_window": 600, "output_reserve": 100}}})),
            None,
            permit,
        )
        .unwrap();
    assert_eq!(c.round_cost_ceiling(&e), Ok(Some(1250)));
    // Roundtrip serialization preserves cost_bound and requires_device_slot.
    let reloaded = Catalog::load(&c.bytes()).unwrap();
    assert_eq!(reloaded.model("a").unwrap().cost_bound, p.cost_bound);
    assert!(reloaded.model("a").unwrap().requires_device_slot);
}

#[test]
fn resolve_with_fallback_skips_restricted_defaults_without_relaxing_explicit_selections() {
    let c = Catalog::load(FIXTURE).unwrap();
    let project_a = selection(json!({
        "preset": "study",
        "layer": {"instructions": "Project guide.", "controls": {"reasoning_effort": "high"}}
    }));
    let empty = Selection::default();

    // Explicit disallowed model or preset never falls back.
    assert_eq!(
        c.resolve_with_fallback(&empty, &selection(json!({"model": "a"})), None, |m, _| m
            == "b")
            .err(),
        Some(Error::Unauthorized)
    );
    assert_eq!(
        c.resolve_with_fallback(&empty, &study(), None, |m, _| m == "b")
            .err(),
        Some(Error::Unauthorized)
    );

    // Omitted request selection with disallowed project default falls back deterministically to "b",
    // dropping project controls unsupported by "b" into omissions and preserving instructions.
    let e = c
        .resolve_with_fallback(&project_a, &empty, Some(4), |m, _| m == "b")
        .unwrap();
    assert_eq!(e.model, "b");
    assert_eq!(e.model_source, Source::Model);
    assert_eq!(e.preset, None);
    assert_eq!(e.project_revision, Some(4));
    assert_eq!(
        omissions(&e),
        vec![(Source::Project, "reasoning_effort", "unsupported_by_target")]
    );
    assert!(
        e.instructions
            .iter()
            .any(|i| i.source == Source::Project && i.text == "Project guide.")
    );

    // Active quiet hours (zero models permitted): unauthorized with or without a project default.
    assert_eq!(
        c.resolve_with_fallback(&project_a, &empty, None, |_, _| false)
            .err(),
        Some(Error::Unauthorized)
    );
    assert_eq!(
        c.resolve_with_fallback(&empty, &empty, None, |_, _| false)
            .err(),
        Some(Error::Unauthorized)
    );

    // Empty catalog with no selection still returns Invalid("model selection").
    let bare =
        Catalog::load(br#"{"version":1,"revision":"empty","models":{},"presets":{}}"#).unwrap();
    assert_eq!(
        bare.resolve_with_fallback(&empty, &empty, None, |_, _| true)
            .err(),
        Some(Error::Invalid("model selection"))
    );

    // Retired/unknown project preset is not masked by fallback.
    let broken_project = selection(json!({"preset": "retired"}));
    assert_eq!(
        c.resolve_with_fallback(&broken_project, &empty, None, |_, _| true)
            .err(),
        Some(Error::Invalid("preset"))
    );
}
