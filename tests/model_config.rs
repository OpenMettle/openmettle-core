use openmettle_core::{
    authz::projects::ProjectSettings,
    model_config::{Catalog, Error, PathTurn, PromptEstimate, ReplaySource, Selection, Source},
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
        e.omissions
            .iter()
            .map(|o| (o.control.as_str(), o.source, o.reason.as_str()))
            .collect::<Vec<_>>(),
        [
            ("temperature", Source::Preset, "unsupported_by_target"),
            ("reasoning_effort", Source::Project, "unsupported_by_target")
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
