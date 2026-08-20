//! SUR-1042 integration: the question entity's two acceptance criteria, end to end on the
//! two-engine fixture (`tests/common`) — **"encrypted round-trip identical on both platforms"** and
//! **"effective note set converges across devices"**.
//!
//! Both are convergence claims, and neither is provable from a single engine. A one-device test
//! shows a seal round-tripping through its own vault, which proves nothing about the wire; and the
//! effective set is a *derivation over synced rows*, so "it converges" is a statement about what two
//! devices compute after exchanging override rows, not about the derivation in isolation.
//!
//! What this pins that the unit tests cannot:
//!   (1) a question sealed on A crosses the cloud as `enc:v2` ciphertext and decrypts to the same
//!       plaintext on B — the server holding a blob it cannot read is the whole E2EE claim;
//!   (2) contradictory curation of the SAME (question, note) pair on two devices converges to ONE
//!       row by whole-row LWW, not two rows — the deterministic-pk OR-set property;
//!   (3) the effective note set is then IDENTICAL on both devices.
//!
//! Deliberately NOT here: the `fk_deps` hold-back that stops an override reaching the cloud before
//! its endpoints (surfc 0055's RLS `WITH CHECK` would reject it as `42501`). That is pinned twice at
//! unit level — `flush_dispatches_all_eight_tables_in_topological_order` and
//! `an_override_is_held_back_when_its_question_fails` — and asserting it here would have meant
//! adding a `change_seq` accessor to the shared fixture to re-prove a settled property.
//!
//! OFFLINE + deterministic (no Supabase, no env guard, NOT `#[ignore]`d), like
//! `sync_736_integration.rs` and `sync_976_integration.rs`. The real-PostgREST leg for these three
//! tables already exists as `sync_1049_integration.rs`.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use braird_core::store::override_id;
use braird_core::sync::{pull_then_flush, NoteUpsert, QuestionNoteOverride, QuestionUpsert};
use common::{block, tick, Device, SharedCloud};
use serde_json::json;

const USER: &str = "user-1";
const TABLES: &[&str] = &["notes", "questions", "question_note_overrides"];

fn note(id: &str, created_at: i64) -> NoteUpsert {
    NoteUpsert {
        id: id.into(),
        book_id: None,
        plaintext: Some(format!("note {id}")),
        page: None,
        tags: vec![],
        source: Some("manual".into()),
        source_id: None,
        source_meta_json: None,
        chapter: None,
        image_path: None,
        ink_crop_path: None,
        created_at,
        deleted: false,
        clear_nullable_fields: vec![],
    }
}

fn question(id: &str, plaintext: &str) -> QuestionUpsert {
    QuestionUpsert {
        id: id.into(),
        plaintext: Some(plaintext.into()),
        status: Some("active".into()),
        tone: Some("introspective".into()),
        resolved_at: None,
        checkin_at: None,
        checkin_response: None,
        created_at: 100,
        deleted: false,
    }
}

fn override_row(note_id: &str, kind: &str, deleted: bool) -> QuestionNoteOverride {
    QuestionNoteOverride {
        question_id: "q1".into(),
        note_id: note_id.into(),
        kind: kind.into(),
        deleted,
    }
}

fn sync(device: &Device, cloud: &SharedCloud) {
    block(pull_then_flush(
        &device.store,
        cloud,
        USER,
        TABLES,
        &device.vault,
    ))
    .expect("clean pull_then_flush");
}

/// `now` for the active-window join. Comfortably past every `created_at` the tests use, so an
/// unresolved question's window is open — the derivation takes it as a parameter precisely so a
/// convergence test does not depend on a wall clock.
const NOW: i64 = 10_000;

#[test]
fn a_question_sealed_on_one_device_decrypts_on_the_other_and_never_crosses_in_plaintext() {
    let vault = braird_core::Vault::generate();
    let cloud = SharedCloud::new();
    let a = Device::new(vault.clone());
    let b = Device::new(vault.clone());

    a.engine
        .enqueue_question(question("q1", "what am I avoiding?"))
        .unwrap();
    sync(&a, &cloud);

    // The SERVER's copy is opaque. This is the E2EE claim stated as an assertion: what reaches the
    // cloud is an `enc:v2` blob, not the question.
    let stored = cloud
        .row("questions", "q1")
        .expect("the question reached the cloud");
    let ciphertext = stored["text"].as_str().unwrap();
    assert!(ciphertext.starts_with("enc:v2:"));
    assert!(
        !ciphertext.contains("avoiding"),
        "the cloud must never hold question plaintext"
    );

    // B pulls and reads it back through its own vault — the same account MK, a different device.
    sync(&b, &cloud);
    let on_b = b
        .engine
        .get_question("q1".into())
        .unwrap()
        .expect("q1 on B");
    assert_eq!(on_b.text.as_deref(), Some("what am I avoiding?"));
    assert!(!on_b.decrypt_failed);
    assert_eq!(on_b.status.as_deref(), Some("active"));
}

#[test]
fn contradictory_curation_of_one_pair_converges_to_a_single_row_and_the_same_effective_set() {
    let vault = braird_core::Vault::generate();
    let cloud = SharedCloud::new();
    let a = Device::new(vault.clone());
    let b = Device::new(vault.clone());

    // Shared history: one question and two notes, both captured inside its active window.
    a.engine
        .enqueue_question(question("q1", "the question"))
        .unwrap();
    a.engine.enqueue_note(note("n-in", 150)).unwrap();
    a.engine.enqueue_note(note("n-pin", 50)).unwrap(); // BEFORE the window opened
    sync(&a, &cloud);
    sync(&b, &cloud);

    // A pins the out-of-window note. B, concurrently, excludes the in-window one.
    a.engine
        .enqueue_question_note_override(override_row("n-pin", "include", false))
        .unwrap();
    tick();
    b.engine
        .enqueue_question_note_override(override_row("n-in", "exclude", false))
        .unwrap();
    sync(&a, &cloud);
    sync(&b, &cloud);
    sync(&a, &cloud);

    // (2) One row per pair — the deterministic pk, not a bag of edges.
    assert!(cloud
        .row("question_note_overrides", &override_id("q1", "n-pin"))
        .is_some());
    assert!(cloud
        .row("question_note_overrides", &override_id("q1", "n-in"))
        .is_some());

    // (3) Both devices compute the SAME effective set: the pinned note only — `n-in` was excluded,
    // and `n-pin` is in solely because of the include.
    let ids = |d: &Device| {
        let mut v: Vec<String> = d
            .engine
            .question_notes("q1".into(), NOW)
            .unwrap()
            .into_iter()
            .map(|n| n.id)
            .collect();
        v.sort();
        v
    };
    assert_eq!(ids(&a), vec!["n-pin".to_string()]);
    assert_eq!(ids(&a), ids(&b), "the effective note set must converge");
}

#[test]
fn a_reversed_override_converges_on_the_later_write_not_on_both() {
    // Whole-row LWW on a deterministic pk: A includes, then B excludes the same pair later. The
    // surviving `kind` IS the answer — there is no include-vs-exclude precedence rule, and there
    // must not be two rows to reconcile.
    let vault = braird_core::Vault::generate();
    let cloud = SharedCloud::new();
    let a = Device::new(vault.clone());
    let b = Device::new(vault.clone());

    a.engine
        .enqueue_question(question("q1", "the question"))
        .unwrap();
    a.engine.enqueue_note(note("n1", 50)).unwrap(); // outside the window; only an include puts it in
    sync(&a, &cloud);
    sync(&b, &cloud);

    a.engine
        .enqueue_question_note_override(override_row("n1", "include", false))
        .unwrap();
    sync(&a, &cloud);
    sync(&b, &cloud);
    assert_eq!(
        b.engine.question_notes("q1".into(), NOW).unwrap().len(),
        1,
        "precondition: B sees the pinned note"
    );

    tick();
    b.engine
        .enqueue_question_note_override(override_row("n1", "exclude", false))
        .unwrap();
    sync(&b, &cloud);
    sync(&a, &cloud);

    assert_eq!(
        cloud
            .row("question_note_overrides", &override_id("q1", "n1"))
            .unwrap()["kind"],
        json!("exclude"),
        "the later write wins the whole row"
    );
    assert!(a
        .engine
        .question_notes("q1".into(), NOW)
        .unwrap()
        .is_empty());
    assert!(b
        .engine
        .question_notes("q1".into(), NOW)
        .unwrap()
        .is_empty());
}

#[test]
fn the_question_log_renders_identically_on_both_devices() {
    // SUR-1071's acceptance criterion — "same outputs on both platforms via the shared core" — is a
    // convergence claim like the two above, so it is proved the same way: two engines, one cloud,
    // and a byte-for-byte comparison of what each would render. The unit tests pin the derivation;
    // only this pins that two devices holding synced rows produce the SAME list, in the SAME order,
    // with the SAME counts. Both platforms consume this one function, so agreeing here is what
    // "identical on iOS and Android" actually reduces to.
    let vault = braird_core::Vault::generate();
    let cloud = SharedCloud::new();
    let a = Device::new(vault.clone());
    let b = Device::new(vault.clone());

    // An older question the user has since resolved, and the current one. `q1` is born at 100 (the
    // `question` helper) and `q0` earlier, so newest-first and active-first disagree about the
    // order — which is what makes the assertion worth making.
    a.engine
        .enqueue_question(QuestionUpsert {
            created_at: 400,
            status: Some("resolved".into()),
            resolved_at: Some(500),
            ..question("q0", "the question I closed")
        })
        .unwrap();
    a.engine
        .enqueue_question(question("q1", "the question I am sitting with"))
        .unwrap();
    a.engine.enqueue_note(note("n-in", 150)).unwrap();
    a.engine.enqueue_note(note("n-old", 50)).unwrap();
    a.engine
        .enqueue_question_note_override(override_row("n-old", "include", false))
        .unwrap();
    sync(&a, &cloud);
    sync(&b, &cloud);

    let log = |d: &Device| {
        d.engine
            .list_questions(NOW)
            .unwrap()
            .into_iter()
            .map(|e| (e.question.id, e.question.text, e.note_count))
            .collect::<Vec<_>>()
    };

    assert_eq!(
        log(&a),
        vec![
            (
                "q1".to_string(),
                Some("the question I am sitting with".to_string()),
                2
            ),
            (
                "q0".to_string(),
                Some("the question I closed".to_string()),
                0
            ),
        ],
        "active first even though the resolved question is not the oldest; q1 counts the \
         in-window note plus the pinned one, and q0's closed window caught neither"
    );
    assert_eq!(log(&a), log(&b), "the log must converge, order included");

    // And the count is the set: what the section says agrees with what the detail page opens, on
    // the device that only ever saw these rows over the wire.
    for entry in b.engine.list_questions(NOW).unwrap() {
        assert_eq!(
            entry.note_count as usize,
            b.engine
                .question_notes(entry.question.id.clone(), NOW)
                .unwrap()
                .len(),
            "count and effective set disagree for {}",
            entry.question.id
        );
    }
}
