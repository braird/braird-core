//! The open-question prompt state machine + typed settings (SUR-1043, SUR-996 R2–R4).
//!
//! A pure function of `(state, settings, now)` → the prompt events a client should act on.
//! Core owns the timer rules so iOS and Android cannot drift: clients render sheets for past-due
//! events and schedule local notifications for future ones, and that is their whole share of the
//! logic. `SyncEngine::next_prompt_events` is the thin wrapper that assembles the state from the
//! store; everything here is clock-free and store-free, which is what makes the rules testable.
//!
//! ## What the machine reads, and what it deliberately does not
//!
//! Question **metadata only** — status, birth, resolution, last check-in. Never the text, so no
//! Vault call is on this path and a `decrypt_failed` question still schedules correctly.
//!
//! ## `checkin_at` is a fact, not a schedule
//!
//! It records WHEN the last check-in was actioned, never when the next one is due. Core derives
//! due-time from it, which is the property that keeps the two clients honest: a stored due-time
//! would let a client write its own idea of the cadence into the synced row. The visible
//! consequence is that shortening the cadence applies retroactively — the next check-in on a long
//! quiet question may fall due immediately — which is the correct reading of "cadence" as an
//! interval rather than an appointment.

/// The synced `user_settings` keys this façade owns (SUR-1042 shipped the untyped write leg and
/// named these for SUR-1043). Constants rather than literals because three platforms write them.
pub const PROMPT_CADENCE_KEY: &str = "prompt_cadence";
pub const PROMPT_TONE_KEY: &str = "prompt_tone";
/// When the user last dismissed a prompt without answering (epoch ms, stored as a decimal string).
///
/// Synced rather than device-local ON PURPOSE: per-row LWW makes the newest skip win, so skipping
/// on the phone silences the same prompt on the tablet. The local `meta` KV would have been
/// cheaper and would have double-prompted every multi-device user.
pub const PROMPT_SKIPPED_AT_KEY: &str = "prompt_skipped_at";

/// Cadence bounds (SUR-996 R4): 72 hours to 4 weeks, defaulting to one week. Clamped in core on
/// BOTH read and write, so an out-of-range value from any client — or one already stored by an
/// older build — lands inside the range rather than being rejected.
pub const CADENCE_MIN_HOURS: u32 = 72;
pub const CADENCE_MAX_HOURS: u32 = 672;
pub const CADENCE_DEFAULT_HOURS: u32 = 168;

const HOUR_MS: i64 = 60 * 60 * 1000;
/// The single nudge fires 24h after account creation (SUR-996 R2).
pub const NUDGE_DELAY_MS: i64 = 24 * HOUR_MS;

/// Which phrasing a prompt uses (SUR-996). The strings themselves stay client-side (SUR-996 Q1 —
/// localization lives with the clients); core owns only the choice, so both platforms cannot
/// disagree about which tone is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PromptTone {
    Introspective,
    Productive,
}

/// What a due prompt is. `Initial` asks for a question (and doubles as the tone picker on first
/// use), `Nudge` is the one-and-only reminder for an unanswered initial prompt, `CheckIn` revisits
/// the live question at cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PromptEventKind {
    Initial,
    Nudge,
    CheckIn,
}

/// The typed façade over the two settings rows. `cadence_hours` is ALWAYS clamped — a value read
/// out of this struct has already passed [`clamp_cadence`], so hosts never see a raw stored number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct PromptSettings {
    pub cadence_hours: u32,
    pub tone: PromptTone,
}

/// One prompt the client should act on. `due_at <= now` → render the sheet; `due_at > now` →
/// schedule a local notification for that moment.
///
/// `tone` is the tone in force now, and is meaningful for `CheckIn` only: `Initial` shows both
/// phrasings as the picker, and the nudge copy is deliberately generic (no question text ever
/// reaches a lock screen — SUR-996 R5). It rides on every event anyway because a non-optional
/// field is simpler across three binding languages than an `Option` two of three kinds ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct PromptEvent {
    pub kind: PromptEventKind,
    pub due_at: i64,
    pub tone: PromptTone,
}

/// The metadata of one stored question, as the machine needs it. Internal — not a UniFFI type:
/// hosts pass no state in, they call `next_prompt_events` and core reads the store itself. That
/// asymmetry IS the anti-drift property; a client-assembled state would put the assembly rules
/// back into two codebases.
pub struct QuestionMeta {
    /// `active | resolved | dismissed`, or anything a newer client wrote. Absent or unrecognised
    /// counts as ACTIVE (see [`is_active`]).
    pub status: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub resolved_at: Option<i64>,
    pub checkin_at: Option<i64>,
}

/// Everything [`next_events`] decides from.
pub struct PromptState {
    /// Host-supplied, because core has no account-creation timestamp anywhere — `user_profiles` is
    /// server-authoritative and deliberately outside the client sync surface. Both platforms read
    /// it off the same GoTrue user object.
    pub account_created_at_ms: i64,
    /// Every live question row, any status.
    pub questions: Vec<QuestionMeta>,
    pub prompt_skipped_at_ms: Option<i64>,
}

/// Force a cadence into 72..=672 hours. Total: there is no invalid input, only clamping.
pub fn clamp_cadence(hours: u32) -> u32 {
    hours.clamp(CADENCE_MIN_HOURS, CADENCE_MAX_HOURS)
}

/// Read a stored tone. Anything unrecognised — absent, deleted, or a value a newer client
/// invented — reads as `Introspective` (founder, 2026-08-19). Tolerant rather than fallible for
/// the same reason `QuestionRecord.status` is an `Option`: the vocabulary has no server CHECK, and
/// a core that errored on a newer client's value would reintroduce the coupling that avoids.
pub fn parse_tone(raw: Option<&str>) -> PromptTone {
    match raw {
        Some(s) if s.eq_ignore_ascii_case("productive") => PromptTone::Productive,
        _ => PromptTone::Introspective,
    }
}

/// The stored form of a tone — the inverse of [`parse_tone`].
pub fn tone_value(tone: PromptTone) -> &'static str {
    match tone {
        PromptTone::Introspective => "introspective",
        PromptTone::Productive => "productive",
    }
}

/// A question still counts as live unless it says otherwise. An unknown status is treated as
/// ACTIVE on purpose: mistaking a newer client's status for "no question" would prompt the user to
/// start a second one and silently fork the log, which is worse than a check-in they can skip.
fn is_active(q: &QuestionMeta) -> bool {
    !matches!(q.status.as_deref(), Some("resolved") | Some("dismissed"))
}

/// The next prompt(s) to act on, sorted by `due_at`.
///
/// NEVER EMPTY, and at most two: there is always a next prompt, and the only phase with two is the
/// opening 24 hours, where the initial prompt is due now AND the nudge must already be scheduled
/// for +24h. A single-event return could not serve both consumers — the user who never opens the
/// app again is exactly the one the nudge exists for, so there is no later call in which to learn
/// about it — and the workaround (clients hardcoding +24h) is the drift this module prevents.
///
/// The rules, in the order they resolve:
///
/// | State | Event(s) |
/// |---|---|
/// | a live question exists | `CheckIn` at `(checkin_at ?? created_at) + cadence` |
/// | nothing ever answered, no skip | `Initial` at account creation, `+ Nudge` while `now < +24h` |
/// | nothing ever answered, skipped at `t` | `Initial` at `t + cadence`, `+ Nudge` while `now < +24h` |
/// | only archived questions | `Initial` at `max(last close, skip) + cadence` — never a `Nudge` again |
///
/// "Resolved → offer a new question" is not here: that dialog happens in the resolve flow, at the
/// moment of resolving. Declining it leaves archived-only state, which is the last row.
pub fn next_events(
    state: &PromptState,
    settings: &PromptSettings,
    now_ms: i64,
) -> Vec<PromptEvent> {
    let cadence_ms = clamp_cadence(settings.cadence_hours) as i64 * HOUR_MS;
    let tone = settings.tone;
    let event = |kind, due_at| PromptEvent { kind, due_at, tone };

    // The NEWEST live question wins. A "New question" supersede archives the old row and creates a
    // new one, and both are live rows until the tombstone flushes; picking the newest keeps the
    // check-in on the question the user is actually sitting with.
    let active = state
        .questions
        .iter()
        .filter(|q| is_active(q))
        .max_by_key(|q| q.created_at);

    if let Some(q) = active {
        // No `checkin_at` yet = just answered, so the first check-in is one cadence from birth.
        let anchor = q.checkin_at.unwrap_or(q.created_at);
        return vec![event(
            PromptEventKind::CheckIn,
            anchor.saturating_add(cadence_ms),
        )];
    }

    // A question that was answered and then closed anchors the next initial-style prompt on its
    // close. `resolved_at` is the intended stamp; `updated_at` covers a dismissal that never set
    // one. `max` because the log accumulates and only the most recent close matters.
    let closed_at = state
        .questions
        .iter()
        .map(|q| q.resolved_at.unwrap_or(q.updated_at))
        .max();

    let initial_due = match closed_at
        .into_iter()
        .chain(state.prompt_skipped_at_ms)
        .max()
    {
        // The one-cadence wait anchors on the most recent interaction, whichever kind it was —
        // skipping the re-offer after a resolve must not be overruled by the older close.
        Some(anchor) => anchor.saturating_add(cadence_ms),
        // Never answered, never skipped: due since the account existed, and it STAYS due (founder,
        // 2026-08-19). The spec's one-cadence wait keys off an interaction, and a user who never
        // saw the sheet has had none — hiding it for up to eight days would cost the activation
        // goal the prompt exists to serve. Clients record "left without answering" as a skip, so a
        // real dismissal still earns the quiet period.
        None => state.account_created_at_ms,
    };

    let mut events = vec![event(PromptEventKind::Initial, initial_due)];

    // ONE nudge, ever, and it needs no fired-flag: the window closes on its own at +24h, and any
    // question row at all — live or archived — means the user has answered once and is past the
    // phase the nudge serves. The client schedules a one-shot notification for `due_at`; the OS
    // does not repeat it.
    let nudge_at = state.account_created_at_ms.saturating_add(NUDGE_DELAY_MS);
    if state.questions.is_empty() && now_ms < nudge_at {
        events.push(event(PromptEventKind::Nudge, nudge_at));
    }

    events.sort_by_key(|e| e.due_at);
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED: i64 = 1_000_000;
    const CADENCE_H: u32 = 168;
    const CADENCE_MS: i64 = 168 * HOUR_MS;

    fn settings(tone: PromptTone) -> PromptSettings {
        PromptSettings {
            cadence_hours: CADENCE_H,
            tone,
        }
    }

    fn question(status: &str, created_at: i64) -> QuestionMeta {
        QuestionMeta {
            status: Some(status.into()),
            created_at,
            updated_at: created_at,
            resolved_at: None,
            checkin_at: None,
        }
    }

    fn state(questions: Vec<QuestionMeta>, skipped_at: Option<i64>) -> PromptState {
        PromptState {
            account_created_at_ms: CREATED,
            questions,
            prompt_skipped_at_ms: skipped_at,
        }
    }

    fn kinds(events: &[PromptEvent]) -> Vec<PromptEventKind> {
        events.iter().map(|e| e.kind).collect()
    }

    // ── the opening phase ────────────────────────────────────────────────────

    #[test]
    fn fresh_account_offers_the_initial_prompt_and_schedules_the_nudge() {
        let events = next_events(
            &state(vec![], None),
            &settings(PromptTone::Introspective),
            CREATED + 60_000,
        );
        assert_eq!(
            kinds(&events),
            vec![PromptEventKind::Initial, PromptEventKind::Nudge]
        );
        assert_eq!(events[0].due_at, CREATED, "initial is due immediately");
        assert_eq!(events[1].due_at, CREATED + NUDGE_DELAY_MS);
    }

    #[test]
    fn the_nudge_is_spent_once_its_window_closes() {
        let events = next_events(
            &state(vec![], None),
            &settings(PromptTone::Introspective),
            CREATED + NUDGE_DELAY_MS + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
    }

    #[test]
    fn an_unanswered_never_skipped_initial_stays_due() {
        // Founder, 2026-08-19: the one-cadence wait keys off an interaction, and this user has had
        // none. A month later the prompt is still there.
        let events = next_events(
            &state(vec![], None),
            &settings(PromptTone::Introspective),
            CREATED + 30 * 24 * HOUR_MS,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
        assert_eq!(events[0].due_at, CREATED);
    }

    #[test]
    fn a_skip_inside_the_nudge_window_still_gets_its_nudge() {
        let skipped = CREATED + 60_000;
        let events = next_events(
            &state(vec![], Some(skipped)),
            &settings(PromptTone::Introspective),
            skipped + 1,
        );
        // Sorted: cadence (≥72h) always outruns the 24h nudge, so the nudge lands first.
        assert_eq!(
            kinds(&events),
            vec![PromptEventKind::Nudge, PromptEventKind::Initial]
        );
        assert_eq!(events[0].due_at, CREATED + NUDGE_DELAY_MS);
        assert_eq!(events[1].due_at, skipped + CADENCE_MS);
    }

    #[test]
    fn a_skip_waits_one_cadence_from_the_skip() {
        let skipped = CREATED + NUDGE_DELAY_MS + 5_000;
        let events = next_events(
            &state(vec![], Some(skipped)),
            &settings(PromptTone::Introspective),
            skipped + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
        assert_eq!(events[0].due_at, skipped + CADENCE_MS);
    }

    // ── the check-in loop ────────────────────────────────────────────────────

    #[test]
    fn a_fresh_answer_schedules_the_first_check_in_from_birth() {
        let answered_at = CREATED + 3_000;
        let events = next_events(
            &state(vec![question("active", answered_at)], None),
            &settings(PromptTone::Productive),
            answered_at + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::CheckIn]);
        assert_eq!(events[0].due_at, answered_at + CADENCE_MS);
        assert_eq!(events[0].tone, PromptTone::Productive);
    }

    #[test]
    fn still_open_resets_the_timer_from_the_check_in() {
        let mut q = question("active", CREATED + 3_000);
        let answered = CREATED + CADENCE_MS + 9_000;
        q.checkin_at = Some(answered);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            answered + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::CheckIn]);
        assert_eq!(events[0].due_at, answered + CADENCE_MS);
    }

    #[test]
    fn a_skipped_check_in_resets_exactly_like_an_answered_one() {
        // "Skip is never punished" (SUR-996 R3): a skip writes `checkin_at` and nothing else, so
        // the two paths are the same input here. Asserted separately so the equivalence is a
        // pinned decision rather than an accident of sharing a branch.
        let skipped_at = CREATED + CADENCE_MS + 400;
        let mut q = question("active", CREATED + 3_000);
        q.checkin_at = Some(skipped_at);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            skipped_at + 1,
        );
        assert_eq!(events[0].due_at, skipped_at + CADENCE_MS);
    }

    #[test]
    fn an_unknown_status_still_counts_as_the_live_question() {
        // A newer client's vocabulary must not read as "no question" — that would prompt for a
        // second one and fork the log.
        let events = next_events(
            &state(vec![question("pondering", CREATED + 10)], None),
            &settings(PromptTone::Introspective),
            CREATED + 20,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::CheckIn]);
    }

    #[test]
    fn a_missing_status_still_counts_as_the_live_question() {
        let mut q = question("active", CREATED + 10);
        q.status = None;
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + 20,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::CheckIn]);
    }

    // ── after the question closes ────────────────────────────────────────────

    #[test]
    fn declining_a_new_question_after_resolve_waits_one_cadence() {
        let resolved = CREATED + CADENCE_MS;
        let mut q = question("resolved", CREATED + 3_000);
        q.resolved_at = Some(resolved);
        q.updated_at = resolved;
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            resolved + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
        assert_eq!(events[0].due_at, resolved + CADENCE_MS);
    }

    #[test]
    fn a_close_without_a_resolved_stamp_falls_back_to_updated_at() {
        let dismissed = CREATED + CADENCE_MS;
        let mut q = question("dismissed", CREATED + 3_000);
        q.updated_at = dismissed;
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            dismissed + 1,
        );
        assert_eq!(events[0].due_at, dismissed + CADENCE_MS);
    }

    #[test]
    fn an_answered_user_never_sees_the_nudge_again() {
        // Still inside the 24h window, but a question exists, so the opening phase is over.
        let mut q = question("resolved", CREATED + 1_000);
        q.resolved_at = Some(CREATED + 2_000);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + 3_000,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
    }

    #[test]
    fn skipping_the_re_offer_anchors_on_the_skip_not_the_close() {
        let resolved = CREATED + CADENCE_MS;
        let skipped = resolved + 60_000;
        let mut q = question("resolved", CREATED + 3_000);
        q.resolved_at = Some(resolved);
        let events = next_events(
            &state(vec![q], Some(skipped)),
            &settings(PromptTone::Introspective),
            skipped + 1,
        );
        assert_eq!(events[0].due_at, skipped + CADENCE_MS);
    }

    #[test]
    fn a_stale_skip_does_not_outrank_a_newer_close() {
        let skipped = CREATED + 1_000;
        let resolved = CREATED + CADENCE_MS;
        let mut q = question("resolved", CREATED + 2_000);
        q.resolved_at = Some(resolved);
        let events = next_events(
            &state(vec![q], Some(skipped)),
            &settings(PromptTone::Introspective),
            resolved + 1,
        );
        assert_eq!(events[0].due_at, resolved + CADENCE_MS);
    }

    #[test]
    fn a_superseding_question_takes_over_the_check_in() {
        let mut old = question("resolved", CREATED + 1_000);
        old.resolved_at = Some(CREATED + 5_000);
        let fresh = question("active", CREATED + 5_000);
        let events = next_events(
            &state(vec![old, fresh], None),
            &settings(PromptTone::Introspective),
            CREATED + 6_000,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::CheckIn]);
        assert_eq!(events[0].due_at, CREATED + 5_000 + CADENCE_MS);
    }

    // ── settings ─────────────────────────────────────────────────────────────

    #[test]
    fn cadence_clamps_at_both_ends() {
        assert_eq!(clamp_cadence(10), CADENCE_MIN_HOURS);
        assert_eq!(clamp_cadence(9_999), CADENCE_MAX_HOURS);
        assert_eq!(clamp_cadence(0), CADENCE_MIN_HOURS);
        assert_eq!(clamp_cadence(CADENCE_DEFAULT_HOURS), CADENCE_DEFAULT_HOURS);
        assert_eq!(clamp_cadence(CADENCE_MIN_HOURS), CADENCE_MIN_HOURS);
        assert_eq!(clamp_cadence(CADENCE_MAX_HOURS), CADENCE_MAX_HOURS);
    }

    #[test]
    fn an_out_of_range_cadence_is_clamped_before_it_reaches_a_due_at() {
        // The clamp is not just a setter guard: a value stored by an older build still lands
        // inside the range on the way out.
        let q = question("active", CREATED);
        let events = next_events(
            &state(vec![q], None),
            &PromptSettings {
                cadence_hours: 1,
                tone: PromptTone::Introspective,
            },
            CREATED + 1,
        );
        assert_eq!(
            events[0].due_at,
            CREATED + CADENCE_MIN_HOURS as i64 * HOUR_MS
        );
    }

    #[test]
    fn shortening_the_cadence_moves_the_next_check_in_earlier() {
        // Intended: `checkin_at` is when the last check-in happened, so a cadence change applies
        // to the interval, not to an appointment already made.
        let q = || question("active", CREATED);
        let slow = next_events(
            &state(vec![q()], None),
            &settings(PromptTone::Introspective),
            CREATED + 1,
        );
        let fast = next_events(
            &state(vec![q()], None),
            &PromptSettings {
                cadence_hours: CADENCE_MIN_HOURS,
                tone: PromptTone::Introspective,
            },
            CREATED + 1,
        );
        assert!(fast[0].due_at < slow[0].due_at);
    }

    #[test]
    fn tone_parses_tolerantly_and_defaults_to_introspective() {
        assert_eq!(parse_tone(Some("productive")), PromptTone::Productive);
        assert_eq!(parse_tone(Some("Productive")), PromptTone::Productive);
        assert_eq!(parse_tone(Some("introspective")), PromptTone::Introspective);
        assert_eq!(parse_tone(Some("zen")), PromptTone::Introspective);
        assert_eq!(parse_tone(Some("")), PromptTone::Introspective);
        assert_eq!(parse_tone(None), PromptTone::Introspective);
    }

    #[test]
    fn tone_round_trips_through_its_stored_form() {
        for tone in [PromptTone::Introspective, PromptTone::Productive] {
            assert_eq!(parse_tone(Some(tone_value(tone))), tone);
        }
    }

    #[test]
    fn every_event_carries_the_tone_in_force() {
        let events = next_events(
            &state(vec![], None),
            &settings(PromptTone::Productive),
            CREATED + 1,
        );
        assert!(events.iter().all(|e| e.tone == PromptTone::Productive));
    }

    // ── invariants that hold in every phase ──────────────────────────────────

    #[test]
    fn there_is_always_a_next_prompt_and_never_more_than_two() {
        let phases = [
            state(vec![], None),
            state(vec![], Some(CREATED + 1)),
            state(vec![question("active", CREATED)], None),
            state(vec![question("resolved", CREATED)], None),
            state(vec![question("dismissed", CREATED)], Some(CREATED + 9)),
            state(vec![question("pondering", CREATED)], None),
        ];
        for (i, phase) in phases.iter().enumerate() {
            for now in [CREATED, CREATED + NUDGE_DELAY_MS + 1] {
                let events = next_events(phase, &settings(PromptTone::Introspective), now);
                assert!(!events.is_empty(), "phase {i} at {now} produced nothing");
                assert!(events.len() <= 2, "phase {i} at {now} produced {events:?}");
                assert!(
                    events.windows(2).all(|w| w[0].due_at <= w[1].due_at),
                    "phase {i} at {now} came back unsorted"
                );
            }
        }
    }

    #[test]
    fn an_absurd_anchor_saturates_instead_of_overflowing() {
        let mut q = question("active", i64::MAX);
        q.checkin_at = Some(i64::MAX);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED,
        );
        assert_eq!(events[0].due_at, i64::MAX);
    }
}
