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
/// When this account first authored a question (epoch ms, decimal string) — the onboarding-done
/// marker, written once and never cleared.
///
/// An explicitly RECORDED fact, after three review rounds proved it cannot be inferred. "Has this
/// user onboarded?" was read first from the live question rows, which a soft-delete empties; then
/// from a tombstone-inclusive count, which `pull_table` defeats because it discards a tombstone for
/// a row the device never had (`pull.rs`, mirroring the JS `if (n.deleted && !local) continue`). A
/// second device installed inside the opening 24 hours therefore saw a pristine account and re-ran
/// onboarding. Each fix was a better inference from data that was never meant to answer the
/// question; a settings row is meant to, and it is live-forever, so no tombstone rule can drop it.
pub const PROMPT_ANSWERED_AT_KEY: &str = "prompt_answered_at";
/// When the user last completed or skipped a check-in pass (epoch ms, decimal string) — SUR-1101.
///
/// ONE stamp for the whole pass, because a check-in now covers every active question at once on a
/// single global cadence. The per-question `questions.checkin_at` still records each question's own
/// last answer and is still read as a legacy anchor (see [`checkin_anchor`]), but no single
/// question's row can say when the PASS happened — a pass that answered nothing (all skipped) writes
/// no question at all. Synced for the [`PROMPT_SKIPPED_AT_KEY`] reason: the newest pass wins across
/// devices, so checking in on the phone silences the tablet.
pub const CHECKIN_LAST_AT_KEY: &str = "checkin_last_at";
/// When the user last dismissed the too-many-questions nudge (epoch ms, decimal string) — SUR-1101.
pub const QUESTION_NUDGE_DISMISSED_AT_KEY: &str = "question_nudge_dismissed_at";

/// Cadence bounds (SUR-996 R4): 72 hours to 4 weeks, defaulting to one week. Clamped in core on
/// BOTH read and write, so an out-of-range value from any client — or one already stored by an
/// older build — lands inside the range rather than being rejected.
pub const CADENCE_MIN_HOURS: u32 = 72;
pub const CADENCE_MAX_HOURS: u32 = 672;
pub const CADENCE_DEFAULT_HOURS: u32 = 168;

const HOUR_MS: i64 = 60 * 60 * 1000;
/// The single nudge fires 24h after account creation (SUR-996 R2).
pub const NUDGE_DELAY_MS: i64 = 24 * HOUR_MS;

/// The too-many-questions nudge (SUR-1101) fires once MORE than this many questions are active —
/// at the 9th, not the 8th. Unrelated to [`NUDGE_DELAY_MS`]'s onboarding nudge despite the word.
pub const QUESTION_NUDGE_THRESHOLD: usize = 8;
/// A dismissed too-many-questions nudge stays silent this long, then re-fires if still over.
pub const QUESTION_NUDGE_QUIET_MS: i64 = 28 * 24 * HOUR_MS;

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
/// EVERY active question in one pass at cadence (SUR-1101).
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
///
/// No question id. Until SUR-1101 a `CheckIn` named the one question it was about; a check-in now
/// covers every active question, so the host lists them from `list_questions` (active first) and
/// records the pass with [`crate::sync::SyncEngine::complete_checkin`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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
    pub id: String,
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
    /// Whether this account has EVER authored a question — the onboarding-done fact.
    ///
    /// Read from the synced [`PROMPT_ANSWERED_AT_KEY`] marker, not inferred from the rows in hand.
    /// Neither the live questions nor a tombstone-inclusive count of them can answer this on a
    /// device that was not present for the writing: a delete empties the first, and the pull path
    /// discards a tombstone for a row it never had, so the second reads zero on a fresh install.
    pub has_ever_answered: bool,
    pub prompt_skipped_at_ms: Option<i64>,
    /// The [`CHECKIN_LAST_AT_KEY`] stamp, raw — [`checkin_anchor`] bounds it.
    pub checkin_last_at_ms: Option<i64>,
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
///
/// Crate-visible because the Lexicon question log orders on it too (SUR-1071). One definition, so
/// the section the user reads and the loop that schedules their check-in cannot disagree about
/// which question is open — least of all about a status neither of them recognises.
pub(crate) fn is_active(status: Option<&str>) -> bool {
    !matches!(status, Some("resolved") | Some("dismissed"))
}

/// Bound an interaction stamp to the window it could possibly have happened in: no earlier than the
/// thing it acts on was born, and never in the future.
///
/// Every anchor here answers "when did the user last do something", so a future stamp is never
/// meaningful — but it is very reachable. `resolved_at` and `checkin_at` are host-supplied, and a
/// row pulled from a device with a fast clock carries its stamp; `updated_at` is worse still,
/// because it is deliberately clamped PAST a pulled row's stamp on write (the `t01_lww_guard`
/// rule), so a dismissal that never set `resolved_at` inherits that inflated value. Unbounded, the
/// next prompt is postponed by the remote skew plus a cadence — months of silence from one wrong
/// clock, with nothing to explain it.
///
/// A FUTURE STAMP FALLS BACK TO `birth`, NOT TO `now`, and that difference is the whole subtlety.
/// Clamping to `now` looks equivalent and is not: the hosts re-run this after every pull, answer and
/// settings change, so each call would re-clamp to a later `now` and push `due_at` out another full
/// cadence — a prompt permanently one cadence away, never arriving, for as long as the skew lasts.
/// `birth` is fixed, so repeated evaluation of unchanged state returns the same answer, which is the
/// property the whole module is built on. It also fails toward SHOWING the prompt (an anchor in the
/// past) rather than hiding it, which is the safer direction for a signal the user can dismiss.
///
/// Both regimes are stable, and the crossover is one-way: once the local clock passes the stamp it
/// stops being "future" and the real value takes over.
fn bound_interaction(stamp: i64, birth: i64, now_ms: i64) -> i64 {
    if stamp > now_ms {
        birth
    } else {
        stamp.max(birth)
    }
}

/// When the current check-in period began, or `None` when no question is active (so there is no
/// check-in to schedule). The CheckIn event is due one cadence after it, and the check-in's
/// "notes captured since the last check-in with no attachment" section reads from it — ONE
/// definition, so the section always covers exactly the period the check-in closes (SUR-1101).
///
/// The anchor is the latest recorded check-in: the pass stamp [`CHECKIN_LAST_AT_KEY`], or any
/// active question's own `checkin_at` (the pre-SUR-1101 per-question stamp, still written when a
/// question's check-in is answered, and the only record an upgrading account has). With no record
/// at all it is the OLDEST active question's birth — the first check-in comes one cadence after the
/// user first had something to check in on, and a question opened later joins that pass rather
/// than restarting the clock.
///
/// Every stamp is bounded to `[oldest active birth, now]` by [`bound_interaction`]. Below, because
/// a check-in recorded before the current run of questions began (the user resolved everything,
/// went quiet, then opened a new question) must not make the new question's check-in instantly
/// overdue. Above, for the fast-remote-clock reason that function records.
pub fn checkin_anchor(state: &PromptState, now_ms: i64) -> Option<i64> {
    let active = || {
        state
            .questions
            .iter()
            .filter(|q| is_active(q.status.as_deref()))
    };
    let birth = active().map(|q| q.created_at).min()?;
    Some(
        state
            .checkin_last_at_ms
            .into_iter()
            .chain(active().filter_map(|q| q.checkin_at))
            .map(|stamp| bound_interaction(stamp, birth, now_ms))
            .max()
            .unwrap_or(birth),
    )
}

/// Whether the too-many-questions nudge should show (SUR-1101): more than
/// [`QUESTION_NUDGE_THRESHOLD`] active questions, and no dismissal inside the last
/// [`QUESTION_NUDGE_QUIET_MS`]. Independent of the check-in cadence.
///
/// A dismissal stamped in the future (a fast remote clock) reads as NO dismissal, not as "silent
/// until then plus four weeks": the nudge is dismissable in one tap, and failing toward showing it
/// is the [`bound_interaction`] posture. It is also stable under re-evaluation, unlike clamping the
/// stamp to `now`, which would slide the quiet period forward on every call.
pub fn question_nudge_due(active_count: usize, dismissed_at: Option<i64>, now_ms: i64) -> bool {
    if active_count <= QUESTION_NUDGE_THRESHOLD {
        return false;
    }
    match dismissed_at {
        Some(at) if at <= now_ms => now_ms >= at.saturating_add(QUESTION_NUDGE_QUIET_MS),
        _ => true,
    }
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
/// | any question is active | ONE `CheckIn`, covering them all, at [`checkin_anchor`] `+ cadence` |
/// | nothing ever answered, no skip | `Initial` at account creation, `+ Nudge` while `now < +24h` |
/// | nothing ever answered, skipped at `t` | `Initial` at `t + cadence` — the skip cancels the nudge |
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

    // Any number of questions may be active at once (SUR-1101), and one check-in covers them all
    // on the single global cadence — so there is one CheckIn, never one per question.
    if let Some(anchor) = checkin_anchor(state, now_ms) {
        return vec![event(
            PromptEventKind::CheckIn,
            anchor.saturating_add(cadence_ms),
        )];
    }

    // A question that was answered and then closed anchors the next initial-style prompt on its
    // close. `resolved_at` is the intended stamp; `updated_at` covers a dismissal that never set
    // one — and that fallback is why the upper bound matters most here: `updated_at` is a
    // BOOKKEEPING stamp, deliberately pushed past a pulled row's on write, so a dismissal can
    // inherit a far-future value and postpone the next prompt by the remote skew. The outer `max`
    // is a different job: the log accumulates, and only the most recent close matters.
    let closed_at = state
        .questions
        .iter()
        .map(|q| bound_interaction(q.resolved_at.unwrap_or(q.updated_at), q.created_at, now_ms))
        .max();

    // The skip is bounded against the ACCOUNT's birth rather than a question's — it is account-level
    // and can precede every question. Its lower bound is slack (a skew-early skip only makes the
    // prompt due sooner, which is where it sits with no skip at all), but the upper bound is not:
    // the value is host-supplied and synced, so a device with a fast clock can record a skip dated
    // years out and silence the prompt on every other device for that long.
    let skipped_at = state
        .prompt_skipped_at_ms
        .map(|t| bound_interaction(t, state.account_created_at_ms, now_ms));

    let initial_due = match closed_at.into_iter().chain(skipped_at).max() {
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

    // ONE nudge, ever, and it needs no fired-flag: the window closes on its own at +24h, and having
    // ever answered — even if that question was since resolved, dismissed or DELETED — puts the
    // user past the phase the nudge serves. The client schedules a one-shot notification for
    // `due_at`; the OS does not repeat it.
    //
    // Keyed on `has_ever_answered` rather than on the live rows in hand, because a soft-deleted
    // question vanishes from every ordinary read: reading that absence as "never answered" would
    // re-run onboarding, and notify someone who finished it, on the strength of a row they deleted.
    //
    // A RECORDED SKIP CANCELS IT (founder, 2026-08-19). R2's sentence covers the skipper and the
    // leaver in one breath, but the two have not done the same thing: the nudge exists so a user
    // who wandered off mid-onboarding does not lose the moment, while a skip is an answer — the
    // user was asked and declined. Nudging them 24h later contradicts the same paragraph's promise
    // that the next prompt waits a full cadence (≥72h), and "always skippable, never nagged" is an
    // explicit non-goal of the feature. So the quiet period a skip earns is quiet, not quieter-
    // except-once.
    let nudge_at = state.account_created_at_ms.saturating_add(NUDGE_DELAY_MS);
    if !state.has_ever_answered && state.prompt_skipped_at_ms.is_none() && now_ms < nudge_at {
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
            id: format!("q-{created_at}"),
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
            has_ever_answered: !questions.is_empty(),
            questions,
            prompt_skipped_at_ms: skipped_at,
            checkin_last_at_ms: None,
        }
    }

    /// The state a user reaches by answering and then DELETING the question: no live rows survive,
    /// but onboarding did happen.
    fn state_after_deleting_the_only_question() -> PromptState {
        PromptState {
            account_created_at_ms: CREATED,
            questions: vec![],
            has_ever_answered: true,
            prompt_skipped_at_ms: None,
            checkin_last_at_ms: None,
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
    fn a_skip_inside_the_nudge_window_cancels_the_nudge() {
        // Founder, 2026-08-19: a skip is an answer, so the quiet period it earns is quiet. Nudging
        // 24h after an explicit dismissal would contradict the same rule's ≥72h promise.
        let skipped = CREATED + 60_000;
        let events = next_events(
            &state(vec![], Some(skipped)),
            &settings(PromptTone::Introspective),
            skipped + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
        assert_eq!(events[0].due_at, skipped + CADENCE_MS);
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
    fn a_skew_inverted_check_in_anchors_on_the_question_birth() {
        // A device whose clock runs behind stamps `checkin_at` before the `created_at` another
        // device wrote. The raw stamp would shorten the interval by the skew.
        let mut q = question("active", CREATED);
        q.checkin_at = Some(CREATED - 5 * 60 * 60 * 1000);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + 1,
        );
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    #[test]
    fn extreme_skew_cannot_make_a_check_in_immediately_overdue() {
        // Past one cadence of skew the raw stamp would put `due_at` in the past, so the sheet would
        // reappear the instant the user answered one — the nagging R3 forbids.
        let mut q = question("active", CREATED);
        q.checkin_at = Some(CREATED - 10 * CADENCE_MS);
        let now = CREATED + 1;
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            now,
        );
        assert!(
            events[0].due_at > now,
            "a skewed check-in must not fall due immediately"
        );
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    #[test]
    fn a_skew_inverted_close_keeps_the_full_quiet_period() {
        let mut q = question("resolved", CREATED);
        q.resolved_at = Some(CREATED - 9 * 60 * 60 * 1000);
        q.updated_at = CREATED;
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + 1,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    const SKEW: i64 = 5 * 365 * 24 * HOUR_MS;

    #[test]
    fn a_dismissal_carrying_a_future_bookkeeping_stamp_falls_back_to_the_question_birth() {
        // The regression the LWW clamp introduced: `updated_at` is deliberately pushed PAST a
        // pulled row's stamp on write, so a dismissal with no `resolved_at` inherits a far-future
        // value. Unbounded, the next prompt is postponed by the remote skew — years of silence.
        let mut q = question("dismissed", CREATED);
        q.resolved_at = None;
        q.updated_at = CREATED + SKEW;
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + 60_000,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::Initial]);
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    #[test]
    fn a_future_check_in_stamp_cannot_silence_the_loop() {
        let mut q = question("active", CREATED);
        q.checkin_at = Some(CREATED + SKEW);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + 60_000,
        );
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    #[test]
    fn a_future_skip_stamp_cannot_silence_the_prompt() {
        // `prompt_skipped_at` is host-supplied AND synced, so one device with a fast clock could
        // otherwise mute every other device for the length of its skew.
        let events = next_events(
            &state(vec![], Some(CREATED + SKEW)),
            &settings(PromptTone::Introspective),
            CREATED + 60_000,
        );
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    #[test]
    fn a_future_stamp_does_not_push_the_prompt_out_on_every_evaluation() {
        // The trap in bounding to `now` instead of to the birth: hosts re-run this after every
        // pull, answer and settings change, so each call would re-clamp to a later `now` and move
        // `due_at` out another full cadence — a prompt permanently one cadence away, never
        // arriving. Unchanged state must give an unchanged answer however often it is asked.
        let with_future_stamp = |checkin: bool| {
            let mut q = question("active", CREATED);
            if checkin {
                q.checkin_at = Some(CREATED + SKEW);
            }
            q
        };
        for skipped in [None, Some(CREATED + SKEW)] {
            for checkin in [true, false] {
                let at = |now| {
                    next_events(
                        &state(vec![with_future_stamp(checkin)], skipped),
                        &settings(PromptTone::Introspective),
                        now,
                    )[0]
                    .due_at
                };
                assert_eq!(
                    at(CREATED + 60_000),
                    at(CREATED + 60_000 + 30 * 24 * HOUR_MS),
                    "due_at slid forward with now (checkin={checkin}, skipped={skipped:?})"
                );
            }
        }
    }

    #[test]
    fn the_crossover_is_one_way_once_the_clock_catches_up() {
        // While the stamp is "future" the anchor is the birth; once the local clock passes it, the
        // real stamp takes over. Both regimes are stable — only the transition moves.
        let mut q = question("active", CREATED);
        q.checkin_at = Some(CREATED + SKEW);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED + SKEW + 1,
        );
        assert_eq!(events[0].due_at, CREATED + SKEW + CADENCE_MS);
    }

    #[test]
    fn bounding_survives_a_now_that_precedes_the_birth() {
        // A device whose own clock trails the question's creation: the bound must still land on a
        // real point of the timeline rather than inverting.
        let q = question("active", CREATED);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            CREATED - 10_000,
        );
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
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
    fn deleting_the_only_question_does_not_restart_onboarding() {
        // A soft-deleted question vanishes from every ordinary read, so the live rows look exactly
        // like a brand-new account. Nudging here would notify someone who finished onboarding, on
        // the strength of a row they deleted.
        let events = next_events(
            &state_after_deleting_the_only_question(),
            &settings(PromptTone::Introspective),
            CREATED + 60_000,
        );
        assert_eq!(
            kinds(&events),
            vec![PromptEventKind::Initial],
            "the prompt returns, but the onboarding nudge is spent"
        );
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
    fn a_resolved_predecessor_does_not_anchor_the_new_questions_check_in() {
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

    // ── concurrent questions (SUR-1101) ──────────────────────────────────────

    #[test]
    fn several_active_questions_share_one_check_in_from_the_oldest_birth() {
        // Q2 opened three days into Q1's period joins Q1's pass; it does not restart the clock and
        // it does not get a check-in of its own.
        let events = next_events(
            &state(
                vec![
                    question("active", CREATED),
                    question("active", CREATED + 3 * 24 * HOUR_MS),
                ],
                None,
            ),
            &settings(PromptTone::Introspective),
            CREATED + 4 * 24 * HOUR_MS,
        );
        assert_eq!(kinds(&events), vec![PromptEventKind::CheckIn]);
        assert_eq!(events[0].due_at, CREATED + CADENCE_MS);
    }

    #[test]
    fn a_completed_pass_anchors_the_next_check_in() {
        let mut s = state(
            vec![
                question("active", CREATED),
                question("active", CREATED + 10),
            ],
            None,
        );
        let pass = CREATED + CADENCE_MS + 60_000;
        s.checkin_last_at_ms = Some(pass);
        let events = next_events(&s, &settings(PromptTone::Introspective), pass + 1);
        assert_eq!(events[0].due_at, pass + CADENCE_MS);
    }

    #[test]
    fn a_legacy_per_question_check_in_still_anchors_an_upgraded_account() {
        // An account upgrading from the one-question model has no pass stamp, only `checkin_at` on
        // its question. Ignoring it would make the check-in due again the moment the user upgrades.
        let answered = CREATED + CADENCE_MS + 5_000;
        let mut q = question("active", CREATED);
        q.checkin_at = Some(answered);
        let events = next_events(
            &state(vec![q], None),
            &settings(PromptTone::Introspective),
            answered + 1,
        );
        assert_eq!(events[0].due_at, answered + CADENCE_MS);
    }

    #[test]
    fn a_pass_recorded_before_the_current_questions_existed_does_not_make_them_overdue() {
        // Everything resolved, a long quiet spell, then a new question: the old pass stamp is older
        // than anything active, so it is bounded up to the new question's birth.
        let born = CREATED + 10 * CADENCE_MS;
        let mut s = state(vec![question("active", born)], None);
        s.checkin_last_at_ms = Some(CREATED + CADENCE_MS);
        let events = next_events(&s, &settings(PromptTone::Introspective), born + 1);
        assert_eq!(events[0].due_at, born + CADENCE_MS);
    }

    #[test]
    fn a_future_pass_stamp_falls_back_to_the_oldest_birth_and_stays_there() {
        let mut s = state(vec![question("active", CREATED)], None);
        s.checkin_last_at_ms = Some(CREATED + 50 * CADENCE_MS);
        let first = next_events(&s, &settings(PromptTone::Introspective), CREATED + 1_000);
        let again = next_events(&s, &settings(PromptTone::Introspective), CREATED + 9_000);
        assert_eq!(first[0].due_at, CREATED + CADENCE_MS);
        assert_eq!(
            first, again,
            "re-evaluating unchanged state must not slide the due time"
        );
    }

    #[test]
    fn the_anchor_is_none_without_an_active_question() {
        let mut resolved = question("resolved", CREATED);
        resolved.resolved_at = Some(CREATED + 1);
        let mut s = state(vec![resolved], None);
        s.checkin_last_at_ms = Some(CREATED + 2);
        assert_eq!(checkin_anchor(&s, CREATED + 3), None);
    }

    #[test]
    fn the_too_many_questions_nudge_fires_at_the_ninth_not_the_eighth() {
        assert!(!question_nudge_due(8, None, CREATED));
        assert!(question_nudge_due(9, None, CREATED));
    }

    #[test]
    fn a_dismissed_nudge_is_silent_for_exactly_four_weeks() {
        let dismissed = CREATED;
        assert!(!question_nudge_due(9, Some(dismissed), dismissed));
        assert!(!question_nudge_due(
            9,
            Some(dismissed),
            dismissed + QUESTION_NUDGE_QUIET_MS - 1
        ));
        assert!(question_nudge_due(
            9,
            Some(dismissed),
            dismissed + QUESTION_NUDGE_QUIET_MS
        ));
        // ...and only if the user is still over the threshold when the quiet period ends.
        assert!(!question_nudge_due(
            8,
            Some(dismissed),
            dismissed + QUESTION_NUDGE_QUIET_MS
        ));
    }

    #[test]
    fn a_future_nudge_dismissal_reads_as_no_dismissal() {
        assert!(question_nudge_due(9, Some(CREATED + 1), CREATED));
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
