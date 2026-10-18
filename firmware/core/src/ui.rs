//! Confirmation by button. The board owns the pin and the LED; the rules live here.
//!
//! Confirmation means a fresh press *after* the request. A button held down (or taped)
//! when the request arrives does not count - that is exactly the attack the button
//! exists to stop.
//!
//! There are three gestures, and the differences are the point. A code or a password
//! is approved by a tap while the light is amber. The wipe needs five seconds of red,
//! and so does a restore, which replaces everything as a wipe does.
//! A backup - every secret leaving at once, sealed - needs two taps in a row while
//! the light is blue. Without that split the button would guard nothing against a
//! hostile host: it would ask for a wipe while the owner expected a code request, and
//! the reflex that approves a code would hand it over. A tap never wipes and never
//! exports; a hold never exports either, and two taps never wipe.
//!
//! One gesture answers no request: two taps while nothing is asked (`IdleDoubleTap`)
//! make a board with a keyboard type the login password (maintainer's decision,
//! 2026-10-17).
//!
//! A request can be withdrawn while it waits (`Ui::withdrawn`, a passkey request the
//! host cancels). That ends the wait the way its deadline would - refused - and never
//! counts as a press or a hold.

use crate::hal::{Clock, Ui};

/// Contact bounce is milliseconds; a level that survives this is the real one.
const DEBOUNCE_MS: u64 = 20;
/// How long after the first tap the second may come and still be the same gesture.
const DOUBLE_TAP_MS: u64 = 800;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Idle,
    /// Waiting for a tap.
    Waiting,
    /// Held: something irreversible is about to happen.
    Danger,
    /// Waiting for two taps: a backup is about to leave.
    Export,
    Ok,
    Refused,
}

/// Blocks until a fresh press-and-release, or the timeout. Every phase is bounded by
/// the same deadline: a stuck button must never park the firmware with keys in RAM.
/// Shows the outcome for a moment so the user learns whether the press counted.
pub fn await_confirmation<U: Ui, C: Clock>(ui: &mut U, clock: &C, timeout_ms: u64) -> bool {
    let deadline = clock.now_ms() + timeout_ms;
    ui.set(State::Waiting);
    if !await_release(ui, clock, deadline) {
        return finish(ui, clock, false);
    }
    if !await_press(ui, clock, deadline) {
        return finish(ui, clock, false);
    }
    // And the release, so the same press cannot confirm twice; if it never comes, the
    // press still counted and the next request will wait for a release first.
    await_release(ui, clock, deadline);
    finish(ui, clock, true)
}

/// Blocks until two fresh taps within `DOUBLE_TAP_MS` of each other, or the timeout;
/// the light shows blue meanwhile. One tap - the reflex that approves a code - is not
/// enough, and a hold is one press, however long.
pub fn await_double_tap<U: Ui, C: Clock>(ui: &mut U, clock: &C, timeout_ms: u64) -> bool {
    let deadline = clock.now_ms() + timeout_ms;
    ui.set(State::Export);
    if !await_release(ui, clock, deadline)
        || !await_press(ui, clock, deadline)
        || !await_release(ui, clock, deadline)
    {
        return finish(ui, clock, false);
    }
    let second = (clock.now_ms() + DOUBLE_TAP_MS).min(deadline);
    if !await_press(ui, clock, second) {
        return finish(ui, clock, false);
    }
    await_release(ui, clock, deadline);
    finish(ui, clock, true)
}

/// Waits for a press that survives the debounce. False if the wait is over first.
fn await_press<U: Ui, C: Clock>(ui: &U, clock: &C, deadline: u64) -> bool {
    loop {
        if over(ui, clock, deadline) {
            return false;
        }
        if ui.pressed() {
            let t = clock.now_ms();
            while clock.now_ms() - t < DEBOUNCE_MS {}
            if ui.pressed() && !ui.withdrawn() {
                return true;
            }
        }
    }
}

/// Whether a wait is over: its deadline has passed, or the request was withdrawn.
fn over<U: Ui, C: Clock>(ui: &U, clock: &C, deadline: u64) -> bool {
    ui.withdrawn() || clock.now_ms() > deadline
}

/// Blocks until the button has been held down for `hold_ms` without letting go, or the
/// timeout; the light shows red while the hold counts. Letting go early costs nothing
/// but the hold: there is time to mean it, and time not to.
pub fn await_hold<U: Ui, C: Clock>(ui: &mut U, clock: &C, timeout_ms: u64, hold_ms: u64) -> bool {
    let deadline = clock.now_ms() + timeout_ms;
    ui.set(State::Waiting);
    if !await_release(ui, clock, deadline) {
        return finish(ui, clock, false);
    }
    while !over(ui, clock, deadline) {
        if !ui.pressed() {
            continue;
        }
        ui.set(State::Danger);
        let start = clock.now_ms();
        while !released(ui, clock) {
            // Asked before the time is counted: a request withdrawn mid-hold ends it,
            // and must never be the moment that completes it.
            if ui.withdrawn() {
                break;
            }
            if clock.now_ms() - start >= hold_ms {
                // The release too, so one hold cannot confirm twice.
                await_release(ui, clock, deadline);
                return finish(ui, clock, true);
            }
        }
        ui.set(State::Waiting); // let go too early: nothing happened
    }
    finish(ui, clock, false)
}

/// True once the button has been up long enough for the level to be real, rather than
/// a bounce in the middle of a press.
fn released<U: Ui, C: Clock>(ui: &U, clock: &C) -> bool {
    if ui.pressed() {
        return false;
    }
    let t = clock.now_ms();
    while clock.now_ms() - t < DEBOUNCE_MS {}
    !ui.pressed()
}

/// Waits out a button that is down, until it has been up long enough to be really up:
/// a bounce in the middle of one press is not a release, or that press would count as
/// two taps, and two taps at blue let a backup out. False if the wait is over first.
fn await_release<U: Ui, C: Clock>(ui: &U, clock: &C, deadline: u64) -> bool {
    while !released(ui, clock) {
        if over(ui, clock, deadline) {
            return false;
        }
    }
    true
}

/// The longest press that still counts as one tap of [`IdleDoubleTap`]: a hold is not one.
const TAP_MAX_MS: u64 = 500;
/// A pause between samples longer than this starts [`IdleDoubleTap`] over: the key was
/// serving a request, which waits for the button itself, and whatever the button did
/// meanwhile belonged to that request.
const SAMPLE_GAP_MS: u64 = 50;

/// The one gesture made with nothing asked: two short taps within `DOUBLE_TAP_MS`, from a
/// button seen up first, so one held at boot or still down from a request does not
/// start it. It types the login password (`crate::login`); nothing else listens to an
/// idle button. Fed by the board on every idle look at the button, never blocking.
pub struct IdleDoubleTap {
    phase: Phase,
    /// The level as last sampled, and since when.
    raw: bool,
    since: u64,
    /// The level once it has held for `DEBOUNCE_MS`; unknown after a start.
    settled: Option<bool>,
    last: Option<u64>,
}

#[derive(Clone, Copy)]
enum Phase {
    /// Waiting for the button to be seen up.
    Unarmed,
    Ready,
    /// Down for the first tap, since.
    First(u64),
    /// Up after it, since.
    Between(u64),
    Second(u64),
}

impl Default for IdleDoubleTap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleDoubleTap {
    #[must_use]
    pub const fn new() -> Self {
        IdleDoubleTap {
            phase: Phase::Unarmed,
            raw: false,
            since: 0,
            settled: None,
            last: None,
        }
    }

    /// One look at the button at `now`: true when it completes the gesture.
    pub fn sample(&mut self, pressed: bool, now: u64) -> bool {
        if self
            .last
            .is_none_or(|t| now.saturating_sub(t) > SAMPLE_GAP_MS)
        {
            *self = Self::new();
            self.raw = pressed;
            self.since = now;
        }
        self.last = Some(now);
        if pressed != self.raw {
            self.raw = pressed;
            self.since = now;
        }
        let edge = if now - self.since >= DEBOUNCE_MS && self.settled != Some(pressed) {
            self.settled = Some(pressed);
            Some(pressed)
        } else {
            None
        };
        let at = self.since;
        let (phase, done) = match (self.phase, edge) {
            // A tap is timed from when the level changed, not from when the debounce let
            // the change through.
            (Phase::First(down), Some(false)) if at - down <= TAP_MAX_MS => {
                (Phase::Between(at), false)
            }
            (Phase::Second(down), Some(false)) if at - down <= TAP_MAX_MS => (Phase::Ready, true),
            // The button seen up, or up after a press held too long: ready for a tap.
            (Phase::Unarmed | Phase::First(_) | Phase::Second(_), Some(false)) => {
                (Phase::Ready, false)
            }
            (Phase::Between(up), Some(true)) if at - up <= DOUBLE_TAP_MS => {
                (Phase::Second(at), false)
            }
            // A press from ready, or one too late to be the second tap: a first tap.
            (Phase::Ready | Phase::Between(_), Some(true)) => (Phase::First(at), false),
            (Phase::Between(up), _) if now - up > DOUBLE_TAP_MS + DEBOUNCE_MS => {
                (Phase::Ready, false)
            }
            // No edge, or one this phase does not wait for: nothing changes.
            (phase, _) => (phase, false),
        };
        self.phase = phase;
        done
    }
}

fn finish<U: Ui, C: Clock>(ui: &mut U, clock: &C, ok: bool) -> bool {
    ui.set(if ok { State::Ok } else { State::Refused });
    let t = clock.now_ms();
    while clock.now_ms() - t < 150 {}
    ui.set(State::Idle);
    ok
}
