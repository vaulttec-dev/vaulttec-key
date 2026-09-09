//! Confirmation by button. The board owns the pin and the LED; the rules live here.
//!
//! Confirmation means a fresh press *after* the request. A button held down (or taped)
//! when the request arrives does not count - that is exactly the attack the button
//! exists to stop.
//!
//! There are three gestures, and the differences are the point. A code or a password
//! is approved by a tap while the light is amber. The wipe needs five seconds of red.
//! A backup - every secret leaving at once, sealed - needs two taps in a row while
//! the light is blue. Without that split the button would guard nothing against a
//! hostile host: it would ask for a wipe while the owner expected a code request, and
//! the reflex that approves a code would hand it over. A tap never wipes and never
//! exports; a hold never exports either, and two taps never wipe.

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

/// Waits for a press that survives the debounce. False if the deadline passes first.
fn await_press<U: Ui, C: Clock>(ui: &U, clock: &C, deadline: u64) -> bool {
    loop {
        if clock.now_ms() > deadline {
            return false;
        }
        if ui.pressed() {
            let t = clock.now_ms();
            while clock.now_ms() - t < DEBOUNCE_MS {}
            if ui.pressed() {
                return true;
            }
        }
    }
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
    while clock.now_ms() <= deadline {
        if !ui.pressed() {
            continue;
        }
        ui.set(State::Danger);
        let start = clock.now_ms();
        while !released(ui, clock) {
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

/// Waits out a button that is already down. False if the deadline passes first.
fn await_release<U: Ui, C: Clock>(ui: &U, clock: &C, deadline: u64) -> bool {
    while ui.pressed() {
        if clock.now_ms() > deadline {
            return false;
        }
    }
    true
}

fn finish<U: Ui, C: Clock>(ui: &mut U, clock: &C, ok: bool) -> bool {
    ui.set(if ok { State::Ok } else { State::Refused });
    let t = clock.now_ms();
    while clock.now_ms() - t < 150 {}
    ui.set(State::Idle);
    ok
}
