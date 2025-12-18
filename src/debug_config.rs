//! Centralized debug switches.
//!
//! Keep these `false` for normal runs. Flip to `true` temporarily when diagnosing
//! hangs or scheduler/timer issues.

/// Verbose timer debug logs (sleep timers, expiration, wakeups).
pub const DEBUG_TIMER: bool = false;

/// Verbose scheduler debug logs (ready queue push/pop, idle switches).
pub const DEBUG_SCHED: bool = false;
