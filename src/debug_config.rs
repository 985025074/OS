//! Centralized debug switches.
//!
//! Keep these `false` for normal runs. Flip to `true` temporarily when diagnosing
//! hangs or scheduler/timer issues.

/// Default kernel log level when `LOG` is not set at build time.
///
/// You can override it by building with `LOG=error|warn|info|debug|trace`.
pub const DEFAULT_LOG_LEVEL: log::LevelFilter = log::LevelFilter::Warn;

/// Verbose timer debug logs (sleep timers, expiration, wakeups).
pub const DEBUG_TIMER: bool = false;

/// Verbose scheduler debug logs (ready queue push/pop, idle switches).
pub const DEBUG_SCHED: bool = false;

/// Verbose trap logs (timer/software interrupts, user exceptions).
pub const DEBUG_TRAP: bool = false;

/// Verbose syscall trace (very noisy).
pub const DEBUG_SYSCALL: bool = false;

/// Print a periodic diagnostic dump when the system has no runnable tasks.
pub const DEBUG_WATCHDOG: bool = false;

/// Run `log::test()` at boot (very noisy).
pub const DEBUG_LOG_TEST: bool = false;
