// this is used for sleep (blocked) threads
use core::{cmp::Ordering, time};

use crate::{
    task::{manager::wakeup_task, task_block::TaskControlBlock},
    time::get_time_ms,
};
use lazy_static::*;
use spin::Mutex;

use alloc::{collections::BinaryHeap, sync::Arc};

use crate::debug_config::DEBUG_TIMER;
use crate::task::process_block::ProcessControlBlock;
pub struct TimeWrap {
    pub task: Arc<TaskControlBlock>,
    pub tid: usize,
    pub time_expired: usize,
}
impl TimeWrap {
    fn new(task: Arc<TaskControlBlock>, time_wait: usize) -> Self {
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        Self {
            task,
            tid,
            time_expired: get_time_ms() + time_wait,
        }
    }
}

impl PartialEq for TimeWrap {
    fn eq(&self, other: &Self) -> bool {
        self.time_expired == other.time_expired
    }
}
impl Eq for TimeWrap {}
impl PartialOrd for TimeWrap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = -(self.time_expired as isize);
        let b = -(other.time_expired as isize);
        Some(a.cmp(&b))
    }
}
impl Ord for TimeWrap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

lazy_static! {
    pub static ref TIMERS: Mutex<BinaryHeap<TimeWrap>> = Mutex::new(BinaryHeap::<TimeWrap>::new());
}

pub fn add_timer(task: Arc<TaskControlBlock>, time_wait: usize) {
    let timer = TimeWrap::new(task, time_wait);
    crate::log_if!(
        DEBUG_TIMER,
        debug,
        "[timer] add tid={} wait_ms={} expire_ms={}",
        timer.tid,
        time_wait,
        timer.time_expired
    );
    TIMERS.lock().push(timer);
}

pub fn check_timer() {
    let current_ms = get_time_ms();

    loop {
        // Pop one expired timer (if any) while holding the lock, then wake it after releasing.
        let popped = {
            let mut timers = TIMERS.lock();
            if DEBUG_TIMER {
                let len = timers.len();
                if let Some(head) = timers.peek() {
                    log::debug!(
                        "[timer] check now_ms={} timers_len={} head_tid={} head_expire_ms={}",
                        current_ms,
                        len,
                        head.tid,
                        head.time_expired
                    );
                } else {
                    log::debug!("[timer] check now_ms={} timers_len=0", current_ms);
                }
            }
            if let Some(head) = timers.peek() {
                let expire = head.time_expired;
                if DEBUG_TIMER {
                    let status = if expire <= current_ms { "ready" } else { "future" };
                    log::debug!(
                        "[timer] peek tid={} expire_ms={} now_ms={} status={}",
                        head.tid,
                        expire,
                        current_ms,
                        status
                    );
                }
                if expire <= current_ms {
                    Some(timers.pop().unwrap())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(timer) = popped {
            let pid = timer
                .task
                .process
                .upgrade()
                .map(|p: alloc::sync::Arc<ProcessControlBlock>| p.getpid())
                .unwrap_or(usize::MAX);
            crate::log_if!(
                DEBUG_TIMER,
                debug,
                "[timer] pop pid={} tid={} expire_ms={} now_ms={}",
                pid,
                timer.tid,
                timer.time_expired,
                current_ms
            );
            crate::log_if!(
                DEBUG_TIMER,
                debug,
                "[timer] wake pid={} tid={} expire_ms={} now_ms={}",
                pid,
                timer.tid,
                timer.time_expired,
                current_ms
            );
            wakeup_task(timer.task.clone());
            // Continue looping in case more timers have expired at the same tick.
            continue;
        }
        break;
    }
}
