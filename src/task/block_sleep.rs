// this is used for sleep (blocked) threads
use core::{cmp::Ordering, time};

use crate::{
    println,
    task::{manager::wakeup_task, task_block::TaskControlBlock},
    time::get_time_ms,
    utils::RefCellSafe,
};
use lazy_static::*;

use alloc::{collections::BinaryHeap, sync::Arc};
pub struct TimeWrap {
    pub task: Arc<TaskControlBlock>,
    pub time_expired: usize,
}
impl TimeWrap {
    fn new(task: Arc<TaskControlBlock>, time_wait: usize) -> Self {
        Self {
            task,
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
    pub static ref TIMERS: RefCellSafe<BinaryHeap<TimeWrap>> =
        unsafe { RefCellSafe::new(BinaryHeap::<TimeWrap>::new()) };
}
// impl this...

pub fn add_timer(task: Arc<TaskControlBlock>, time_wait: usize) {
    let current_ms = get_time_ms();
    let timer = TimeWrap::new(task, time_wait);
    println!(
        "[add_timer] Current time: {}ms, will expire at: {}ms",
        current_ms, timer.time_expired
    );
    TIMERS.borrow_mut().push(timer);
}
pub fn check_timer() {
    let current_ms = get_time_ms();
    let mut timers = TIMERS.borrow_mut();

    // if let Some(timer) = timers.peek() {
    //     println!(
    //         "[check_timer] Current: {}ms, next timer expires at: {}ms",
    //         current_ms, timer.time_expired
    //     );
    // }

    while let Some(timer) = timers.peek() {
        if timer.time_expired <= current_ms {
            // println!(
            //     "[check_timer] Waking up task at {}ms (expired at {}ms)",
            //     current_ms, timer.time_expired
            // );
            let task = timer.task.clone();
            timers.pop();
            wakeup_task(task);
        } else {
            break;
        }
    }
}
