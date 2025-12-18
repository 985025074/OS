use alloc::{collections::vec_deque::VecDeque, sync::Arc};

use crate::task::task_block::TaskControlBlock;
use spin::Mutex as SpinLock;

pub struct Semaphore {
    pub inner: SpinLock<SemaphoreInner>,
}

pub struct SemaphoreInner {
    pub count: isize,
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
}

impl Semaphore {
    pub fn new(res_count: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: SpinLock::new(SemaphoreInner {
                count: res_count as isize,
                wait_queue: VecDeque::new(),
            }),
        })
    }
    pub fn up(&self) {
        let mut inner = self.inner.lock();
        inner.count += 1;
        if inner.count <= 0 {
            if let Some(task) = inner.wait_queue.pop_front() {
                // everytime we just wake one
                crate::task::manager::wakeup_task(task);
            }
        }
    }
    pub fn down(&self) {
        let mut inner = self.inner.lock();
        inner.count -= 1;
        if inner.count < 0 {
            let task = crate::task::processor::current_task().unwrap();
            inner.wait_queue.push_back(task);
            drop(inner); // Drop the borrow before blocking
            crate::task::processor::block_current_and_run_next();
        }
    }
}
