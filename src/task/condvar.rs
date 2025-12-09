use alloc::{collections::VecDeque, sync::Arc};

use crate::{
    task::{
        manager::wakeup_task,
        mutex::Mutex,
        processor::{block_current_and_run_next, current_task},
        task_block::TaskControlBlock,
    },
    utils::RefCellSafe,
};

pub struct Condvar {
    pub inner: RefCellSafe<CondvarInner>,
}

pub struct CondvarInner {
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
}

impl Condvar {
    pub fn new() -> Self {
        Self {
            inner: unsafe {
                RefCellSafe::new(CondvarInner {
                    wait_queue: VecDeque::new(),
                })
            },
        }
    }

    pub fn signal(&self) {
        let mut inner = self.inner.borrow_mut();
        if let Some(task) = inner.wait_queue.pop_front() {
            wakeup_task(task);
        }
    }

    pub fn wait(&self, mutex: Arc<dyn Mutex>) {
        mutex.unlock();
        let mut inner = self.inner.borrow_mut();
        inner.wait_queue.push_back(current_task().unwrap());
        drop(inner);
        block_current_and_run_next();
        mutex.lock();
    }
}
