use alloc::{collections::vec_deque::VecDeque, sync::Arc};

use crate::{
    task::{
        manager::wakeup_task,
        processor::{
            block_current_and_run_next, current_task, suspend_current_and_run_next,
            take_current_task,
        },
        task_block::TaskControlBlock,
    },
    utils::RefCellSafe,
};

// this is needed for multi thread(or error )
pub trait Mutex: Sync + Send {
    fn lock(&self);
    fn unlock(&self);
}
// todo :busy-wait mutex and block mutex
// because things in arc cant be changed we need inner part here.

pub struct BlockMutex {
    inner: RefCellSafe<BlockMutexInner>,
}
pub struct BlockMutexInner {
    is_blocked: bool,
    //use priorioty queue to contain the TimeWrap(block task)
    wait_queue: VecDeque<Arc<TaskControlBlock>>,
}
impl BlockMutex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RefCellSafe::new(BlockMutexInner {
                is_blocked: false,
                wait_queue: VecDeque::new(),
            }),
        })
    }
}
impl Mutex for BlockMutex {
    fn lock(&self) {
        let mut inner = self.inner.borrow_mut();
        match inner.is_blocked {
            false => {
                inner.is_blocked = true;
            }
            true => {
                let task = current_task().unwrap();
                inner.wait_queue.push_back(task);
                drop(inner); // Drop the borrow before blocking
                block_current_and_run_next();
            }
        }
    }
    fn unlock(&self) {
        let mut inner = self.inner.borrow_mut();
        assert!(inner.is_blocked);
        if let Some(task) = inner.wait_queue.pop_front() {
            // everytime we just wake one
            wakeup_task(task);
        } else {
            inner.is_blocked = false;
        }
    }
}

pub struct SpinMutex {
    locked: RefCellSafe<bool>,
}
impl SpinMutex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            locked: RefCellSafe::new(false),
        })
    }
}
impl Mutex for SpinMutex {
    fn lock(&self) {
        loop {
            let mut locked = self.locked.borrow_mut();
            if *locked {
                drop(locked);
                suspend_current_and_run_next();
                continue;
            } else {
                *locked = true;
                return;
            }
        }
    }

    fn unlock(&self) {
        let mut locked = self.locked.borrow_mut();
        *locked = false;
    }
}
