use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    mm::read_user_value,
    task::{
        manager::wakeup_task,
        processor::{block_current_and_run_next, current_process, current_task},
        task_block::TaskControlBlock,
    },
    trap::get_current_token,
};

const ENOSYS: isize = -38;
const EINVAL: isize = -22;
const EAGAIN: isize = -11;

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_WAKE_BITSET: usize = 10;
const FUTEX_PRIVATE_FLAG: usize = 128;
const FUTEX_CMD_MASK: usize = 0x7f;

type FutexKey = (usize, usize); // (pid, uaddr)

lazy_static! {
    static ref FUTEX_QUEUES: Mutex<BTreeMap<FutexKey, VecDeque<Arc<TaskControlBlock>>>> =
        Mutex::new(BTreeMap::new());
}

pub(crate) fn futex_wake(pid: usize, uaddr: usize, nr_wake: usize) -> isize {
    if uaddr == 0 {
        return EINVAL;
    }
    let key = (pid, uaddr);
    let mut map = FUTEX_QUEUES.lock();
    let Some(queue) = map.get_mut(&key) else {
        return 0;
    };
    let mut woke = 0usize;
    while woke < nr_wake {
        let Some(task) = queue.pop_front() else {
            break;
        };
        wakeup_task(task);
        woke += 1;
    }
    if queue.is_empty() {
        map.remove(&key);
    }
    woke as isize
}

pub fn syscall_futex(
    uaddr: usize,
    op: usize,
    val: usize,
    _timeout: usize,
    _uaddr2: usize,
    _val3: usize,
) -> isize {
    let cmd = op & FUTEX_CMD_MASK;
    let _private = (op & FUTEX_PRIVATE_FLAG) != 0;
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            if uaddr == 0 {
                return EINVAL;
            }
            let token = get_current_token();
            let cur = read_user_value(token, uaddr as *const i32);
            if cur != val as i32 {
                return EAGAIN;
            }
            let task = current_task().unwrap();
            let pid = current_process().getpid();
            FUTEX_QUEUES
                .lock()
                .entry((pid, uaddr))
                .or_insert_with(VecDeque::new)
                .push_back(task);
            block_current_and_run_next();
            0
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let pid = current_process().getpid();
            futex_wake(pid, uaddr, val)
        }
        _ => ENOSYS,
    }
}
