use crate::{
    println,
    task::task_block::{TaskBlock, TaskState},
    utils::RefCellSafe,
};

use crate::utils::get_app_data_by_name;
use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use lazy_static::lazy_static;
const MAX_TASKS: usize = 8;
const TARGET_LOC: usize = 0x8040_0000;

pub struct TaskManager {
    // pub current_task: isize,
    // Arc is for possible child and father..
    pub task_blocks: VecDeque<Arc<TaskBlock>>,
}
impl TaskManager {
    fn new() -> Self {
        Self {
            // current_task: -1,
            task_blocks: VecDeque::new(),
        }
    }
    // fn current_task(&self) -> &TaskBlock {
    //     &self.task_blocks[self.current_task as usize]
    // }
    /// attention! rust's str isn't ended with \0, but c's string is.
    /// add it manually.
    pub fn load_app_by_name(&mut self, name: &str) {
        unsafe extern "C" {
            // this is start also the number
            fn num_user_apps();
        }
        println!("[kernel] task manager loading app {}", name);
        let number_of_apps = unsafe { *(num_user_apps as *const i64) } as usize;
        let start_loc = (num_user_apps as usize) + core::mem::size_of::<usize>();
        let app_data = get_app_data_by_name(name.as_ptr() as usize, number_of_apps, start_loc);
        self.task_blocks
            .push_back(Arc::new(TaskBlock::new(app_data, name.as_ptr() as usize)));
    }
}
lazy_static! {
    pub static ref TASK_MANAGER: RefCellSafe<TaskManager> = RefCellSafe::new(TaskManager::new());
}
pub fn add_task(task: Arc<TaskBlock>) {
    let mut inner = TASK_MANAGER.borrow_mut();
    inner.task_blocks.push_back(task);
    drop(inner);
}
pub fn fetch_task() -> Option<Arc<TaskBlock>> {
    // println!("[kernel] Fetching next task.");

    let mut inner = TASK_MANAGER.borrow_mut();
    // println!("task manger borrowed");
    let temp = inner.task_blocks.pop_front();
    drop(inner);
    temp
}
