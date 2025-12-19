use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::mutex::Mutex;
use crate::fs::{File, Stdin, Stdout};
use crate::mm::{KERNEL_SPACE, MemorySet, translated_mutref};
use crate::println;
use crate::task::condvar::Condvar;
use crate::task::id::{PidHandle, pid_alloc};
use crate::task::manager::{add_task, insert_into_pid2process, select_hart_for_new_task};
use crate::task::semaphore::Semaphore;
use crate::task::signal::{SignalActions, SignalFlags};
use crate::task::task_block::TaskControlBlock;
use crate::trap::context::TrapContext;
use crate::trap::trap_handler;
use crate::utils::RecycleAllocator;
use spin::{Mutex as SpinMutex, MutexGuard};
pub struct ProcessControlBlock {
    // immutable
    pub pid: PidHandle,
    // mutable
    inner: SpinMutex<ProcessControlBlockInner>,
}

// 进程控制块
// 里面存放线程共用的 资源
pub struct ProcessControlBlockInner {
    pub is_zombie: bool,
    pub memory_set: MemorySet,
    pub parent: Option<Weak<ProcessControlBlock>>,
    pub children: Vec<Arc<ProcessControlBlock>>,
    pub exit_code: i32,
    //
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    pub signals: SignalFlags,
    pub signals_actions: SignalActions,
    pub signals_masks: SignalFlags,
    pub handling_signal: i32,
    // TaskControlBlock实际上现在是线程
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    // 进程控制块 有一个分配 线程ID的分配器
    pub task_res_allocator: RecycleAllocator,
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// Tasks waiting in `waitpid(-1/...)` for this process's children.
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
}

impl ProcessControlBlockInner {
    #[allow(unused)]
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }

    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }

    pub fn alloc_tid(&mut self) -> usize {
        self.task_res_allocator.alloc()
    }

    pub fn dealloc_tid(&mut self, tid: usize) {
        self.task_res_allocator.dealloc(tid)
    }

    pub fn thread_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
    }
}

impl ProcessControlBlock {
    pub fn borrow_mut(&self) -> MutexGuard<'_, ProcessControlBlockInner> {
        self.inner.lock()
    }

    pub fn try_borrow_mut(&self) -> Option<MutexGuard<'_, ProcessControlBlockInner>> {
        self.inner.try_lock()
    }

    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        // allocate a pid
        let pid_handle = pid_alloc();
        let process = Arc::new(Self {
            pid: pid_handle,
            inner: SpinMutex::new(ProcessControlBlockInner {
                is_zombie: false,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                fd_table: vec![
                    // 0 -> stdin
                    Some(Arc::new(Stdin)),
                    // 1 -> stdout
                    Some(Arc::new(Stdout)),
                    // 2 -> stderr
                    Some(Arc::new(Stdout)),
                ],
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                tasks: Vec::new(),
                task_res_allocator: RecycleAllocator::new(),
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
            }),
        });
        // new只会被主线程调用?,反正这里我们要手动创建一个 Task线程
        // NOTE: Pass false for alloc_user_res because from_elf has already
        // allocated user stack and trap context for the main thread (tid=0)
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&process),
            ustack_base,
            false, // Don't allocate again!
        ));
        // prepare trap_cx of main thread
        let task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        let ustack_top = task_inner.res.as_ref().unwrap().ustack_top();
        let kstack_top = task.kstack.get_top();
        drop(task_inner);
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            ustack_top,
            KERNEL_SPACE.lock().token(),
            kstack_top,
            trap_handler as usize,
        );
        // println!(
        //     "[DEBUG] ProcessControlBlock::new - entry_point={:#x}, ustack_top={:#x}, kstack_top={:#x}",
        //     entry_point, ustack_top, kstack_top
        // );
        // add main thread to the process
        let mut process_inner = process.borrow_mut();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        // add main thread to scheduler
        crate::println!(
            "[proc] init main thread pid={} tid=0 entry={:#x} ustack_top={:#x} kstack_top={:#x}",
            process.getpid(),
            entry_point,
            ustack_top,
            kstack_top
        );
        // Bootstrap initproc onto hart 0 for determinism.
        task.set_cpu_id(0);
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>) {
        assert_eq!(self.borrow_mut().thread_count(), 1);
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        // substitute memory_set
        self.borrow_mut().memory_set = memory_set;
        // then we need to update the task's user resource
        // Note: from_elf already created both the user stack and trap_cx area,
        // so we don't call alloc_user_res() which would cause double-mapping
        let task = self.borrow_mut().get_task(0);
        let mut task_inner = task.borrow_mut();
        let res = task_inner.res.as_mut().unwrap();
        res.ustack_base = ustack_base;
        // Update trap_cx_ppn from the new memory_set
        task_inner.trap_cx_ppn = res.trap_cx_ppn();
        // push arguments on user stack
        let mut user_sp = task_inner.res.as_mut().unwrap().ustack_top();
        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
        let argv_base = user_sp;
        let mut argv: Vec<_> = (0..=args.len())
            .map(|arg| {
                translated_mutref(
                    new_token,
                    (argv_base + arg * core::mem::size_of::<usize>()) as *mut usize,
                )
            })
            .collect();
        *argv[args.len()] = 0;
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
            *argv[i] = user_sp;
            let mut p = user_sp;
            for c in args[i].as_bytes() {
                *translated_mutref(new_token, p as *mut u8) = *c;
                p += 1;
            }
            *translated_mutref(new_token, p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();
        // initialize trap_cx
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            task.kstack.get_top(),
            trap_handler as usize,
        );
        trap_cx.x[10] = args.len();
        trap_cx.x[11] = argv_base;
        *task_inner.get_trap_cx() = trap_cx;
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        let mut parent = self.borrow_mut();
        assert_eq!(parent.thread_count(), 1);
        // clone parent's memory_set completely including trampoline/ustacks/trap_cxs
        let memory_set = MemorySet::from_existed_user(&parent.memory_set);
        // alloc a pid
        let pid = pid_alloc();
        // copy fd table
        let mut new_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        for fd in parent.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        // create child process pcb
        let child = Arc::new(Self {
            pid,
            inner: SpinMutex::new(ProcessControlBlockInner {
                is_zombie: false,
                memory_set,
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                exit_code: 0,
                fd_table: new_fd_table,
                // is right here?
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                tasks: Vec::new(),
                task_res_allocator: RecycleAllocator::new(),
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
            }),
        });
        // add child
        parent.children.push(Arc::clone(&child));
        // create main thread of child process
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&child),
            parent
                .get_task(0)
                .borrow_mut()
                .res
                .as_ref()
                .unwrap()
                .ustack_base(),
            // here we do not allocate trap_cx or ustack again
            // but mention that we allocate a new kstack here
            false,
        ));
        // Distribute child processes across harts.
        task.set_cpu_id(select_hart_for_new_task());
        // attach task to child process
        let mut child_inner = child.borrow_mut();
        child_inner.tasks.push(Some(Arc::clone(&task)));
        drop(child_inner);
        // modify kstack_top in trap_cx of this thread
        let task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        trap_cx.kernel_sp = task.kstack.get_top();
        // set return value for child process
        trap_cx.x[10] = 0;

        // println!(
        //     "[DEBUG] fork - child trap_cx: sepc={:#x}, sp={:#x}, kernel_sp={:#x}, a0={:#x}",
        //     trap_cx.sepc, trap_cx.x[2], trap_cx.kernel_sp, trap_cx.x[10]
        // );

        drop(task_inner);
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        // add this thread to scheduler
        add_task(task);
        child
    }

    pub fn getpid(&self) -> usize {
        self.pid.0
    }
}
