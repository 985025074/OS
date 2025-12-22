use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::mutex::Mutex;
use crate::fs::{File, Stdin, Stdout};
use crate::config::USER_STACK_SIZE;
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

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;
const AT_ENTRY: usize = 9;
const AT_UID: usize = 11;
const AT_EUID: usize = 12;
const AT_GID: usize = 13;
const AT_EGID: usize = 14;
const AT_SECURE: usize = 23;
const AT_RANDOM: usize = 25;

fn build_linux_stack(
    token: usize,
    mut sp: usize,
    args: &[String],
    envs: &[String],
    elf_aux: crate::mm::ElfAux,
    entry_point: usize,
) -> (usize, usize, usize) {
    fn write_bytes(token: usize, addr: usize, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            *translated_mutref(token, (addr + i) as *mut u8) = *b;
        }
    }

    fn push_usize(token: usize, sp: &mut usize, value: usize) {
        *sp -= core::mem::size_of::<usize>();
        *translated_mutref(token, *sp as *mut usize) = value;
    }

    let argc = args.len();
    let envc = envs.len();

    // Push argument and environment strings (top-down).
    let mut arg_ptrs: Vec<usize> = Vec::with_capacity(argc);
    for arg in args.iter().rev() {
        let bytes = arg.as_bytes();
        sp -= bytes.len() + 1;
        write_bytes(token, sp, bytes);
        *translated_mutref(token, (sp + bytes.len()) as *mut u8) = 0;
        arg_ptrs.push(sp);
    }
    arg_ptrs.reverse();

    let mut env_ptrs: Vec<usize> = Vec::with_capacity(envc);
    for env in envs.iter().rev() {
        let bytes = env.as_bytes();
        sp -= bytes.len() + 1;
        write_bytes(token, sp, bytes);
        *translated_mutref(token, (sp + bytes.len()) as *mut u8) = 0;
        env_ptrs.push(sp);
    }
    env_ptrs.reverse();

    // AT_RANDOM: 16 bytes.
    sp -= 16;
    let random_ptr = sp;
    let mut x = (entry_point as u64) ^ (sp as u64).rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    for i in 0..16usize {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *translated_mutref(token, (random_ptr + i) as *mut u8) = (x >> 56) as u8;
    }

    let auxv: [(usize, usize); 10] = [
        (AT_PHDR, elf_aux.phdr),
        (AT_PHENT, elf_aux.phent),
        (AT_PHNUM, elf_aux.phnum),
        (AT_PAGESZ, crate::config::PAGE_SIZE),
        (AT_ENTRY, entry_point),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_RANDOM, random_ptr),
    ];

    // Make the final entry stack pointer 16-byte aligned.
    // Starting from a 16-byte boundary, pushing an odd number of usize words flips alignment.
    let aux_words = (auxv.len() + 1) * 2; // + AT_NULL
    let envp_words = envc + 1; // NULL-terminated
    let argv_words = argc + 1; // NULL-terminated
    let total_words = aux_words + envp_words + argv_words + 1; // + argc
    sp &= !0xf;
    if total_words % 2 == 1 {
        sp -= core::mem::size_of::<usize>();
    }

    // auxv (type, val) pairs, ends with AT_NULL.
    push_usize(token, &mut sp, 0);
    push_usize(token, &mut sp, AT_NULL);
    for (t, v) in auxv.iter().rev() {
        push_usize(token, &mut sp, *v);
        push_usize(token, &mut sp, *t);
    }

    // envp pointers array (envc + 1), with trailing NULL.
    push_usize(token, &mut sp, 0);
    for p in env_ptrs.iter().rev() {
        push_usize(token, &mut sp, *p);
    }
    let envp_base = sp;

    // argv pointers array (argc + 1), with trailing NULL.
    push_usize(token, &mut sp, 0);
    for p in arg_ptrs.iter().rev() {
        push_usize(token, &mut sp, *p);
    }
    let argv_base = sp;

    // argc.
    push_usize(token, &mut sp, argc);

    (sp, argv_base, envp_base)
}
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
    /// Linux-like argv for `/proc/<pid>/cmdline` and ps.
    pub argv: Vec<String>,
    /// Process creation time since boot (ms).
    pub start_time_ms: usize,
    //
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    pub cwd: String,
    pub heap_start: usize,
    pub brk: usize,
    pub mmap_next: usize,
    pub mmap_areas: Vec<(usize, usize)>,
    pub signals: SignalFlags,
    pub signals_actions: SignalActions,
    pub signals_masks: SignalFlags,
    pub handling_signal: i32,
    /// Linux-like scheduler state used by rt-tests (cyclictest/hackbench).
    pub sched_policy: i32,
    pub sched_priority: i32,
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
        let (memory_set, ustack_base, entry_point, elf_aux) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        let heap_start = ustack_base + USER_STACK_SIZE;
        // allocate a pid
        let pid_handle = pid_alloc();
        let args = vec![String::from("init_proc")];
        let (user_sp, argv_base, envp_base) = build_linux_stack(
            new_token,
            ustack_base + USER_STACK_SIZE,
            &args,
            &[],
            elf_aux,
            entry_point,
        );
        let process = Arc::new(Self {
            pid: pid_handle,
            inner: SpinMutex::new(ProcessControlBlockInner {
                is_zombie: false,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                argv: args.clone(),
                start_time_ms: crate::time::get_time_ms(),
                fd_table: vec![
                    // 0 -> stdin
                    Some(Arc::new(Stdin)),
                    // 1 -> stdout
                    Some(Arc::new(Stdout)),
                    // 2 -> stderr
                    Some(Arc::new(Stdout)),
                ],
                cwd: String::from("/user"),
                heap_start,
                brk: heap_start,
                mmap_next: 0x4000_0000,
                mmap_areas: Vec::new(),
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                sched_policy: 0,
                sched_priority: 0,
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
        let kstack_top = task.kstack.get_top();
        drop(task_inner);
        let mut tcx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            kstack_top,
            trap_handler as usize,
        );
        tcx.x[10] = args.len();
        tcx.x[11] = argv_base;
        tcx.x[12] = envp_base;
        *trap_cx = tcx;
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
            ustack_base + USER_STACK_SIZE,
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
        let (memory_set, ustack_base, entry_point, elf_aux) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        let heap_start = ustack_base + USER_STACK_SIZE;
        // substitute memory_set
        {
            let mut inner = self.borrow_mut();
            inner.memory_set = memory_set;
            inner.heap_start = heap_start;
            inner.brk = heap_start;
            inner.mmap_next = 0x4000_0000;
            inner.mmap_areas.clear();
            inner.argv = args.clone();
        }
        // then we need to update the task's user resource
        // Note: from_elf already created both the user stack and trap_cx area,
        // so we don't call alloc_user_res() which would cause double-mapping
        let task = self.borrow_mut().get_task(0);
        let mut task_inner = task.borrow_mut();
        let res = task_inner.res.as_mut().unwrap();
        res.ustack_base = ustack_base;
        // Update trap_cx_ppn from the new memory_set
        task_inner.trap_cx_ppn = res.trap_cx_ppn();
        // Build a Linux-like initial stack layout so both:
        // - C runtime can read argc/argv from `sp` (as in oscomp ulib), and
        // - Rust runtime can read argc/argv from a0/a1.
        let (user_sp, argv_base, envp_base) = build_linux_stack(
            new_token,
            task_inner.res.as_mut().unwrap().ustack_top(),
            &args,
            &[],
            elf_aux,
            entry_point,
        );
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
        trap_cx.x[12] = envp_base;
        *task_inner.get_trap_cx() = trap_cx;
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        let mut parent = self.borrow_mut();
        assert_eq!(parent.thread_count(), 1);
        let sched_policy = parent.sched_policy;
        let sched_priority = parent.sched_priority;
        let argv = parent.argv.clone();
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
                argv,
                start_time_ms: crate::time::get_time_ms(),
                fd_table: new_fd_table,
                cwd: parent.cwd.clone(),
                heap_start: parent.heap_start,
                brk: parent.brk,
                mmap_next: parent.mmap_next,
                mmap_areas: parent.mmap_areas.clone(),
                // is right here?
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                sched_policy,
                sched_priority,
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
