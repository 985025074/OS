use core::{arch::asm, sync::atomic::{AtomicBool, AtomicUsize, Ordering}};

use crate::config::TRAMPOLINE;
use crate::debug_config::DEBUG_TRAP;
use crate::task::block_sleep::check_timer;
use crate::task::processor::{exit_current_and_run_next, suspend_current_and_run_next};
// use crate::task::signal::{check_if_current_signals_error, handle_signals};
use crate::time::set_next_trigger;
use crate::{println, trap::context::TrapContext};
pub mod context;
pub mod trap;
use crate::syscall::syscall;
use riscv::{interrupt::Trap, register::{scause, sstatus, stval}};

#[allow(unused)]
fn log_for_trap_context(context: &TrapContext) {
    println!("--- Trap Context ---");
    for i in 0..32 {
        println!("x[{}] = {:#x}", i, context.x[i]);
    }
    // println!("sstatus = {:#x}", context.sstatus);
    println!("sepc    = {:#x}", context.sepc);
    println!("--------------------");
}

const USER_ENV_CALL: usize = 8;
const INSTRUCTION_ADDRESS_MISALIGNED: usize = 0;
const INSTRUCTION_ACCESS_FAULT: usize = 1;
const ILLEGAL_INSTRUCTION: usize = 2;
const BREAKPOINT: usize = 3;
const LOAD_ADDRESS_MISALIGNED: usize = 4;
const LOAD_ACCESS_FAULT: usize = 5;
const STORE_ADDRESS_MISALIGNED: usize = 6;
const STORE_ACCESS_FAULT: usize = 7;
const INSTRUCTION_PAGE_FAULT: usize = 12;
const LOAD_PAGE_FAULT: usize = 13;
const STORE_PAGE_FAULT: usize = 15;
const TIME_INTERVAL: usize = 5;
const SOFTWARE_INTERRUPT: usize = 1;

/// Log only the first trap_return to see initial user entry.
static FIRST_TRAP_RETURN_LOGGED: AtomicBool = AtomicBool::new(false);
/// Count trap_return invocations for debugging.
static TRAP_RETURN_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Count trap_handler invocations for debugging.
static TRAP_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn init_trap() {
    set_kernel_trap_entry();
}

// kernel_interupt made the os able to stop when time is up.
// so some sleeping task can be waked up.
fn set_kernel_trap_entry() {
    unsafe extern "C" {
        fn alltraps();
        fn alltraps_k();
    }
    let alltraps_k_va = alltraps_k as usize;
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            alltraps_k_va,
            riscv::register::stvec::TrapMode::Direct,
        );
        riscv::register::stvec::write(to_write);
    }
}

fn set_user_trap_entry() {
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            TRAMPOLINE as usize,
            riscv::register::stvec::TrapMode::Direct,
        );
        riscv::register::stvec::write(to_write);
    }
}

fn enable_supervisor_interrupt() {
    unsafe {
        sstatus::set_sie();
    }
}

fn disable_supervisor_interrupt() {
    unsafe {
        sstatus::clear_sie();
    }
}

#[unsafe(no_mangle)]
pub fn trap_from_kernel(trap_cx: &mut TrapContext) {
    let scause = scause::read();
    let stval = stval::read();
    match scause.cause() {
        Trap::Interrupt(TIME_INTERVAL) => {
            let hart = {
                let h: usize;
                unsafe { asm!("mv {}, tp", out(reg) h) };
                h
            };
            static KERNEL_TIMER_LOG: AtomicUsize = AtomicUsize::new(0);
            let kcnt = KERNEL_TIMER_LOG.fetch_add(1, Ordering::SeqCst);
            if DEBUG_TRAP && kcnt < 4 {
                log::debug!("[trap_from_kernel] hart={} timer interrupt", hart);
            }
            // crate::println!("[trap_from_kernel] Timer interrupt, checking timers...");
            set_next_trigger();
            check_timer();
            // crate::println!("[trap_from_kernel] Done checking timers");
            // do not schedule, just return to kernel
        }
        Trap::Interrupt(_) => {
            // Clear possible software interrupt and ignore others
            unsafe { riscv::register::sip::clear_ssoft() };
        }
        Trap::Exception(BREAKPOINT) => {
            // Skip the ebreak
            trap_cx.sepc += 2;
        }
        Trap::Exception(ILLEGAL_INSTRUCTION) => {
            panic!(
                "Illegal instruction in kernel: sepc = {:#x}, stval = {:#x}",
                trap_cx.sepc, stval
            );
        }
        Trap::Exception(INSTRUCTION_PAGE_FAULT)
        | Trap::Exception(LOAD_PAGE_FAULT)
        | Trap::Exception(STORE_PAGE_FAULT) => {
            panic!(
                "Kernel page fault: cause = {:?}, sepc = {:#x}, stval = {:#x}",
                scause.cause(),
                trap_cx.sepc,
                stval
            );
        }
        _ => {
            panic!(
                "Unsupported trap from kernel: {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
}
// todo : avoid cloning here..
fn get_trap_context() -> &'static mut TrapContext {
    let now_task_block = crate::task::processor::current_task().unwrap();
    let now_task_block_inner = now_task_block.borrow_mut();
    let trap_cx_ppn = now_task_block_inner.trap_cx_ppn;
    // IMPORTANT: Drop the borrow before returning the reference
    // This is safe because:
    // 1. trap_cx_ppn is a PhysPageNum (Copy type)
    // 2. The physical page won't be deallocated while the task is running
    // 3. We're in kernel space with traps disabled
    drop(now_task_block_inner);
    trap_cx_ppn.get_mut()
}
pub fn get_current_token() -> usize {
    let now_task_block = crate::task::processor::current_task().unwrap();
    let process = now_task_block.process.upgrade().unwrap();
    let process_inner = process.borrow_mut();
    process_inner.memory_set.token()
}
#[unsafe(no_mangle)]
pub fn trap_handler() {
    let idx = TRAP_HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
    if DEBUG_TRAP && idx < 6 {
        let hart = {
            let h: usize;
            unsafe { asm!("mv {}, tp", out(reg) h) };
            h
        };
        log::debug!(
            "[trap_handler#{}] hart={} scause={:?} stval={:#x}",
            idx,
            hart,
            scause::read().cause(),
            stval::read()
        );
    }
    // now is kernel space
    set_kernel_trap_entry();
    let scause = scause::read();
    let stval = stval::read();
    let code = scause.cause(); // usize
    match code {
        // user env call ...
        Trap::Exception(USER_ENV_CALL) => {
            // Get syscall arguments
            let (syscall_id, args) = {
                let cx = get_trap_context();
                cx.sepc += 4;
                (
                    cx.x[17],
                    [cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]],
                )
            }; // cx is dropped here, releasing the borrow

            // NOTE: Do NOT enable interrupts during syscall execution.
            // This is because syscalls may acquire spin::Mutex locks (e.g., heap allocator,
            // VirtIO block device), and if a timer interrupt fires while a lock is held,
            // the interrupt handler might try to allocate memory (via wakeup_task -> add_task
            // -> VecDeque::push_back), causing a deadlock.
            //
            // The tradeoff is that long-running syscalls (like exec) won't be preemptible,
            // but this is acceptable for correctness.
            //
            // If you need preemptible syscalls, consider:
            // 1. Using interrupt-safe allocators
            // 2. Avoiding memory allocation in interrupt handlers
            // 3. Selectively enabling interrupts only for syscalls that don't use spin::Mutex

            // Execute syscall (may change memory layout via exec)
            let result = syscall(syscall_id, args);

            // Get trap context again (may be different after exec)
            let cx = get_trap_context();
            cx.x[10] = result as usize;
        }
        Trap::Exception(code) => {
            handle_user_exception(code, stval);
        }
        Trap::Interrupt(TIME_INTERVAL) => {
            set_next_trigger();
            check_timer();
            suspend_current_and_run_next();
        }
        Trap::Interrupt(SOFTWARE_INTERRUPT) => {
            // Used as an IPI to wake up harts from `wfi` (e.g., when a remote hart enqueues a task).
            unsafe { riscv::register::sip::clear_ssoft() };
        }
        Trap::Interrupt(interrupt) => {
            panic!(
                "Unsupported interrupt: cause = {:?}, stval = {:#x}",
                interrupt, stval
            );
        }
    }
    // println!("handle siganl");
    // handle_signals();

    // if let Some((errno, msg)) = check_if_current_signals_error() {
    //     println!("[kernel] {}", msg);
    //     exit_current_and_run_next(errno);
    // }
    trap_return();
}

fn exception_name(code: usize) -> &'static str {
    match code {
        INSTRUCTION_ADDRESS_MISALIGNED => "Instruction address misaligned",
        INSTRUCTION_ACCESS_FAULT => "Instruction access fault",
        ILLEGAL_INSTRUCTION => "Illegal instruction",
        BREAKPOINT => "Breakpoint",
        LOAD_ADDRESS_MISALIGNED => "Load address misaligned",
        LOAD_ACCESS_FAULT => "Load access fault",
        STORE_ADDRESS_MISALIGNED => "Store address misaligned",
        STORE_ACCESS_FAULT => "Store access fault",
        INSTRUCTION_PAGE_FAULT => "Instruction page fault",
        LOAD_PAGE_FAULT => "Load page fault",
        STORE_PAGE_FAULT => "Store page fault",
        USER_ENV_CALL => "Environment call from U-mode",
        _ => "Unknown exception",
    }
}

fn handle_user_exception(code: usize, stval: usize) {
    let cx = get_trap_context();
    log::warn!(
        "[user_exn] code={} ({}) sepc={:#x} stval={:#x}",
        code,
        exception_name(code),
        cx.sepc,
        stval
    );
    exit_current_and_run_next(-1);
}

#[unsafe(no_mangle)]
/// set the new addr of __restore asm function in TRAMPOLINE page,
/// set the reg a0 = trap_cx_ptr, reg a1 = phy addr of usr page table,
/// finally, jump to new addr of __restore asm function
pub fn trap_return() -> ! {
    let entered = TRAP_RETURN_COUNT.load(Ordering::SeqCst);
    if DEBUG_TRAP && entered < 4 {
        let hart = {
            let h: usize;
            unsafe { asm!("mv {}, tp", out(reg) h) };
            h
        };
        log::debug!(
            "[trap_return entry#{}] hart={} sp={:#x}",
            entered,
            hart,
            {
                let s: usize;
                unsafe { asm!("mv {}, sp", out(reg) s) };
                s
            }
        );
    }
    // this shouln't be interrupted
    disable_supervisor_interrupt();
    set_user_trap_entry();

    // Get the trap context virtual address for the current thread
    let task = crate::task::processor::current_task().unwrap();
    let task_inner = task.borrow_mut();
    let trap_cx_ptr = task_inner.res.as_ref().unwrap().trap_cx_user_va();
    drop(task_inner);

    let user_satp = get_current_token();

    let cnt = TRAP_RETURN_COUNT.fetch_add(1, Ordering::SeqCst);
    if DEBUG_TRAP && cnt < 4 {
        let hart = {
            let h: usize;
            unsafe { asm!("mv {}, tp", out(reg) h) };
            h
        };
        if !FIRST_TRAP_RETURN_LOGGED.swap(true, Ordering::SeqCst) {
            let cx = get_trap_context();
            let tp_kernel: usize;
            unsafe { asm!("mv {}, tp", out(reg) tp_kernel) };
            log::debug!(
                "[trap_return#{}] hart={} trap_cx_ptr={:#x} sepc={:#x} user_satp={:#x} tp={:#x}",
                cnt,
                hart,
                trap_cx_ptr,
                cx.sepc,
                user_satp,
                tp_kernel
            );
        } else {
            log::debug!(
                "[trap_return#{}] hart={} trap_cx_ptr={:#x} user_satp={:#x}",
                cnt,
                hart,
                trap_cx_ptr,
                user_satp,
            );
        }
    }

    unsafe extern "C" {
        fn alltraps();
        fn restore();
    }
    let restore_va = restore as usize - alltraps as usize + TRAMPOLINE;
    unsafe {
        asm!(
            "fence.i",
            "jr {restore_va}",             // jump to new addr of __restore asm function
            restore_va = in(reg) restore_va,
            in("a0") trap_cx_ptr,      // a0 = virt addr of Trap Context
            in("a1") user_satp,        // a1 = phy addr of usr page table
            options(noreturn)
        );
    }
}
