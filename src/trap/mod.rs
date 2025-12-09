use core::arch::asm;

use crate::config::TRAMPOLINE;
use crate::task::block_sleep::check_timer;
use crate::task::processor::{PROCESSOR, exit_current_and_run_next, suspend_current_and_run_next};
// use crate::task::signal::{check_if_current_signals_error, handle_signals};
use crate::time::set_next_trigger;
use crate::{println, trap::context::TrapContext};
pub mod context;
pub mod trap;
use crate::syscall::syscall;
use riscv::{
    interrupt::Trap,
    register::{scause, sscratch, sstatus, stval},
};

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
    let alltraps_k_va = alltraps_k as usize - alltraps as usize + TRAMPOLINE;
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            alltraps_k_va,
            riscv::register::stvec::TrapMode::Direct,
        );
        riscv::register::stvec::write(to_write);
        sscratch::write(trap_from_kernel as usize);
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
pub fn trap_from_kernel(_trap_cx: &TrapContext) {
    let scause = scause::read();
    let stval = stval::read();
    match scause.cause() {
        Trap::Interrupt(TIME_INTERVAL) => {
            set_next_trigger();
            check_timer();
            // do not schedule, just return to kernel
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
    let processor = PROCESSOR.borrow();
    let now_task_block = processor.current().unwrap();
    drop(processor);
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
    let processor = PROCESSOR.borrow();
    let now_task_block = processor.current().unwrap();
    drop(processor);
    let process = now_task_block.process.upgrade().unwrap();
    let process_inner = process.borrow_mut();
    process_inner.memory_set.token()
}
#[unsafe(no_mangle)]
pub fn trap_handler() {
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
                (cx.x[17], [cx.x[10], cx.x[11], cx.x[12]])
            }; // cx is dropped here, releasing the borrow

            // Enable S-mode interrupt so timer can fire during syscall
            enable_supervisor_interrupt();

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
    {
        let cx = get_trap_context();
        println!(
            "[kernel] Unhandled user trap: {} (code = {}), sepc = {:#x}, stval = {:#x}",
            exception_name(code),
            code,
            cx.sepc,
            stval
        );
    }
    exit_current_and_run_next(-1);
}

#[unsafe(no_mangle)]
/// set the new addr of __restore asm function in TRAMPOLINE page,
/// set the reg a0 = trap_cx_ptr, reg a1 = phy addr of usr page table,
/// finally, jump to new addr of __restore asm function
pub fn trap_return() -> ! {
    // this shouln't be interrupted
    disable_supervisor_interrupt();
    set_user_trap_entry();

    // Get the trap context virtual address for the current thread
    let task = crate::task::processor::current_task().unwrap();
    let task_inner = task.borrow_mut();
    let trap_cx_ptr = task_inner.res.as_ref().unwrap().trap_cx_user_va();
    drop(task_inner);

    let user_satp = get_current_token();

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
