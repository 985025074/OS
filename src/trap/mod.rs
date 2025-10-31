use core::arch::asm;

use crate::config::{TRAMPOLINE, TRAP_CONTEXT, kernel_stack_position};
use crate::task::TASK_MANAGER;
use crate::task::{go_to_next_task, suspend_and_go_to_next};
use crate::time::set_next_trigger;
use crate::{println, trap::context::TrapContext};
pub mod context;
pub mod trap;
use crate::syscall::syscall;
use riscv::register::scause::set;
use riscv::register::stvec::{Stvec, TrapMode};
use riscv::{
    interrupt::{Exception, Trap},
    register::{scause, stval},
};

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
const INSTRUCTION_FAULT: usize = 1;
const TIME_INTERVAL: usize = 5;
pub fn init_trap() {
    // todo : 这里仍有bug dont know why
    // set_kernel_trap_entry();
    set_user_trap_entry();
}
#[unsafe(no_mangle)]
fn trap_from_kernel() -> ! {
    panic!("not impled");
}
fn set_kernel_trap_entry() {
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            trap_from_kernel as usize,
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
    // unsafe {
    //     stvec::write(trampoline as usize, TrapMode::Direct);
    // }
}
fn get_trap_context() -> &'static mut TrapContext {
    let now_task_num = TASK_MANAGER.borrow_mut().current_task;
    let task_block = &TASK_MANAGER.borrow().task_blocks[now_task_num as usize];
    let cx = task_block.trap_context_loc.get_bytes_array();
    unsafe { &mut *(cx.as_mut_ptr() as *mut TrapContext) }
}
pub fn get_current_token() -> usize {
    let now_task_num = TASK_MANAGER.borrow_mut().current_task;
    let task_block = &TASK_MANAGER.borrow().task_blocks[now_task_num as usize];
    task_block.code_memory_set.token()
}
#[unsafe(no_mangle)]
pub fn trap_handler() {
    // now is kernel space
    // set_kernel_trap_entry();
    let cx: &mut TrapContext = get_trap_context();
    use crate::println;
    // log_for_trap_context(cx);
    let scause = scause::read();
    let stval = stval::read();
    let code = scause.cause(); // usize

    match code {
        // user env call ...
        Trap::Exception(USER_ENV_CALL) => {
            // UserEnvCall
            cx.sepc += 4;
            // println!("USER ENV CALL!,call id = {}", cx.x[17]);
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(INSTRUCTION_FAULT) => {
            println!(
                "Instruction Fault at sepc = {:#x}, stval = {:#x}",
                cx.sepc, stval
            );
            go_to_next_task();
        }
        Trap::Interrupt(TIME_INTERVAL) => {
            set_next_trigger();
            suspend_and_go_to_next();
        }
        _ => {
            let Trap::Exception(code) = code else {
                panic!(
                    "Unsupported interupt: cause = {:?}, stval = {:#x}",
                    code, stval
                )
            };
            panic!("Unsupported trap: cause = {}, stval = {:#x}", code, stval);
        }
    }
    trap_return();
}
#[unsafe(no_mangle)]
/// set the new addr of __restore asm function in TRAMPOLINE page,
/// set the reg a0 = trap_cx_ptr, reg a1 = phy addr of usr page table,
/// finally, jump to new addr of __restore asm function
pub fn trap_return() -> ! {
    set_user_trap_entry();
    let trap_cx_ptr = TRAP_CONTEXT;
    let user_satp = get_current_token();
    unsafe extern "C" {
        fn alltraps();
        fn restore();
    }
    let restore_va = restore as usize - alltraps as usize + TRAMPOLINE;
    // println!("restore va {:x}", restore_va);
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
