use crate::task::load_next_task;
use crate::{println, trap::context::TrapContext};

pub mod context;
pub mod trap;
use crate::syscall::syscall;
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
pub fn init_trap() {
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            trap::alltraps as usize,
            riscv::register::stvec::TrapMode::Direct,
        );
        riscv::register::stvec::write(to_write);
    }
}
#[unsafe(no_mangle)]
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
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
            load_next_task();
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
    cx
}
