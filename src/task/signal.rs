pub const MAX_SIG: usize = 31;
use bitflags::bitflags;

use crate::{
    mm::{translated_mutref, translated_single_address},
    println,
    task::processor::current_process,
    task::{manager::pid2process, processor::suspend_current_and_run_next},
    trap::{context::TrapContext, get_current_token},
};

bitflags! {
    pub struct SignalFlags: u32 {
        const SIGDEF = 1; // Default signal handling
        const SIGHUP = 1 << 1;
        const SIGINT = 1 << 2;
        const SIGQUIT = 1 << 3;
        const SIGILL = 1 << 4;
        const SIGTRAP = 1 << 5;
        const SIGABRT = 1 << 6;
        const SIGBUS = 1 << 7;
        const SIGFPE = 1 << 8;
        const SIGKILL = 1 << 9;
        const SIGUSR1 = 1 << 10;
        const SIGSEGV = 1 << 11;
        const SIGUSR2 = 1 << 12;
        const SIGPIPE = 1 << 13;
        const SIGALRM = 1 << 14;
        const SIGTERM = 1 << 15;
        const SIGSTKFLT = 1 << 16;
        const SIGCHLD = 1 << 17;
        const SIGCONT = 1 << 18;
        const SIGSTOP = 1 << 19;
        const SIGTSTP = 1 << 20;
        const SIGTTIN = 1 << 21;
        const SIGTTOU = 1 << 22;
        const SIGURG = 1 << 23;
        const SIGXCPU = 1 << 24;
        const SIGXFSZ = 1 << 25;
        const SIGVTALRM = 1 << 26;
        const SIGPROF = 1 << 27;
        const SIGWINCH = 1 << 28;
        const SIGIO = 1 << 29;
        const SIGPWR = 1 << 30;
        const SIGSYS = 1 << 31;
    }
}
impl SignalFlags {
    pub fn check_error(&self) -> Option<(i32, &'static str)> {
        if self.contains(Self::SIGINT) {
            Some((-2, "Killed, SIGINT=2"))
        } else if self.contains(Self::SIGILL) {
            Some((-4, "Illegal Instruction, SIGILL=4"))
        } else if self.contains(Self::SIGABRT) {
            Some((-6, "Aborted, SIGABRT=6"))
        } else if self.contains(Self::SIGFPE) {
            Some((-8, "Erroneous Arithmetic Operation, SIGFPE=8"))
        } else if self.contains(Self::SIGKILL) {
            Some((-9, "Killed, SIGKILL=9"))
        } else if self.contains(Self::SIGSEGV) {
            Some((-11, "Segmentation Fault, SIGSEGV=11"))
        } else {
            //println!("[K] signalflags check_error  {:?}", self);
            None
        }
    }
}
pub fn check_if_current_signals_error() -> Option<(i32, &'static str)> {
    let process = current_process();
    let process_inner = process.borrow_mut();
    process_inner.signals.check_error()
}
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct SignalAction {
    pub handler: usize,
    pub mask: SignalFlags,
}
impl Default for SignalAction {
    fn default() -> Self {
        SignalAction {
            handler: 0,
            mask: SignalFlags { bits: 0 },
        }
    }
}

pub struct SignalActions {
    pub table: [SignalAction; MAX_SIG + 1],
    // pub table: i32,
}
impl Default for SignalActions {
    fn default() -> Self {
        // SignalActions { table: 0 }
        SignalActions {
            table: [SignalAction {
                handler: 0,
                mask: SignalFlags { bits: 0 },
            }; MAX_SIG + 1],
        }
    }
}

// set the signal mask, return the old mask
pub fn set_signal_mask(mask: u32) -> isize {
    let cur_process = current_process();
    let mut inner = cur_process.borrow_mut();
    let old_mask = inner.signals;
    if let Some(flag) = SignalFlags::from_bits(mask) {
        inner.signals = flag;
        old_mask.bits() as isize
    } else {
        -1
    }
}

// check if the signal num is valid (and action)
fn check_sigaction_error(signal: SignalFlags, action: usize, old_action: usize) -> bool {
    if action == 0
        || old_action == 0
        || signal == SignalFlags::SIGKILL
        || signal == SignalFlags::SIGSTOP
    {
        true
    } else {
        false
    }
}

pub fn set_signal(
    signum: i32,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> isize {
    let token = get_current_token();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if signum as usize > MAX_SIG {
        return -1;
    }
    if let Some(flag) = SignalFlags::from_bits(1 << signum) {
        if check_sigaction_error(flag, action as usize, old_action as usize) {
            return -1;
        }
        let prev_action = inner.signals_actions.table[signum as usize];
        *translated_mutref(token, old_action) = prev_action;
        inner.signals_actions.table[signum as usize] =
            *translated_mutref(token, action as *mut SignalAction);
        0
    } else {
        -1
    }
}

// insert the bit flag.. if already set  return -1
pub fn kill(pid: usize, signum: i32) -> isize {
    let process = pid2process(pid).unwrap();
    if let Some(flag) = SignalFlags::from_bits(1 << signum) {
        // insert the signal if legal
        let mut process_ref = process.borrow_mut();
        if process_ref.signals.contains(flag) {
            return -1;
        }
        process_ref.signals.insert(flag);
        0
    } else {
        -1
    }
}

pub fn kill_current(signum: i32) -> isize {
    let process = current_process();
    if let Some(flag) = SignalFlags::from_bits(1 << signum) {
        // insert the signal if legal
        let mut process_ref = process.borrow_mut();
        if process_ref.signals.contains(flag) {
            return -1;
        }
        process_ref.signals.insert(flag);
        0
    } else {
        -1
    }
}

// fn check_pending_signals() {
//     for sig in 0..(MAX_SIG + 1) {
//         let process = current_process();
//         let process_inner = process.borrow_mut();
//         let signal = SignalFlags::from_bits(1 << sig).unwrap();
//         // 如果当前📶 进入 等候区间,并且 没有被mask
//         if process_inner.signals.contains(signal) && (!process_inner.signals_masks.contains(signal))
//         {
//             let mut masked = true;
//             let handling_sig = process_inner.handling_signal;
//             // 已经在处理了,那么 不进行信号处理
//             if handling_sig == -1 {
//                 masked = false;
//             } else {
//                 // 没有在处理,但是 没有handler
//                 let handling_sig = handling_sig as usize;
//                 if !process_inner.signals_actions.table[handling_sig]
//                     .mask
//                     .contains(signal)
//                 {
//                     masked = false;
//                 }
//             }
//             if !masked {
//                 drop(process_inner);
//                 drop(process);
//                 if signal == SignalFlags::SIGKILL
//                     || signal == SignalFlags::SIGSTOP
//                     || signal == SignalFlags::SIGCONT
//                     || signal == SignalFlags::SIGDEF
//                 {
//                     // signal is a kernel signal
//                     call_kernel_signal_handler(signal);
//                 } else {
//                     // signal is a user signal
//                     call_user_signal_handler(sig, signal);
//                     return;
//                 }
//             }
//         }
//     }
// }
// check if there is siganl to solve .
// if so it will change the ret addr to the signal handler
// if have pending signal ,it will suspend
// pub fn handle_signals() {
//     loop {
//         // in the below function , it will change the sepc address to the signal
//         // (if possible )
//         check_pending_signals();
//         let (frozen, killed) = {
//             let process = current_process().unwrap();
//             let process_inner = process.borrow_mut();
//             (process_inner.frozen, process_inner.killed)
//         };
//         // if not frozen or killed , then break
//         if !frozen || killed {
//             break;
//         }
//         suspend_current_and_run_next();
//     }
// }

// os/src/process/mod.rs

// fn call_kernel_signal_handler(signal: SignalFlags) {
//     let process = current_process().unwrap();
//     let mut process_inner = process.borrow_mut();
//     match signal {
//         SignalFlags::SIGSTOP => {
//             process_inner.frozen = true;
//             process_inner.signals ^= SignalFlags::SIGSTOP;
//         }
//         SignalFlags::SIGCONT => {
//             if process_inner.signals.contains(SignalFlags::SIGCONT) {
//                 process_inner.signals ^= SignalFlags::SIGCONT;
//                 process_inner.frozen = false;
//             }
//         }
//         _ => {
//             // println!(
//             //     "[K] call_kernel_signal_handler:: current process sigflag {:?}",
//             //     process_inner.signals
//             // );
//             process_inner.killed = true;
//         }
//     }
// }

// fn call_user_signal_handler(sig: usize, signal: SignalFlags) {
//     let process = current_process();
//     let mut process_inner = process.borrow_mut();

//     let handler = process_inner.signal_actions.table[sig].handler;
//     if handler != 0 {
//         // user handler

//         // handle flag
//         process_inner.handling_signal = sig as isize;
//         // remove the siganl ..
//         process_inner.signals ^= signal;

//         // backup trapframe
//         let mut trap_ctx = process.borrow_mut().trap_context_loc.get_mut() as &mut TrapContext;
//         process_inner.trap_ctx_backup = Some(*trap_ctx);

//         // modify trapframe
//         trap_ctx.sepc = handler;

//         // put args (a0)
//         trap_ctx.x[10] = sig;
//     } else {
//         // default action
//         println!("[K] process/call_user_signal_handler: default action: ignore it or kill process");
//     }
// }

// pub fn sigreturn() -> isize {
//     let process =current_process();
//     let mut inner = process.borrow_mut();
//     inner.handling_signal = -1;
//     // restore the trap context
//     let trap_ctx = inner.trap_context_loc.get_mut() as &mut TrapContext;
//     *trap_ctx = inner.trap_ctx_backup.unwrap();
//     trap_ctx.x[10] as isize
// }
