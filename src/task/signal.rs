pub const MAX_SIG: usize = 31;
use bitflags::bitflags;

use crate::{
    mm::{translated_mutref, translated_single_address},
    println,
    task::{
        pid::get_task_by_pid,
        processor::{current_task, suspend_current_and_run_next},
    },
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
// pub fn check_if_current_signals_error() -> Option<(i32, &'static str)> {
//     if let Some(task) = current_task() {
//         let task_inner = task.get_inner();
//         task_inner.signals.check_error()
//     } else {
//         None
//     }
// }
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

// // set the signal mask, return the old mask
// pub fn set_signal_mask(mask: u32) -> isize {
//     if let Some(task) = current_task() {
//         let mut inner = task.get_inner();
//         let old_mask = inner.signal_mask;
//         if let Some(flag) = SignalFlags::from_bits(mask) {
//             inner.signal_mask = flag;
//             old_mask.bits() as isize
//         } else {
//             -1
//         }
//     } else {
//         -1
//     }
// }

// // check if the signal num is valid (and action)
// fn check_sigaction_error(signal: SignalFlags, action: usize, old_action: usize) -> bool {
//     if action == 0
//         || old_action == 0
//         || signal == SignalFlags::SIGKILL
//         || signal == SignalFlags::SIGSTOP
//     {
//         true
//     } else {
//         false
//     }
// }

// pub fn set_signal(
//     signum: i32,
//     action: *const SignalAction,
//     old_action: *mut SignalAction,
// ) -> isize {
//     let token = get_current_token();
//     let task = current_task().unwrap();
//     let mut inner = task.get_inner();
//     if signum as usize > MAX_SIG {
//         return -1;
//     }
//     if let Some(flag) = SignalFlags::from_bits(1 << signum) {
//         if check_sigaction_error(flag, action as usize, old_action as usize) {
//             return -1;
//         }
//         let prev_action = inner.signal_actions.table[signum as usize];
//         *translated_mutref(token, old_action) = prev_action;
//         inner.signal_actions.table[signum as usize] =
//             *translated_mutref(token, action as *mut SignalAction);
//         0
//     } else {
//         -1
//     }
// }

// // insert the bit flag.. if already set  return -1
// pub fn kill(pid: usize, signum: i32) -> isize {
//     if let Some(task) = get_task_by_pid(pid) {
//         if let Some(flag) = SignalFlags::from_bits(1 << signum) {
//             // insert the signal if legal
//             let mut task_ref = task.get_inner();
//             if task_ref.signals.contains(flag) {
//                 return -1;
//             }
//             task_ref.signals.insert(flag);
//             0
//         } else {
//             -1
//         }
//     } else {
//         -1
//     }
// }
// pub fn kill_current(signum: i32) -> isize {
//     if let Some(task) = current_task() {
//         if let Some(flag) = SignalFlags::from_bits(1 << signum) {
//             // insert the signal if legal
//             let mut task_ref = task.get_inner();
//             if task_ref.signals.contains(flag) {
//                 return -1;
//             }
//             task_ref.signals.insert(flag);
//             0
//         } else {
//             -1
//         }
//     } else {
//         -1
//     }
// }

// fn check_pending_signals() {
//     for sig in 0..(MAX_SIG + 1) {
//         let task = current_task().unwrap();
//         let task_inner = task.get_inner();
//         let signal = SignalFlags::from_bits(1 << sig).unwrap();
//         // 如果当前📶 进入 等候区间,并且 没有被mask
//         if task_inner.signals.contains(signal) && (!task_inner.signal_mask.contains(signal)) {
//             let mut masked = true;
//             let handling_sig = task_inner.handling_signal;
//             // 已经在处理了,那么 不进行信号处理
//             if handling_sig == -1 {
//                 masked = false;
//             } else {
//                 // 没有在处理,但是 没有handler
//                 let handling_sig = handling_sig as usize;
//                 if !task_inner.signal_actions.table[handling_sig]
//                     .mask
//                     .contains(signal)
//                 {
//                     masked = false;
//                 }
//             }
//             if !masked {
//                 drop(task_inner);
//                 drop(task);
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
// // check if there is siganl to solve .
// // if so it will change the ret addr to the signal handler
// // if have pending signal ,it will suspend
// pub fn handle_signals() {
//     loop {
//         // in the below function , it will change the sepc address to the signal
//         // (if possible )
//         check_pending_signals();
//         let (frozen, killed) = {
//             let task = current_task().unwrap();
//             let task_inner = task.get_inner();
//             (task_inner.frozen, task_inner.killed)
//         };
//         // if not frozen or killed , then break
//         if !frozen || killed {
//             break;
//         }
//         suspend_current_and_run_next();
//     }
// }

// // os/src/task/mod.rs

// fn call_kernel_signal_handler(signal: SignalFlags) {
//     let task = current_task().unwrap();
//     let mut task_inner = task.get_inner();
//     match signal {
//         SignalFlags::SIGSTOP => {
//             task_inner.frozen = true;
//             task_inner.signals ^= SignalFlags::SIGSTOP;
//         }
//         SignalFlags::SIGCONT => {
//             if task_inner.signals.contains(SignalFlags::SIGCONT) {
//                 task_inner.signals ^= SignalFlags::SIGCONT;
//                 task_inner.frozen = false;
//             }
//         }
//         _ => {
//             // println!(
//             //     "[K] call_kernel_signal_handler:: current task sigflag {:?}",
//             //     task_inner.signals
//             // );
//             task_inner.killed = true;
//         }
//     }
// }

// fn call_user_signal_handler(sig: usize, signal: SignalFlags) {
//     let task = current_task().unwrap();
//     let mut task_inner = task.get_inner();

//     let handler = task_inner.signal_actions.table[sig].handler;
//     if handler != 0 {
//         // user handler

//         // handle flag
//         task_inner.handling_signal = sig as isize;
//         // remove the siganl ..
//         task_inner.signals ^= signal;

//         // backup trapframe
//         let mut trap_ctx = task.get_inner().trap_context_loc.get_mut() as &mut TrapContext;
//         task_inner.trap_ctx_backup = Some(*trap_ctx);

//         // modify trapframe
//         trap_ctx.sepc = handler;

//         // put args (a0)
//         trap_ctx.x[10] = sig;
//     } else {
//         // default action
//         println!("[K] task/call_user_signal_handler: default action: ignore it or kill process");
//     }
// }

// pub fn sigreturn() -> isize {
//     if let Some(task) = current_task() {
//         let mut inner = task.get_inner();
//         inner.handling_signal = -1;
//         // restore the trap context
//         let trap_ctx = inner.trap_context_loc.get_mut() as &mut TrapContext;
//         *trap_ctx = inner.trap_ctx_backup.unwrap();
//         trap_ctx.x[10] as isize
//     } else {
//         -1
//     }
// }
