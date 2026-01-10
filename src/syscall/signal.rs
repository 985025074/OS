use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{
    debug_config::DEBUG_PTHREAD,
    mm::{read_user_value, try_read_user_value, write_user_value},
    sbi::send_ipi,
    syscall::misc::decode_linux_tid,
    task::{
        block_sleep::add_timer,
        manager::{pid2process, wakeup_task},
        processor::{block_current_and_run_next, current_process, current_task},
        signal::{RtSigAction, SignalAction, RT_SIG_MAX, SIG_DFL, SIG_IGN, kill, set_signal, set_signal_mask},
        task_block::{SigSavedContext, TaskControlBlock},
    },
    time::get_time_ms,
    trap::get_current_token,
};
use crate::config::SIGRETURN_TRAMPOLINE;

fn sigreturn_trampoline_va() -> usize {
    unsafe extern "C" {
        fn alltraps();
        fn sigreturn_trampoline();
    }
    sigreturn_trampoline as usize - alltraps as usize + SIGRETURN_TRAMPOLINE
}

const EINVAL: isize = -22;
const EAGAIN: isize = -11;
const ESRCH: isize = -3;
const SIGCHLD: usize = 17;
const SA_SIGINFO: usize = 0x4;
const SA_NODEFER: usize = 0x40000000;

// pub fn syscall_sigreturn() -> isize {
//     sigreturn()
// }

pub fn syscall_kill(pid: usize, signum: i32) -> isize {
    kill(pid, signum)
}

/// Linux `tgkill` (syscall 131).
///
/// Delivers a signal to a specific thread (Linux-style tid encoding).
pub fn syscall_tgkill(tgid: usize, tid: usize, sig: i32) -> isize {
    if sig == 0 {
        return if pid2process(tgid).is_some() { 0 } else { ESRCH };
    }
    if DEBUG_PTHREAD {
        crate::println!("[tgkill] tgid={} tid={} sig={}", tgid, tid, sig);
    }
    let Some(tid_index) = decode_linux_tid(tgid, tid) else {
        return EINVAL;
    };
    let Some(proc) = pid2process(tgid) else {
        return ESRCH;
    };
    let task = {
        let inner = proc.borrow_mut();
        inner.tasks.get(tid_index).and_then(|t| t.as_ref()).cloned()
    };
    let Some(task) = task else {
        return ESRCH;
    };
    {
        let mut inner = task.borrow_mut();
        inner.pending_signal = Some(sig as usize);
    }
    let on_cpu = task.on_cpu.load(Ordering::Acquire);
    wakeup_task(task);
    if on_cpu != TaskControlBlock::OFF_CPU {
        send_ipi(on_cpu);
    }
    0
}

/// Linux `tkill` (syscall 130).
///
/// Delivers a signal to a specific thread in the current process.
pub fn syscall_tkill(tid: usize, sig: i32) -> isize {
    let tgid = current_process().getpid();
    syscall_tgkill(tgid, tid, sig)
}
pub fn syscall_sigaction(
    signum: i32,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> isize {
    set_signal(signum, action, old_action)
}
pub fn syscall_sigprocmask(how: u32) -> isize {
    set_signal_mask(how)
}

/// Linux `rt_sigaction` (syscall 134).
pub fn syscall_rt_sigaction(signum: usize, act: usize, oldact: usize, sigsetsize: usize) -> isize {
    let _ = sigsetsize;
    if signum == 0 || signum > RT_SIG_MAX {
        return EINVAL;
    }
    let token = get_current_token();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if oldact != 0 {
        let cur = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        write_user_value(token, oldact as *mut RtSigAction, &cur);
    }
    if act != 0 {
        let new = read_user_value(token, act as *const RtSigAction);
        if DEBUG_PTHREAD {
            crate::println!(
                "[rt_sigaction] signo={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                signum,
                new.handler,
                new.flags,
                new.restorer,
                new.mask
            );
        }
        if signum < inner.rt_sig_handlers.len() {
            inner.rt_sig_handlers[signum] = new;
        }
    }
    0
}

/// Linux `rt_sigprocmask` (syscall 135).
pub fn syscall_rt_sigprocmask(how: usize, set: usize, oldset: usize, sigsetsize: usize) -> isize {
    let token = get_current_token();
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    let _ = sigsetsize;
    if oldset != 0 {
        write_user_value(token, oldset as *mut u64, &inner.signal_mask);
    }
    if set != 0 {
        let new_mask = read_user_value(token, set as *const u64);
        if DEBUG_PTHREAD {
            crate::println!(
                "[rt_sigprocmask] how={} new_mask={:#x} old_mask={:#x}",
                how,
                new_mask,
                inner.signal_mask
            );
        }
        match how {
            0 => inner.signal_mask |= new_mask,       // SIG_BLOCK
            1 => inner.signal_mask &= !new_mask,      // SIG_UNBLOCK
            2 => inner.signal_mask = new_mask,        // SIG_SETMASK
            _ => return EINVAL,
        }
    }
    0
}

/// Linux `rt_sigreturn` (syscall 139).
pub fn syscall_rt_sigreturn() -> isize {
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    if DEBUG_PTHREAD {
        crate::println!("[rt_sigreturn] tid={}", inner.res.as_ref().map(|r| r.tid).unwrap_or(0));
    }
    if let Some(saved) = inner.sig_saved_ctx.take() {
        if saved.uses_ucontext && saved.ucontext_ptr != 0 {
            let token = get_current_token();
            let sp = inner.get_trap_cx().x[2];
            let a2 = inner.get_trap_cx().x[12];
            let uc = try_read_user_value(token, saved.ucontext_ptr as *const UContext)
                .or_else(|| try_read_user_value(token, sp as *const UContext));
            if let Some(uc) = uc {
                if DEBUG_PTHREAD && saved.signum == 33 {
                    let tp = saved.trap_cx.x[4];
                    let cancel = try_read_user_value(token, tp.wrapping_sub(156) as *const i32);
                    let canceldisable = try_read_user_value(token, tp.wrapping_sub(152) as *const u8);
                    let cancelasync = try_read_user_value(token, tp.wrapping_sub(151) as *const u8);
                    let sig_ctx = uc.uc_mcontext;
                    log::debug!(
                        "[sigcancel] ucontext ptr={:#x} sp={:#x} a2={:#x} sepc {:#x}->{:#x} a0 {:#x}->{:#x} mask {:#x}->{:#x} tp {:#x}->{:#x} flags={:?}/{:?}/{:?}",
                        saved.ucontext_ptr,
                        sp,
                        a2,
                        saved.trap_cx.sepc,
                        sig_ctx.regs.pc,
                        saved.trap_cx.x[10],
                        sig_ctx.regs.a0,
                        saved.mask,
                        uc.uc_sigmask,
                        saved.trap_cx.x[4],
                        sig_ctx.regs.tp,
                        cancel,
                        canceldisable,
                        cancelasync
                    );
                }
                let mut restored = saved.trap_cx;
                let sig_ctx = uc.uc_mcontext;
                sig_ctx.regs.write_to_trap(&mut restored);
                *inner.get_trap_cx() = restored;
                inner.signal_mask = uc.uc_sigmask;
                return restored.x[10] as isize;
            }
        }
        *inner.get_trap_cx() = saved.trap_cx;
        inner.signal_mask = saved.mask;
        return saved.trap_cx.x[10] as isize;
    }
    0
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct LinuxSigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    si_pad0: i32,
    field: [i32; 28],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SigStack {
    ss_sp: usize,
    ss_flags: i32,
    _pad: i32,
    ss_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserRegsStruct {
    pc: usize,
    ra: usize,
    sp: usize,
    gp: usize,
    tp: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    s0: usize,
    s1: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
}

impl UserRegsStruct {
    fn from_trap(cx: &crate::trap::context::TrapContext) -> Self {
        Self {
            pc: cx.sepc,
            ra: cx.x[1],
            sp: cx.x[2],
            gp: cx.x[3],
            tp: cx.x[4],
            t0: cx.x[5],
            t1: cx.x[6],
            t2: cx.x[7],
            s0: cx.x[8],
            s1: cx.x[9],
            a0: cx.x[10],
            a1: cx.x[11],
            a2: cx.x[12],
            a3: cx.x[13],
            a4: cx.x[14],
            a5: cx.x[15],
            a6: cx.x[16],
            a7: cx.x[17],
            s2: cx.x[18],
            s3: cx.x[19],
            s4: cx.x[20],
            s5: cx.x[21],
            s6: cx.x[22],
            s7: cx.x[23],
            s8: cx.x[24],
            s9: cx.x[25],
            s10: cx.x[26],
            s11: cx.x[27],
            t3: cx.x[28],
            t4: cx.x[29],
            t5: cx.x[30],
            t6: cx.x[31],
        }
    }

    fn write_to_trap(&self, cx: &mut crate::trap::context::TrapContext) {
        cx.sepc = self.pc;
        cx.x[0] = 0;
        cx.x[1] = self.ra;
        cx.x[2] = self.sp;
        cx.x[3] = self.gp;
        cx.x[4] = self.tp;
        cx.x[5] = self.t0;
        cx.x[6] = self.t1;
        cx.x[7] = self.t2;
        cx.x[8] = self.s0;
        cx.x[9] = self.s1;
        cx.x[10] = self.a0;
        cx.x[11] = self.a1;
        cx.x[12] = self.a2;
        cx.x[13] = self.a3;
        cx.x[14] = self.a4;
        cx.x[15] = self.a5;
        cx.x[16] = self.a6;
        cx.x[17] = self.a7;
        cx.x[18] = self.s2;
        cx.x[19] = self.s3;
        cx.x[20] = self.s4;
        cx.x[21] = self.s5;
        cx.x[22] = self.s6;
        cx.x[23] = self.s7;
        cx.x[24] = self.s8;
        cx.x[25] = self.s9;
        cx.x[26] = self.s10;
        cx.x[27] = self.s11;
        cx.x[28] = self.t3;
        cx.x[29] = self.t4;
        cx.x[30] = self.t5;
        cx.x[31] = self.t6;
    }
}

const RISCV_FP_STATE_SIZE: usize = 528;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct SigContext {
    regs: UserRegsStruct,
    fp_state: [u8; RISCV_FP_STATE_SIZE],
}

impl Default for SigContext {
    fn default() -> Self {
        Self {
            regs: UserRegsStruct::default(),
            fp_state: [0u8; RISCV_FP_STATE_SIZE],
        }
    }
}

const UCONTEXT_SIGSET_PAD: usize = 128 - core::mem::size_of::<u64>();

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct UContext {
    uc_flags: usize,
    uc_link: usize,
    uc_stack: SigStack,
    uc_sigmask: u64,
    __unused: [u8; UCONTEXT_SIGSET_PAD],
    uc_mcontext: SigContext,
}

impl Default for UContext {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SigStack::default(),
            uc_sigmask: 0,
            __unused: [0u8; UCONTEXT_SIGSET_PAD],
            uc_mcontext: SigContext::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

fn timespec_to_ms(ts: TimeSpec) -> Option<usize> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1_000_000_000 {
        return None;
    }
    let ms = (ts.sec as u64)
        .saturating_mul(1_000)
        .saturating_add((ts.nsec as u64) / 1_000_000);
    Some(ms.min(usize::MAX as u64) as usize)
}

fn sig_bit(sig: usize) -> Option<u64> {
    if sig == 0 || sig > 64 {
        return None;
    }
    Some(1u64 << (sig - 1))
}

fn has_zombie_child() -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    inner
        .children
        .iter()
        .any(|child| child.borrow_mut().is_zombie)
}

fn remove_waiter(task: &Arc<TaskControlBlock>) {
    let process = current_process();
    let mut inner = process.borrow_mut();
    inner.wait_queue.retain(|t| !Arc::ptr_eq(t, task));
}

/// Linux `rt_sigtimedwait` (syscall 137).
pub fn syscall_rt_sigtimedwait(set: usize, info: usize, timeout: usize, sigsetsize: usize) -> isize {
    let _ = info;
    let _ = sigsetsize;
    if set == 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let mask = read_user_value(token, set as *const u64);
    if mask == 0 {
        return EINVAL;
    }

    let sigchld_bit = sig_bit(SIGCHLD).unwrap();
    let task = current_task().unwrap();

    // Immediate pending signal.
    if let Some(sig) = task.borrow_mut().pending_signal {
        if let Some(bit) = sig_bit(sig) {
            if (mask & bit) != 0 {
                task.borrow_mut().pending_signal = None;
                return sig as isize;
            }
        }
    }

    // SIGCHLD via zombie child detection.
    if (mask & sigchld_bit) != 0 && has_zombie_child() {
        return SIGCHLD as isize;
    }

    if timeout == 0 {
        return EAGAIN;
    }

    let ts = read_user_value(token, timeout as *const TimeSpec);
    let timeout_ms = match timespec_to_ms(ts) {
        Some(ms) => ms,
        None => return EINVAL,
    };
    if timeout_ms == 0 {
        return EAGAIN;
    }
    let deadline_ms = get_time_ms().saturating_add(timeout_ms);

    let mut timer_set = false;
    loop {
        {
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.wait_queue.push_back(Arc::clone(&task));
        }
        if !timer_set {
            let now_ms = get_time_ms();
            let wait_ms = deadline_ms.saturating_sub(now_ms);
            if wait_ms == 0 {
                remove_waiter(&task);
                return EAGAIN;
            }
            add_timer(Arc::clone(&task), wait_ms);
            timer_set = true;
        }

        block_current_and_run_next();
        remove_waiter(&task);

        // Re-check pending signal.
        if let Some(sig) = task.borrow_mut().pending_signal {
            if let Some(bit) = sig_bit(sig) {
                if (mask & bit) != 0 {
                    task.borrow_mut().pending_signal = None;
                    return sig as isize;
                }
            }
        }

        if (mask & sigchld_bit) != 0 && has_zombie_child() {
            return SIGCHLD as isize;
        }
        if get_time_ms() >= deadline_ms {
            return EAGAIN;
        }
    }
}

pub fn maybe_deliver_signal() {
    let Some(task) = current_task() else {
        return;
    };
    let signum = {
        let mut inner = task.borrow_mut();
        if inner.sig_saved_ctx.is_some() {
            return;
        }
        let Some(sig) = inner.pending_signal else {
            return;
        };
        if let Some(bit) = sig_bit(sig) {
            if (inner.signal_mask & bit) != 0 {
                return;
            }
        } else {
            return;
        }
        inner.pending_signal = None;
        sig
    };
    if DEBUG_PTHREAD {
        let mask = task.borrow_mut().signal_mask;
        crate::println!("[signal] deliver sig={} mask={:#x}", signum, mask);
    }
    if DEBUG_PTHREAD && signum == 33 {
        let token = get_current_token();
        let tp = task.borrow_mut().get_trap_cx().x[4];
        let cancel = try_read_user_value(token, tp.wrapping_sub(156) as *const i32);
        let canceldisable = try_read_user_value(token, tp.wrapping_sub(152) as *const u8);
        let cancelasync = try_read_user_value(token, tp.wrapping_sub(151) as *const u8);
        log::debug!(
            "[sigcancel] tp={:#x} cancel={:?} disable={:?} async={:?}",
            tp,
            cancel,
            canceldisable,
            cancelasync
        );
    }

    let action = {
        let process = current_process();
        let inner = process.borrow_mut();
        inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default()
    };
    if DEBUG_PTHREAD {
        crate::println!(
            "[signal] action signo={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
            signum,
            action.handler,
            action.flags,
            action.restorer,
            action.mask
        );
    }
    if action.handler == SIG_DFL || action.handler == SIG_IGN {
        return;
    }

    let mut inner = task.borrow_mut();
    if inner.sig_saved_ctx.is_some() {
        return;
    }
    let cx = inner.get_trap_cx();
    let saved_mask = inner.signal_mask;
    inner.sig_saved_ctx = Some(SigSavedContext {
        trap_cx: *cx,
        mask: saved_mask,
        ucontext_ptr: 0,
        uses_ucontext: false,
        signum,
    });

    let mut new_mask = saved_mask | action.mask;
    if (action.flags & SA_NODEFER) == 0 {
        if let Some(bit) = sig_bit(signum) {
            new_mask |= bit;
        }
    }
    inner.signal_mask = new_mask;

    let mut user_sp = cx.x[2];
    let mut siginfo_ptr = 0usize;
    let mut ucontext_ptr = 0usize;
    if (action.flags & SA_SIGINFO) != 0 {
        user_sp = (user_sp.saturating_sub(15)) & !0x0f;
        user_sp = user_sp.saturating_sub(core::mem::size_of::<LinuxSigInfo>());
        siginfo_ptr = user_sp;

        user_sp = (user_sp.saturating_sub(15)) & !0x0f;
        user_sp = user_sp.saturating_sub(core::mem::size_of::<UContext>());
        ucontext_ptr = user_sp;

        let mut siginfo = LinuxSigInfo::default();
        siginfo.si_signo = signum as i32;
        siginfo.si_code = -6; // SI_TKILL
        siginfo.field[0] = current_process().getpid() as i32;
        siginfo.field[1] = 0; // uid

        let sig_context = SigContext {
            regs: UserRegsStruct::from_trap(cx),
            ..Default::default()
        };
        let ucontext = UContext {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SigStack::default(),
            uc_sigmask: saved_mask,
            uc_mcontext: sig_context,
            ..Default::default()
        };

        let token = get_current_token();
        write_user_value(token, siginfo_ptr as *mut LinuxSigInfo, &siginfo);
        write_user_value(token, ucontext_ptr as *mut UContext, &ucontext);
        if let Some(saved) = inner.sig_saved_ctx.as_mut() {
            saved.ucontext_ptr = ucontext_ptr;
            saved.uses_ucontext = true;
        }

        cx.x[11] = siginfo_ptr;
        cx.x[12] = ucontext_ptr;
        cx.x[2] = user_sp;
        if DEBUG_PTHREAD && signum == 33 {
            log::debug!(
                "[sigcancel] frame sp={:#x} siginfo={:#x} ucontext={:#x}",
                user_sp,
                siginfo_ptr,
                ucontext_ptr
            );
        }
    } else {
        cx.x[11] = 0;
        cx.x[12] = 0;
    }

    cx.sepc = action.handler;
    cx.x[10] = signum;
    // Always use the kernel-provided rt_sigreturn trampoline to avoid invalid
    // user restorer pointers causing instruction page faults.
    cx.x[1] = sigreturn_trampoline_va();
}

pub fn try_sigreturn_from_fault() -> bool {
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    let Some(saved) = inner.sig_saved_ctx.take() else {
        return false;
    };
    *inner.get_trap_cx() = saved.trap_cx;
    inner.signal_mask = saved.mask;
    true
}
