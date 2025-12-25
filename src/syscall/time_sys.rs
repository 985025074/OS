use crate::{
    config::CLOCK_FREQ,
    mm::translated_mutref,
    syscall::thread,
    time::get_time,
    trap::get_current_token,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    sec: u64,
    usec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Tms {
    tms_utime: i64,
    tms_stime: i64,
    tms_cutime: i64,
    tms_cstime: i64,
}

pub fn syscall_gettimeofday(tv_ptr: usize, _tz: usize) -> isize {
    if tv_ptr == 0 {
        return 0;
    }
    let ticks = get_time() as u64;
    let us = ticks.saturating_mul(1_000_000) / CLOCK_FREQ as u64;
    let tv = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let token = get_current_token();
    *translated_mutref(token, tv_ptr as *mut TimeVal) = tv;
    0
}

pub fn syscall_nanosleep(req_ptr: usize, _rem_ptr: usize) -> isize {
    if req_ptr == 0 {
        return -1;
    }
    let token = get_current_token();
    let ts = *translated_mutref(token, req_ptr as *mut TimeSpec);
    if ts.sec < 0 || ts.nsec < 0 {
        return -1;
    }
    let ms = (ts.sec as usize)
        .saturating_mul(1000)
        .saturating_add((ts.nsec as usize) / 1_000_000);
    thread::sys_sleep(ms)
}

pub fn syscall_clock_gettime(_clk_id: usize, tp_ptr: usize) -> isize {
    if tp_ptr == 0 {
        return -1;
    }
    let ticks = get_time() as u64;
    let ns = ticks.saturating_mul(1_000_000_000) / CLOCK_FREQ as u64;
    let ts = TimeSpec {
        sec: (ns / 1_000_000_000) as i64,
        nsec: (ns % 1_000_000_000) as i64,
    };
    let token = get_current_token();
    *translated_mutref(token, tp_ptr as *mut TimeSpec) = ts;
    0
}

/// Linux `clock_nanosleep` (syscall 115 on riscv64).
///
/// rt-tests (cyclictest) uses this for periodic sleeps (often with TIMER_ABSTIME).
pub fn syscall_clock_nanosleep(_clk_id: usize, flags: usize, req_ptr: usize, rem_ptr: usize) -> isize {
    const TIMER_ABSTIME: usize = 1;
    if req_ptr == 0 {
        return -1;
    }
    // We only provide coarse sleeping based on the existing `sys_sleep(ms)` path.
    if (flags & TIMER_ABSTIME) == 0 {
        return syscall_nanosleep(req_ptr, rem_ptr);
    }
    let token = get_current_token();
    let ts = *translated_mutref(token, req_ptr as *mut TimeSpec);
    if ts.sec < 0 || ts.nsec < 0 {
        return -1;
    }
    let target_ns: u64 = (ts.sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.nsec as u64);
    let ticks = get_time() as u64;
    let now_ns = ticks.saturating_mul(1_000_000_000) / CLOCK_FREQ as u64;
    if target_ns <= now_ns {
        return 0;
    }
    let delta_ns = target_ns - now_ns;
    let ms = (delta_ns / 1_000_000) as usize;
    thread::sys_sleep(ms)
}

pub fn syscall_times(tms_ptr: usize) -> isize {
    if tms_ptr != 0 {
        let token = get_current_token();
        *translated_mutref(token, tms_ptr as *mut Tms) = Tms {
            tms_utime: 0,
            tms_stime: 0,
            tms_cutime: 0,
            tms_cstime: 0,
        };
    }
    crate::time::get_time_ms() as isize
}
