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
    let tv = *translated_mutref(token, req_ptr as *mut TimeVal);
    let ms = (tv.sec as usize)
        .saturating_mul(1000)
        .saturating_add((tv.usec as usize) / 1000);
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
