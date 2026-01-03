use alloc::sync::Arc;
use core::cmp::min;
use core::arch::asm;

use crate::{
    config::PAGE_SIZE,
    fs::{File, OSInode, ext4_lock},
    mm::{MapPermission, PTEFlags, translated_mutref},
    task::processor::current_process,
    trap::get_current_token,
};

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;

// Linux `mmap(2)` flags (subset).
const MAP_FIXED: usize = 0x10;

const EINVAL: isize = -22;
const ENOMEM: isize = -12;

fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

fn get_fd_inode(fd: usize) -> Option<Arc<ext4_fs::Inode>> {
    let process = current_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return None;
    }
    let file = inner.fd_table[fd].as_ref()?.clone();
    file.as_any()
        .downcast_ref::<OSInode>()
        .map(|o| {
            // Ensure data written via buffered `write(2)` is visible to file-backed `mmap(2)`.
            // This keeps simple tests (write -> fstat -> mmap -> read) working.
            let _ = o.flush();
            o.ext4_inode()
        })
}

pub fn syscall_brk(addr: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    if addr == 0 {
        return inner.brk as isize;
    }
    if addr < inner.heap_start {
        return inner.brk as isize;
    }

    let old_brk = inner.brk;
    let new_brk = addr;
    let heap_start = inner.heap_start;
    let old_end = align_up(old_brk, PAGE_SIZE);
    let new_end = align_up(new_brk, PAGE_SIZE);
    if new_end > old_end {
        let _ = inner
            .memory_set
            .append_to(heap_start.into(), new_end.into());
    } else if new_end < old_end {
        let _ = inner
            .memory_set
            .shrink_to(heap_start.into(), new_end.into());
    }
    inner.brk = new_brk;
    inner.brk as isize
}

pub fn syscall_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: isize,
    off: usize,
) -> isize {
    if len == 0 {
        return EINVAL;
    }

    let process = current_process();
    let mut inner = process.borrow_mut();

    // A very small `mmap` implementation:
    // - only honor `addr` when `MAP_FIXED` is set;
    // - otherwise treat `addr` as a hint and allocate from `mmap_next`;
    // - never move `mmap_next` backwards (important for glibc/ld.so).
    let start = if (flags & MAP_FIXED) != 0 {
        if addr == 0 {
            return EINVAL;
        }
        align_down(addr, PAGE_SIZE)
    } else {
        align_up(inner.mmap_next, PAGE_SIZE)
    };
    let map_len = align_up(len, PAGE_SIZE);
    let Some(end) = start.checked_add(map_len) else {
        return ENOMEM;
    };

    let mut perm = MapPermission::U;
    if (prot & PROT_READ) != 0 {
        perm |= MapPermission::R;
    }
    if (prot & PROT_WRITE) != 0 {
        perm |= MapPermission::W;
    }
    if (prot & PROT_EXEC) != 0 {
        perm |= MapPermission::X;
    }

    if (flags & MAP_FIXED) != 0 {
        // Refuse to map over kernel-only pages (e.g. TrapContext/trampoline).
        let mut cur = start;
        while cur < end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                    return ENOMEM;
                }
            }
            cur += PAGE_SIZE;
        }

        // Linux MAP_FIXED replaces any existing mappings in the range.
        inner
            .memory_set
            .unmap_user_range(start.into(), end.into());

        // Keep `mmap_areas` bookkeeping consistent (split/trim overlaps).
        let mut new_areas = alloc::vec::Vec::new();
        for (s, l) in inner.mmap_areas.drain(..) {
            let e = s + l;
            if end <= s || start >= e {
                new_areas.push((s, l));
                continue;
            }
            if start > s {
                new_areas.push((s, start - s));
            }
            if end < e {
                new_areas.push((end, e - end));
            }
        }
        inner.mmap_areas = new_areas;
    }

    if !inner
        .memory_set
        .try_insert_framed_area(start.into(), end.into(), perm)
    {
        return ENOMEM;
    }
    if end > inner.mmap_next {
        inner.mmap_next = end;
    }
    inner.mmap_areas.push((start, map_len));
    drop(inner);

    // Best-effort: file-backed initial population.
    if fd >= 0 {
        if let Some(inode) = get_fd_inode(fd as usize) {
            let _ext4_guard = ext4_lock();
            let token = get_current_token();
            let mut pos = 0usize;
            let mut tmp = [0u8; 512];
            while pos < len {
                let to_read = min(tmp.len(), len - pos);
                let read = inode.read_at(off + pos, &mut tmp[..to_read]);
                if read == 0 {
                    break;
                }
                for i in 0..read {
                    *translated_mutref(token, (start + pos + i) as *mut u8) = tmp[i];
                }
                pos += read;
            }
        }
    }

    start as isize
}

pub fn syscall_munmap(addr: usize, len: usize) -> isize {
    if len == 0 {
        return EINVAL;
    }
    if addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    let start = addr;
    let Some(end) = start.checked_add(len) else {
        return EINVAL;
    };
    let end = align_up(end, PAGE_SIZE);

    inner
        .memory_set
        .unmap_user_range(start.into(), end.into());

    // Update `mmap_areas` bookkeeping: remove/split any overlapping entries.
    let mut new_areas = alloc::vec::Vec::new();
    for (s, l) in inner.mmap_areas.drain(..) {
        let e = s + l;
        if end <= s || start >= e {
            new_areas.push((s, l));
            continue;
        }
        if start > s {
            new_areas.push((s, start - s));
        }
        if end < e {
            new_areas.push((end, e - end));
        }
    }
    inner.mmap_areas = new_areas;
    0
}

/// Linux `mprotect` (syscall 226).
///
/// Many glibc programs call this during startup to set guard pages / adjust
/// permissions. We currently do not enforce per-page user permissions strictly,
/// so accept the call and return success.
pub fn syscall_mprotect(_addr: usize, _len: usize, _prot: usize) -> isize {
    if _len == 0 {
        return 0;
    }
    if _addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    let Some(end) = _addr.checked_add(_len) else {
        return EINVAL;
    };
    let start = _addr;
    let end = align_up(end, PAGE_SIZE);

    let mut new_flags = PTEFlags::U;
    if (_prot & PROT_READ) != 0 {
        new_flags |= PTEFlags::R;
    }
    if (_prot & PROT_WRITE) != 0 {
        new_flags |= PTEFlags::W;
    }
    if (_prot & PROT_EXEC) != 0 {
        new_flags |= PTEFlags::X;
    }

    let process = current_process();
    let mut inner = process.borrow_mut();
    let mut addr = start;
    while addr < end {
        let vpn = crate::mm::VirtAddr::from(addr).floor();
        let Some(pte) = inner.memory_set.translate(vpn) else {
            return ENOMEM;
        };
        if !pte.flags().contains(PTEFlags::U) {
            return ENOMEM;
        }
        let old = pte.flags();
        let mut flags = new_flags;
        // Preserve software-managed bits (RSW) so that shared/COW mappings keep their nature.
        if old.contains(PTEFlags::COW) {
            flags |= PTEFlags::COW;
        }
        if old.contains(PTEFlags::SHARED) {
            flags |= PTEFlags::SHARED;
        }
        if !inner.memory_set.set_pte_flags(vpn, flags) {
            return ENOMEM;
        }
        addr += PAGE_SIZE;
    }
    // Ensure permission changes take effect immediately.
    unsafe { asm!("sfence.vma"); }
    0
}

/// Linux `mlock` (syscall 228).
///
/// We do not implement page pinning; accept the call so rt-tests can proceed.
pub fn syscall_mlock(_addr: usize, _len: usize) -> isize {
    0
}

/// Linux `munlock` (syscall 229).
pub fn syscall_munlock(_addr: usize, _len: usize) -> isize {
    0
}

/// Linux `mlockall` (syscall 230).
pub fn syscall_mlockall(_flags: usize) -> isize {
    0
}

/// Linux `munlockall` (syscall 231).
pub fn syscall_munlockall() -> isize {
    0
}
