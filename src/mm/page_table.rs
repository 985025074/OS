//! Implementation of [`PageTableEntry`] and [`PageTable`].

use crate::{config::PAGE_SIZE, mm::PhysAddr};

use super::{FrameTracker, MapPermission, PhysPageNum, StepByOne, VirtAddr, VirtPageNum, frame_alloc};
use crate::task::processor::current_task;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;
use core::{cmp::min, mem::MaybeUninit};

bitflags! {
    /// page table entry flags
    pub struct PTEFlags: u16 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
        /// Software-managed copy-on-write marker (Sv39 PTE RSW bit 0).
        const COW = 1 << 8;
        /// Software-managed shared mapping marker (Sv39 PTE RSW bit 1).
        ///
        /// Used to preserve System V shared memory mappings across `fork()`.
        const SHARED = 1 << 9;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
/// page table entry structure
pub struct PageTableEntry {
    pub bits: usize,
}

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        }
    }
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    pub fn flags(&self) -> PTEFlags {
        // Low 10 bits are flags (including the 2 software RSW bits).
        PTEFlags::from_bits((self.bits & 0x3ff) as u16).unwrap()
    }
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    pub fn readable(&self) -> bool {
        (self.flags() & PTEFlags::R) != PTEFlags::empty()
    }
    pub fn writable(&self) -> bool {
        (self.flags() & PTEFlags::W) != PTEFlags::empty()
    }
    pub fn executable(&self) -> bool {
        (self.flags() & PTEFlags::X) != PTEFlags::empty()
    }
}

/// page table structure
pub struct PageTable {
    root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

/// Assume that it won't oom when creating/mapping.
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    /// Temporarily used to get arguments from user space.
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1usize << 44) - 1)),
            frames: Vec::new(),
        }
    }
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }
    /// v is added inside.
    #[allow(unused)]
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
    }

    /// Unmap an existing leaf PTE if it is present and valid.
    ///
    /// Returns `true` if an entry was unmapped.
    pub fn unmap_if_mapped(&mut self, vpn: VirtPageNum) -> bool {
        let Some(pte) = self.find_pte(vpn) else {
            return false;
        };
        if !pte.is_valid() {
            return false;
        }
        *pte = PageTableEntry::empty();
        true
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).map(|pte| *pte)
    }

    /// Update an existing leaf PTE's flags, preserving its mapped PPN.
    ///
    /// Returns `false` if the vpn is not mapped.
    pub fn set_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        let Some(pte) = self.find_pte(vpn) else {
            return false;
        };
        if !pte.is_valid() {
            return false;
        }
        let ppn = pte.ppn();
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        true
    }

    /// Update an existing leaf PTE's mapped PPN and flags.
    ///
    /// Returns `false` if the vpn is not mapped.
    pub fn remap(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) -> bool {
        let Some(pte) = self.find_pte(vpn) else {
            return false;
        };
        if !pte.is_valid() {
            return false;
        }
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        true
    }
    /// Translate `VirtAddr` to `PhysAddr`
    pub fn translate_va(&self, va: VirtAddr) -> Option<PhysAddr> {
        self.find_pte(va.clone().floor()).map(|pte| {
            let aligned_pa: PhysAddr = pte.ppn().into();
            let offset = va.page_offset();
            let aligned_pa_usize: usize = aligned_pa.into();
            (aligned_pa_usize + offset).into()
        })
    }
    pub fn token(&self) -> usize {
        8usize << 60 | self.root_ppn.0
    }
    pub fn clone(&self) -> Self {
        //todo:alloc new frames...
        return Self {
            root_ppn: self.root_ppn,
            frames: Vec::new(),
        };
    }
}

fn try_resolve_lazy_page(token: usize, va: usize, access: MapPermission) -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let Some(process) = task.process.upgrade() else {
        return false;
    };
    let Some(mut inner) = process.try_borrow_mut() else {
        return false;
    };
    if token != inner.memory_set.token() {
        return false;
    }
    inner.memory_set.resolve_lazy_fault(va, access)
}

fn translated_address_with(token: usize, ptr: *const u8, access: MapPermission) -> &'static mut u8 {
    let page_table = PageTable::from_token(token);
    let va = VirtAddr::from(ptr as usize);
    let vpn = va.floor();
    let pte = match page_table.translate(vpn) {
        Some(pte) if pte.is_valid() => pte,
        _ => {
            if try_resolve_lazy_page(token, ptr as usize, access) {
                page_table.translate(vpn).unwrap()
            } else {
                page_table.translate(vpn).unwrap()
            }
        }
    };
    let ppn = pte.ppn();
    &mut ppn.get_bytes_array()[va.page_offset()]
}

/// Load a string from other address spaces into kernel space without an end `\0`.
pub fn translated_str(token: usize, ptr: *const u8) -> String {
    let page_table = PageTable::from_token(token);
    let mut string = String::new();
    let mut va = ptr as usize;
    loop {
        let ch: u8 = *(page_table
            .translate_va(VirtAddr::from(va))
            .unwrap()
            .get_mut());
        if ch == 0 {
            break;
        }
        string.push(ch as char);
        va += 1;
    }
    string
}
pub fn translated_mutref<T>(token: usize, ptr: *mut T) -> &'static mut T {
    let real_addr = translated_address_with(token, ptr as *const u8, MapPermission::W);
    unsafe { &mut *(real_addr as *mut u8 as *mut T) }
}

/// Copy bytes from user space into a kernel buffer.
///
/// Panics if any user page in the range is unmapped.
pub fn copy_from_user(token: usize, src: *const u8, dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    let page_table = PageTable::from_token(token);
    let mut start = src as usize;
    let end = start + dst.len();
    let mut written = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let vpn = start_va.floor();
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => {
                if try_resolve_lazy_page(token, start, MapPermission::R) {
                    page_table.translate(vpn).unwrap()
                } else {
                    page_table.translate(vpn).unwrap()
                }
            }
        };
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        unsafe {
            core::ptr::copy_nonoverlapping(
                (pa.0 + page_off) as *const u8,
                dst.as_mut_ptr().add(written),
                n,
            );
        }
        start += n;
        written += n;
    }
}

/// Copy bytes from user space into a kernel buffer.
///
/// Returns `Err(())` if any user page in the range is unmapped.
pub fn try_copy_from_user(token: usize, src: *const u8, dst: &mut [u8]) -> Result<(), ()> {
    if dst.is_empty() {
        return Ok(());
    }
    let page_table = PageTable::from_token(token);
    let mut start = src as usize;
    let end = start.checked_add(dst.len()).ok_or(())?;
    let mut written = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let vpn = start_va.floor();
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => {
                if try_resolve_lazy_page(token, start, MapPermission::R) {
                    match page_table.translate(vpn) {
                        Some(pte) if pte.is_valid() => pte,
                        _ => return Err(()),
                    }
                } else {
                    return Err(());
                }
            }
        };
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        unsafe {
            core::ptr::copy_nonoverlapping(
                (pa.0 + page_off) as *const u8,
                dst.as_mut_ptr().add(written),
                n,
            );
        }
        start += n;
        written += n;
    }
    Ok(())
}

/// Copy bytes from a kernel buffer into user space.
///
/// Panics if any user page in the range is unmapped.
pub fn copy_to_user(token: usize, dst: *mut u8, src: &[u8]) {
    if src.is_empty() {
        return;
    }
    let page_table = PageTable::from_token(token);
    let mut start = dst as usize;
    let end = start + src.len();
    let mut read = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let vpn = start_va.floor();
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => {
                if try_resolve_lazy_page(token, start, MapPermission::W) {
                    page_table.translate(vpn).unwrap()
                } else {
                    page_table.translate(vpn).unwrap()
                }
            }
        };
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(read),
                (pa.0 + page_off) as *mut u8,
                n,
            );
        }
        start += n;
        read += n;
    }
}

/// Copy bytes from a kernel buffer into user space.
///
/// Returns `Err(())` if any user page in the range is unmapped.
pub fn try_copy_to_user(token: usize, dst: *mut u8, src: &[u8]) -> Result<(), ()> {
    if src.is_empty() {
        return Ok(());
    }
    let page_table = PageTable::from_token(token);
    let mut start = dst as usize;
    let end = start.checked_add(src.len()).ok_or(())?;
    let mut read = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let vpn = start_va.floor();
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => {
                if try_resolve_lazy_page(token, start, MapPermission::W) {
                    match page_table.translate(vpn) {
                        Some(pte) if pte.is_valid() => pte,
                        _ => return Err(()),
                    }
                } else {
                    return Err(());
                }
            }
        };
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(read),
                (pa.0 + page_off) as *mut u8,
                n,
            );
        }
        start += n;
        read += n;
    }
    Ok(())
}

pub fn read_user_value<T: Copy>(token: usize, src: *const T) -> T {
    let mut value = MaybeUninit::<T>::uninit();
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    copy_from_user(token, src as *const u8, dst_bytes);
    unsafe { value.assume_init() }
}

pub fn try_read_user_value<T: Copy>(token: usize, src: *const T) -> Option<T> {
    let mut value = MaybeUninit::<T>::uninit();
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    if try_copy_from_user(token, src as *const u8, dst_bytes).is_err() {
        return None;
    }
    Some(unsafe { value.assume_init() })
}

pub fn write_user_value<T: Copy>(token: usize, dst: *mut T, value: &T) {
    let src_bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    copy_to_user(token, dst as *mut u8, src_bytes);
}

pub fn try_write_user_value<T: Copy>(token: usize, dst: *mut T, value: &T) -> Result<(), ()> {
    let src_bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    try_copy_to_user(token, dst as *mut u8, src_bytes)
}
/// translate a single pointer
pub fn translated_single_address(token: usize, ptr: *const u8) -> &'static mut u8 {
    translated_address_with(token, ptr, MapPermission::R)
}
/// translate a pointer to a mutable u8 Vec through page table
pub fn translated_byte_buffer(token: usize, ptr: *const u8, len: usize) -> Vec<&'static mut [u8]> {
    let page_table = PageTable::from_token(token);
    let mut start = ptr as usize;
    let end = start + len;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => {
                if !try_resolve_lazy_page(token, start, MapPermission::W) {
                    let _ = try_resolve_lazy_page(token, start, MapPermission::R);
                }
                page_table.translate(vpn).unwrap()
            }
        };
        let ppn = pte.ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    v
}
