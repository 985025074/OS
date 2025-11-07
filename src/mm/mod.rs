//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.

mod address;
mod frame_allocator;
mod heap_allocator;
mod memory_set;
mod page_table;

use crate::println;
pub use address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use address::{StepByOne, VPNRange};
use alloc::vec::Vec;
pub use frame_allocator::{FrameTracker, frame_alloc, frame_dealloc};
pub use memory_set::kernel_token;
pub use memory_set::remap_test;
pub use memory_set::{KERNEL_SPACE, MapPermission, MemorySet};
pub use page_table::{PTEFlags, PageTable};
pub use page_table::{PageTableEntry, translated_byte_buffer, translated_single_address};
pub struct UserBuffer {
    pub buffers: Vec<&'static mut [u8]>,
}

impl UserBuffer {
    pub fn new(buffers: Vec<&'static mut [u8]>) -> Self {
        Self { buffers }
    }
    pub fn len(&self) -> usize {
        let mut total: usize = 0;
        for b in self.buffers.iter() {
            total += b.len();
        }
        total
    }
}
/// initiate heap allocator, frame allocator and kernel space
pub fn init() {
    heap_allocator::init_heap();
    println!("[kernel] heap initialized.");
    frame_allocator::init_frame_allocator();
    println!("[kernel] frame allocator initialized.");
    KERNEL_SPACE.borrow_mut().activate();
    println!("[kernel] kernel space activated.");
}
