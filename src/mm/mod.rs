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

pub use address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use address::{StepByOne, VPNRange};
pub use frame_allocator::{FrameTracker, frame_alloc};
pub use memory_set::remap_test;
pub use memory_set::{KERNEL_SPACE, MapPermission, MemorySet};
use page_table::{PTEFlags, PageTable};
pub use page_table::{PageTableEntry, translated_byte_buffer};

use crate::println;

/// initiate heap allocator, frame allocator and kernel space
pub fn init() {
    heap_allocator::init_heap();
    println!("[kernel] heap initialized.");
    frame_allocator::init_frame_allocator();
    println!("[kernel] frame allocator initialized.");
    KERNEL_SPACE.borrow_mut().activate();
    println!("[kernel] kernel space activated.");
}
