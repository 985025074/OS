//! Constants used in rCore

use core::sync::atomic::{AtomicUsize, Ordering};

// Linux userland (busybox/glibc) expects a large initial stack.
pub const USER_STACK_SIZE: usize = 4096 * 256; // 1 MiB
pub const KERNEL_STACK_SIZE: usize = 4096 * 8;  // 32KB
// Kernel heap must be large enough to buffer big user ELFs and pthread-heavy glibc benches.
pub const KERNEL_HEAP_SIZE: usize = 0x400_0000; // 64 MiB
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
/// User-accessible sigreturn trampoline page (separate from kernel trap trampoline).
pub const SIGRETURN_TRAMPOLINE: usize = TRAMPOLINE - PAGE_SIZE;
pub const TRAP_CONTEXT: usize = SIGRETURN_TRAMPOLINE - PAGE_SIZE;
pub const MAX_HARTS: usize = 4;
pub const KERNEL_ENTRY_PA: usize = 0x8020_0000;
/// Return (bottom, top) of a kernel stack in kernel space. Bottom is smaller while top is bigger.
/// and we use top - xx to push data...
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    let top = TRAMPOLINE - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

pub const CLOCK_FREQ: usize = 12500000;

// QEMU virt RAM starts at 0x8000_0000. Default to 512MiB to match common `-m 512M`.
pub const DEFAULT_MEMORY_START: usize = 0x8000_0000;
pub const DEFAULT_MEMORY_END: usize = 0xA000_0000;

static PHYS_MEM_START: AtomicUsize = AtomicUsize::new(DEFAULT_MEMORY_START);
static PHYS_MEM_END: AtomicUsize = AtomicUsize::new(DEFAULT_MEMORY_END);

pub fn set_phys_mem_range(start: usize, end: usize) {
    if end > start {
        PHYS_MEM_START.store(start, Ordering::SeqCst);
        PHYS_MEM_END.store(end, Ordering::SeqCst);
    }
}

pub fn phys_mem_start() -> usize {
    PHYS_MEM_START.load(Ordering::SeqCst)
}

pub fn phys_mem_end() -> usize {
    PHYS_MEM_END.load(Ordering::SeqCst)
}

pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machine
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
    (0x1000_2000, 0x00_1000), // Virtio Block (bus 1) in virt machine
];

pub const TRAP_CONTEXT_BASE: usize = TRAP_CONTEXT;
