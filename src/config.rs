//! Constants used in rCore

// Linux userland (busybox/glibc) expects a large initial stack.
pub const USER_STACK_SIZE: usize = 4096 * 256; // 1 MiB
pub const KERNEL_STACK_SIZE: usize = 4096 * 16;  // Increased from 4 to 16 pages (64KB)
// Kernel heap must be large enough to buffer big user ELFs (e.g. glibc tests).
pub const KERNEL_HEAP_SIZE: usize = 0x200_0000; // 32 MiB
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
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
pub const MEMORY_END: usize = 0xA000_0000;

pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machine
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
];

pub const TRAP_CONTEXT_BASE: usize = TRAMPOLINE - PAGE_SIZE;
