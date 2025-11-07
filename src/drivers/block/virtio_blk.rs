use super::BlockDevice;
use crate::{
    mm::{
        FrameTracker, PageTable, PhysAddr, PhysPageNum, VirtAddr, frame_alloc, frame_dealloc,
        kernel_token,
    },
    println,
    utils::RefCellSafe,
};
use alloc::vec::Vec;
use lazy_static::*;
use virtio_drivers::{Hal, VirtIOBlk, VirtIOHeader};

#[allow(unused)]
const VIRTIO0: usize = 0x10001000;

pub struct VirtIOBlock(RefCellSafe<VirtIOBlk<'static, VirtioHal>>);

lazy_static! {
    static ref QUEUE_FRAMES: RefCellSafe<Vec<FrameTracker>> =
        unsafe { RefCellSafe::new(Vec::new()) };
}

impl BlockDevice for VirtIOBlock {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        self.0
            .borrow_mut()
            .read_block(block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }
    fn write_block(&self, block_id: usize, buf: &[u8]) {
        self.0
            .borrow_mut()
            .write_block(block_id, buf)
            .expect("Error when writing VirtIOBlk");
    }
}
#[repr(C)]
pub struct TestHeader {
    pub magic: u32,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
    pub device_features: u32,
    _reserved1: [u8; 8],
    pub driver_features: u32,
    _reserved2: [u8; 12],
    pub queue_num_max: u16,
    _reserved3: [u8; 0x44 - 0x36],
    pub queue_ready: u16,
    _reserved4: [u8; 0x60 - 0x46],
    pub status: u8,
}

impl VirtIOBlock {
    #[allow(unused)]
    pub fn new() -> Self {
        let test_header = unsafe { &*(VIRTIO0 as *const TestHeader) };
        // println!(
        //     "[VirtIO DEBUG] Header info:\n  magic={:#x}\n  version={}\n  device_id={:#x}\n  vendor_id={:#x}\n  device_features={:#x}\n  driver_features={:#x}\n  queue_num_max={}\n  queue_ready={}\n  status={:#x}",
        //     test_header.magic,
        //     test_header.version,
        //     test_header.device_id,
        //     test_header.vendor_id,
        //     test_header.device_features,
        //     test_header.driver_features,
        //     test_header.queue_num_max,
        //     test_header.queue_ready,
        //     test_header.status,
        // );

        let result = unsafe {
            // Try to initialize the underlying virtio block driver and
            // print a helpful error if it fails instead of panicking silently
            // via unwrap(). This gives clearer diagnostics when init fails.
            let inner = match VirtIOBlk::<VirtioHal>::new(&mut *(VIRTIO0 as *mut VirtIOHeader)) {
                Ok(dev) => dev,
                Err(e) => {
                    println!("[VirtIO ERROR] VirtIOBlk::new failed: {:?}", e);
                    panic!("VirtIOBlk initialization failed");
                }
            };
            Self(RefCellSafe::new(inner))
        };
        println!("VirtIOBlock initialized.");
        result
    }
}

pub struct VirtioHal;

impl Hal for VirtioHal {
    fn dma_alloc(pages: usize) -> usize {
        let mut ppn_base = PhysPageNum(0);
        for i in 0..pages {
            let frame = frame_alloc().unwrap();
            if i == 0 {
                ppn_base = frame.ppn;
            }
            assert_eq!(frame.ppn.0, ppn_base.0 + i);
            QUEUE_FRAMES.borrow_mut().push(frame);
        }
        let pa: PhysAddr = ppn_base.into();
        pa.0
    }

    fn dma_dealloc(pa: usize, pages: usize) -> i32 {
        let pa = PhysAddr::from(pa);
        let mut ppn_base: PhysPageNum = pa.into();
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            ppn_base.0 += 1;
        }
        0
    }

    fn phys_to_virt(addr: usize) -> usize {
        addr
    }

    fn virt_to_phys(vaddr: usize) -> usize {
        PageTable::from_token(kernel_token())
            .translate_va(VirtAddr::from(vaddr))
            .unwrap()
            .0
    }
}
