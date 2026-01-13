use crate::{
    mm::{
        FrameTracker, PageTable, PhysAddr, PhysPageNum, VirtAddr, frame_alloc,
        frame_alloc_contiguous, frame_dealloc, kernel_token,
    },
    println,
};
use alloc::vec::Vec;
use ext4_fs::BlockDevice;
use lazy_static::*;
use spin::Mutex;
use virtio_drivers::{Hal, VirtIOBlk, VirtIOHeader};

#[allow(unused)]
const VIRTIO0: usize = 0x10001000;
#[allow(unused)]
const VIRTIO1: usize = 0x10002000;
const VIRTIO_MMIO_MAGIC: u32 = 0x74726976;
const VIRTIO_DEVICE_BLOCK: u32 = 2;

struct VirtIOBlockInner {
    blk: VirtIOBlk<'static, VirtioHal>,
    bounce: FrameTracker,
}

pub struct VirtIOBlock(Mutex<VirtIOBlockInner>);

lazy_static! {
    static ref QUEUE_FRAMES: Mutex<Vec<FrameTracker>> = Mutex::new(Vec::new());
}

impl BlockDevice for VirtIOBlock {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        assert_eq!(buf.len() % 512, 0, "read_block buf must be 512B-aligned size");
        let sectors_per_block = buf.len() / 512;
        let base_sector = block_id * sectors_per_block;

        // VirtIO DMA requires physically-contiguous buffers. A `&mut [u8]` coming from the heap
        // may cross pages and thus not be contiguous in physical memory even if it is contiguous
        // in virtual memory. Use a 4KiB bounce page and copy each 512B sector.
        //
        // Note: our vendored `virtio-drivers` supports multi-sector reads/writes by allowing
        // `buf.len()` to be any multiple of 512.
        let mut inner = self.0.lock();
        let VirtIOBlockInner { blk, bounce } = &mut *inner;
        let bounce_bytes = bounce.ppn.get_bytes_array();
        const MAX_CHUNK_BYTES: usize = 4096;
        const SECTOR_BYTES: usize = 512;
        const MAX_CHUNK_SECTORS: usize = MAX_CHUNK_BYTES / SECTOR_BYTES;

        let mut done = 0usize;
        while done < sectors_per_block {
            let chunk = core::cmp::min(sectors_per_block - done, MAX_CHUNK_SECTORS);
            let chunk_bytes = chunk * SECTOR_BYTES;
            blk.read_block(base_sector + done, &mut bounce_bytes[..chunk_bytes])
                .expect("Error when reading VirtIOBlk");
            let dst_off = done * SECTOR_BYTES;
            buf[dst_off..dst_off + chunk_bytes].copy_from_slice(&bounce_bytes[..chunk_bytes]);
            done += chunk;
        }
    }
    fn write_block(&self, block_id: usize, buf: &[u8]) {
        assert_eq!(buf.len() % 512, 0, "write_block buf must be 512B-aligned size");
        let sectors_per_block = buf.len() / 512;
        let base_sector = block_id * sectors_per_block;

        let mut inner = self.0.lock();
        let VirtIOBlockInner { blk, bounce } = &mut *inner;
        let bounce_bytes = bounce.ppn.get_bytes_array();
        const MAX_CHUNK_BYTES: usize = 4096;
        const SECTOR_BYTES: usize = 512;
        const MAX_CHUNK_SECTORS: usize = MAX_CHUNK_BYTES / SECTOR_BYTES;

        let mut done = 0usize;
        while done < sectors_per_block {
            let chunk = core::cmp::min(sectors_per_block - done, MAX_CHUNK_SECTORS);
            let chunk_bytes = chunk * SECTOR_BYTES;
            let src_off = done * SECTOR_BYTES;
            bounce_bytes[..chunk_bytes].copy_from_slice(&buf[src_off..src_off + chunk_bytes]);
            blk.write_block(base_sector + done, &bounce_bytes[..chunk_bytes])
                .expect("Error when writing VirtIOBlk");
            done += chunk;
        }
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
        Self::try_new_with_base(VIRTIO0).expect("VirtIO block device not found")
    }

    pub fn try_new_with_base(base: usize) -> Option<Self> {
        let test_header = unsafe { &*(base as *const TestHeader) };
        if test_header.magic != VIRTIO_MMIO_MAGIC || test_header.device_id != VIRTIO_DEVICE_BLOCK {
            return None;
        }
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
            let blk = match VirtIOBlk::<VirtioHal>::new(&mut *(base as *mut VirtIOHeader)) {
                Ok(dev) => dev,
                Err(e) => {
                    println!("[VirtIO ERROR] VirtIOBlk::new failed: {:?}", e);
                    return None;
                }
            };
            let bounce = frame_alloc()?;
            Some(Self(Mutex::new(VirtIOBlockInner { blk, bounce })))
        };
        if result.is_some() {
            println!("VirtIOBlock initialized at {:#x}.", base);
        }
        result
    }

    #[allow(unused)]
    pub fn try_new_second() -> Option<Self> {
        Self::try_new_with_base(VIRTIO1)
    }
}

pub struct VirtioHal;

impl Hal for VirtioHal {
    fn dma_alloc(pages: usize) -> usize {
        let frames = frame_alloc_contiguous(pages).expect("VirtIOBlock: OOM for queue pages");
        let ppn_base = frames[0].ppn;
        for frame in frames {
            // The virtio queue layout requires the ring/descriptor memory to be zeroed.
            // virtio-drivers does not clear the DMA region on its own.
            frame.ppn.get_bytes_array().fill(0);
            QUEUE_FRAMES.lock().push(frame);
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
