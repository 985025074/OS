use alloc::sync::{Arc, Weak};
use spin::Mutex;

use crate::{fs::File, mm::UserBuffer, task::processor::suspend_current_and_run_next};

// A small pipe buffer makes typical shell pipelines (busybox/ash, rt-tests) extremely
// slow and can even deadlock if producers/consumers don't run concurrently.
const RING_BUFFER_SIZE: usize = 4096;
//  Pipe 是一个包装器,包装 具体的 队列
pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<Mutex<PipeRingBuffer>>,
}

impl Pipe {
    pub fn read_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
        }
    }
    pub fn write_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
        }
    }

    pub fn poll_readable(&self) -> bool {
        if !self.readable {
            return false;
        }
        let ring = self.buffer.lock();
        ring.available_read() > 0 || ring.all_write_ends_closed()
    }

    pub fn poll_writable(&self) -> bool {
        if !self.writable {
            return false;
        }
        let ring = self.buffer.lock();
        ring.available_write() > 0 || ring.all_read_ends_closed()
    }
}
#[derive(Copy, Clone, PartialEq)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    arr: [u8; RING_BUFFER_SIZE],
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    read_end: Option<Weak<Pipe>>,
    write_end: Option<Weak<Pipe>>,
}

impl PipeRingBuffer {
    pub fn new() -> Self {
        Self {
            arr: [0; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            read_end: None,
            write_end: None,
        }
    }

    /// 设置内部参数
    pub fn set_read_end(&mut self, read_end: &Arc<Pipe>) {
        self.read_end = Some(Arc::downgrade(read_end));
    }
    pub fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }
    /// 环状队列 读取字节
    pub fn read_byte(&mut self) -> u8 {
        self.status = RingBufferStatus::NORMAL;
        let c = self.arr[self.head];
        self.head = (self.head + 1) % RING_BUFFER_SIZE;
        if self.head == self.tail {
            self.status = RingBufferStatus::EMPTY;
        }
        c
    }
    pub fn write_byte(&mut self, byte: u8) {
        self.status = RingBufferStatus::NORMAL;
        self.arr[self.tail] = byte;
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        if self.tail == self.head {
            self.status = RingBufferStatus::FULL;
        }
    }
    //. 队列是否有可读字节
    pub fn available_read(&self) -> usize {
        if self.status == RingBufferStatus::EMPTY {
            0
        } else {
            if self.tail > self.head {
                self.tail - self.head
            } else {
                self.tail + RING_BUFFER_SIZE - self.head
            }
        }
    }
    pub fn available_write(&self) -> usize {
        if self.status == RingBufferStatus::FULL {
            0
        } else {
            RING_BUFFER_SIZE - self.available_read()
        }
    }
    /// 通过weak Ptr 判断是否所有写端都关闭
    pub fn all_write_ends_closed(&self) -> bool {
        self.write_end.as_ref().unwrap().upgrade().is_none()
    }

    /// 通过weak Ptr 判断是否所有读端都关闭
    pub fn all_read_ends_closed(&self) -> bool {
        self.read_end.as_ref().unwrap().upgrade().is_none()
    }
}

/// Return (read_end, write_end)
pub fn make_pipe() -> (Arc<Pipe>, Arc<Pipe>) {
    let buffer = Arc::new(Mutex::new(PipeRingBuffer::new()));
    let read_end = Arc::new(Pipe::read_end_with_buffer(buffer.clone()));
    let write_end = Arc::new(Pipe::write_end_with_buffer(buffer.clone()));
    {
        let mut inner = buffer.lock();
        inner.set_read_end(&read_end);
        inner.set_write_end(&write_end);
    }
    (read_end, write_end)
}

impl File for Pipe {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn read(&self, buf: UserBuffer) -> usize {
        assert!(self.readable());
        let want_to_read = buf.len();
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail == 0 {
                if ring_buffer.all_write_ends_closed() {
                    return 0;
                }
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            // Read at most what's currently available; for pipes, returning a
            // short read is normal once some data is obtained.
            let mut buf_iter = buf.into_iter();
            let mut read_now = 0usize;
            let to_read = core::cmp::min(avail, want_to_read);
            for _ in 0..to_read {
                let Some(byte_ref) = buf_iter.next() else {
                    break;
                };
                unsafe {
                    *byte_ref = ring_buffer.read_byte();
                }
                read_now += 1;
            }
            return read_now;
        }
    }
    fn write(&self, buf: UserBuffer) -> usize {
        assert!(self.writable());
        let want_to_write = buf.len();
        let mut buf_iter = buf.into_iter();
        let mut already_write = 0usize;
        loop {
            let mut ring_buffer = self.buffer.lock();
            let loop_write = ring_buffer.available_write();
            if loop_write == 0 {
                if ring_buffer.all_read_ends_closed() {
                    return already_write;
                }
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            // write at most loop_write bytes
            for _ in 0..loop_write {
                if let Some(byte_ref) = buf_iter.next() {
                    unsafe {
                        ring_buffer.write_byte(*byte_ref);
                    }
                    already_write += 1;
                    if already_write == want_to_write {
                        return want_to_write;
                    }
                } else {
                    return already_write;
                }
            }
        }
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
