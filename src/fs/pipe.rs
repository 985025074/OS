use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::Mutex;

use crate::{
    debug_config::DEBUG_UNIXBENCH,
    fs::File,
    mm::UserBuffer,
    task::{
        manager::{wakeup_task, PID2PCB},
        processor::{block_current_and_run_next, current_task},
    },
};

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
    read_waiters: VecDeque<Arc<crate::task::task_block::TaskControlBlock>>,
    write_waiters: VecDeque<Arc<crate::task::task_block::TaskControlBlock>>,
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
            read_waiters: VecDeque::new(),
            write_waiters: VecDeque::new(),
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

    fn read_end_count(&self) -> usize {
        self.read_end
            .as_ref()
            .map(|w| w.strong_count())
            .unwrap_or(0)
    }

    fn write_end_count(&self) -> usize {
        self.write_end
            .as_ref()
            .map(|w| w.strong_count())
            .unwrap_or(0)
    }

    fn push_reader(&mut self, task: Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        if self.read_waiters.iter().any(|t| Arc::ptr_eq(t, &task)) {
            return false;
        }
        self.read_waiters.push_back(task);
        true
    }

    fn push_writer(&mut self, task: Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        if self.write_waiters.iter().any(|t| Arc::ptr_eq(t, &task)) {
            return false;
        }
        self.write_waiters.push_back(task);
        true
    }

    fn pop_reader(&mut self) -> Option<Arc<crate::task::task_block::TaskControlBlock>> {
        self.read_waiters.pop_front()
    }

    fn pop_writer(&mut self) -> Option<Arc<crate::task::task_block::TaskControlBlock>> {
        self.write_waiters.pop_front()
    }

    fn drain_readers(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.read_waiters.drain(..).collect()
    }

    fn drain_writers(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.write_waiters.drain(..).collect()
    }
}

fn log_pipe_end_owners(end: &Arc<Pipe>, label: &str) {
    if !DEBUG_UNIXBENCH {
        return;
    }
    let end_ptr = Arc::as_ptr(end);
    let map = PID2PCB.lock();
    let mut owners = Vec::new();
    let mut total = 0usize;
    for (pid, pcb) in map.iter() {
        let Some(inner) = pcb.try_borrow_mut() else {
            continue;
        };
        for (fd, file) in inner.fd_table.iter().enumerate() {
            let Some(file) = file else {
                continue;
            };
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                continue;
            };
            if (pipe as *const Pipe) == end_ptr {
                total += 1;
                if owners.len() < 8 {
                    owners.push((*pid, fd));
                }
            }
        }
    }
    drop(map);
    if total > 0 {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[pipe] {} owners={:?} total={}",
            label,
            owners,
            total
        );
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
        if want_to_read == 0 {
            return 0;
        }
        let has_pending_signal = || {
            current_task()
                .map(|t| t.borrow_mut().pending_signal.is_some())
                .unwrap_or(false)
        };
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail == 0 {
                if has_pending_signal() {
                    crate::log_if!(DEBUG_UNIXBENCH, info, "[pipe] read abort (pending signal)");
                    return 0;
                }
                if ring_buffer.all_write_ends_closed() {
                    crate::log_if!(DEBUG_UNIXBENCH, info, "[pipe] read EOF");
                    return 0;
                }
                let task = current_task().unwrap();
                let task_for_log = task.clone();
                let inserted = ring_buffer.push_reader(task);
                let waiters = ring_buffer.read_waiters.len();
                let writers = ring_buffer.write_end_count();
                let write_end = ring_buffer.write_end.as_ref().and_then(|w| w.upgrade());
                drop(ring_buffer);
                if DEBUG_UNIXBENCH && inserted {
                    let pid = task_for_log
                        .process
                        .upgrade()
                        .map(|p| p.getpid())
                        .unwrap_or(usize::MAX);
                    let tid = task_for_log
                        .borrow_mut()
                        .res
                        .as_ref()
                        .map(|r| r.tid)
                        .unwrap_or(usize::MAX);
                    crate::log_if!(
                        DEBUG_UNIXBENCH,
                        info,
                        "[pipe] wait read pid={} tid={} waiters={} writers={}",
                        pid,
                        tid,
                        waiters,
                        writers
                    );
                    if writers > 0 {
                        if let Some(end) = write_end {
                            log_pipe_end_owners(&end, "write");
                        }
                    }
                }
                block_current_and_run_next();
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
            let writer = if read_now > 0 {
                ring_buffer.pop_writer()
            } else {
                None
            };
            drop(ring_buffer);
            if let Some(writer) = writer {
                wakeup_task(writer);
            }
            return read_now;
        }
    }
    fn write(&self, buf: UserBuffer) -> usize {
        assert!(self.writable());
        let want_to_write = buf.len();
        if want_to_write == 0 {
            return 0;
        }
        let has_pending_signal = || {
            current_task()
                .map(|t| t.borrow_mut().pending_signal.is_some())
                .unwrap_or(false)
        };
        // Copy user data up front to avoid holding user pointers across blocking writes.
        let mut data = Vec::with_capacity(want_to_write);
        for byte_ref in buf.into_iter() {
            unsafe {
                data.push(*byte_ref);
            }
        }
        let mut buf_iter = data.into_iter();
        let mut already_write = 0usize;
        loop {
            let mut ring_buffer = self.buffer.lock();
            let loop_write = ring_buffer.available_write();
            if loop_write == 0 {
                if has_pending_signal() {
                    crate::log_if!(DEBUG_UNIXBENCH, info, "[pipe] write abort (pending signal)");
                    return already_write;
                }
                if ring_buffer.all_read_ends_closed() {
                    crate::log_if!(DEBUG_UNIXBENCH, info, "[pipe] write to closed read end");
                    return already_write;
                }
                let task = current_task().unwrap();
                let task_for_log = task.clone();
                let inserted = ring_buffer.push_writer(task);
                let waiters = ring_buffer.write_waiters.len();
                let readers = ring_buffer.read_end_count();
                let read_end = ring_buffer.read_end.as_ref().and_then(|w| w.upgrade());
                drop(ring_buffer);
                if DEBUG_UNIXBENCH && inserted {
                    let pid = task_for_log
                        .process
                        .upgrade()
                        .map(|p| p.getpid())
                        .unwrap_or(usize::MAX);
                    let tid = task_for_log
                        .borrow_mut()
                        .res
                        .as_ref()
                        .map(|r| r.tid)
                        .unwrap_or(usize::MAX);
                    crate::log_if!(
                        DEBUG_UNIXBENCH,
                        info,
                        "[pipe] wait write pid={} tid={} waiters={} readers={}",
                        pid,
                        tid,
                        waiters,
                        readers
                    );
                    if readers > 0 {
                        if let Some(end) = read_end {
                            log_pipe_end_owners(&end, "read");
                        }
                    }
                }
                block_current_and_run_next();
                continue;
            }
            // write at most loop_write bytes
            let mut reader_to_wake: Option<Arc<crate::task::task_block::TaskControlBlock>> = None;
            for _ in 0..loop_write {
                if let Some(byte) = buf_iter.next() {
                    ring_buffer.write_byte(byte);
                    already_write += 1;
                    if reader_to_wake.is_none() {
                        reader_to_wake = ring_buffer.pop_reader();
                    }
                    if already_write == want_to_write {
                        drop(ring_buffer);
                        if let Some(reader) = reader_to_wake {
                            wakeup_task(reader);
                        }
                        return want_to_write;
                    }
                } else {
                    drop(ring_buffer);
                    if let Some(reader) = reader_to_wake {
                        wakeup_task(reader);
                    }
                    return already_write;
                }
            }
            drop(ring_buffer);
            if let Some(reader) = reader_to_wake {
                wakeup_task(reader);
            }
        }
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let mut ring = self.buffer.lock();
        if self.readable {
            let writers = ring.drain_writers();
            drop(ring);
            for task in writers {
                wakeup_task(task);
            }
        } else if self.writable {
            let readers = ring.drain_readers();
            drop(ring);
            for task in readers {
                wakeup_task(task);
            }
        }
    }
}
