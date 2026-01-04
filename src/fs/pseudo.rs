extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::mm::UserBuffer;

use super::File;

pub enum PseudoKind {
    Static(Vec<u8>),
    Urandom(u64),
    Null,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoKindTag {
    Static,
    Urandom,
    Null,
    Zero,
}

pub struct PseudoFile {
    readable: bool,
    writable: bool,
    inner: Mutex<PseudoInner>,
}

struct PseudoInner {
    offset: usize,
    kind: PseudoKind,
}

/// A minimal pseudo directory for `/proc`, `/sys`, etc.
///
/// Directory iteration is implemented in `syscall_getdents64` by downcasting.
pub struct PseudoDir {
    path: String,
    entries: Vec<PseudoDirent>,
    inner: Mutex<PseudoDirInner>,
}

#[derive(Clone)]
pub struct PseudoDirent {
    pub name: alloc::string::String,
    pub ino: u64,
    pub dtype: u8, // Linux DT_* values (e.g. 4=DIR, 8=REG)
}

struct PseudoDirInner {
    index: usize,
}

impl PseudoDir {
    pub fn new(path: &str, entries: Vec<PseudoDirent>) -> Self {
        let mut p = String::from(path);
        if p.is_empty() {
            p.push('/');
        }
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        while p.len() > 1 && p.ends_with('/') {
            p.pop();
        }
        Self {
            path: p,
            entries,
            inner: Mutex::new(PseudoDirInner { index: 0 }),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn entries(&self) -> &[PseudoDirent] {
        &self.entries
    }

    pub fn index(&self) -> usize {
        self.inner.lock().index
    }

    pub fn set_index(&self, index: usize) {
        self.inner.lock().index = index;
    }
}

impl File for PseudoDir {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A minimal RTC device node for busybox `hwclock`.
///
/// Actual RTC semantics are handled in `syscall_ioctl` by downcasting.
pub struct RtcFile;

impl RtcFile {
    pub fn new() -> Self {
        Self
    }
}

impl File for RtcFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, buf: UserBuffer) -> usize {
        buf.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

type ShmData = Arc<Mutex<Vec<u8>>>;

lazy_static! {
    static ref SHM_OBJECTS: Mutex<BTreeMap<String, ShmData>> = Mutex::new(BTreeMap::new());
}

pub fn shm_list() -> Vec<String> {
    SHM_OBJECTS.lock().keys().cloned().collect()
}

pub fn shm_get(name: &str) -> Option<ShmData> {
    SHM_OBJECTS.lock().get(name).cloned()
}

pub fn shm_create(name: &str) -> ShmData {
    let mut map = SHM_OBJECTS.lock();
    map.entry(String::from(name))
        .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
        .clone()
}

pub fn shm_remove(name: &str) -> bool {
    SHM_OBJECTS.lock().remove(name).is_some()
}

/// A minimal block device node for `/dev/root` so tools like busybox `df`
/// treat the root filesystem as a real device-backed mount.
pub struct PseudoBlock;

impl PseudoBlock {
    pub fn new() -> Self {
        Self
    }
}

impl File for PseudoBlock {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A minimal shared-memory file for `/dev/shm/<name>`.
///
/// This is a very small in-memory backing store to satisfy musl's `shm_open`/`shm_unlink`
/// users (e.g., `cyclictest`). It provides per-fd offsets and a shared data buffer.
pub struct PseudoShmFile {
    data: ShmData,
    offset: Mutex<usize>,
}

impl PseudoShmFile {
    pub fn new(data: ShmData) -> Self {
        Self {
            data,
            offset: Mutex::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.data.lock().len()
    }

    pub fn offset(&self) -> usize {
        *self.offset.lock()
    }

    pub fn set_offset(&self, offset: usize) {
        *self.offset.lock() = offset;
    }

    pub fn truncate(&self, new_len: usize) {
        let mut data = self.data.lock();
        data.resize(new_len, 0);
        let mut off = self.offset.lock();
        if *off > new_len {
            *off = new_len;
        }
    }
}

impl File for PseudoShmFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut off = self.offset.lock();
        let data = self.data.lock();
        if *off >= data.len() {
            return 0;
        }
        let mut total = 0usize;
        for slice in buf.buffers.iter_mut() {
            if *off >= data.len() {
                break;
            }
            let n = core::cmp::min(slice.len(), data.len() - *off);
            slice[..n].copy_from_slice(&data[*off..*off + n]);
            *off += n;
            total += n;
            if n < slice.len() {
                break;
            }
        }
        total
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let mut off = self.offset.lock();
        let mut data = self.data.lock();
        let mut total = 0usize;
        for slice in buf.buffers.iter() {
            if slice.is_empty() {
                continue;
            }
            let end = off.saturating_add(slice.len());
            if end > data.len() {
                data.resize(end, 0);
            }
            data[*off..end].copy_from_slice(slice);
            *off = end;
            total += slice.len();
        }
        total
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PseudoFile {
    pub fn new_static(content: &str) -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Static(content.as_bytes().to_vec()),
            }),
        }
    }

    pub fn new_urandom(seed: u64) -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Urandom(seed),
            }),
        }
    }

    pub fn new_null() -> Self {
        Self {
            readable: true,
            writable: true,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Null,
            }),
        }
    }

    pub fn new_zero() -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Zero,
            }),
        }
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        self.inner.lock().offset = offset;
    }

    pub fn len(&self) -> Option<usize> {
        let inner = self.inner.lock();
        match &inner.kind {
            PseudoKind::Static(data) => Some(data.len()),
            _ => None,
        }
    }

    pub fn kind_tag(&self) -> PseudoKindTag {
        match &self.inner.lock().kind {
            PseudoKind::Static(_) => PseudoKindTag::Static,
            PseudoKind::Urandom(_) => PseudoKindTag::Urandom,
            PseudoKind::Null => PseudoKindTag::Null,
            PseudoKind::Zero => PseudoKindTag::Zero,
        }
    }
}

impl File for PseudoFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        let PseudoInner { offset, kind } = &mut *inner;
        match kind {
            PseudoKind::Static(data) => {
                if *offset >= data.len() {
                    return 0;
                }
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    if *offset >= data.len() {
                        break;
                    }
                    let n = core::cmp::min(slice.len(), data.len() - *offset);
                    slice[..n].copy_from_slice(&data[*offset..*offset + n]);
                    *offset += n;
                    total += n;
                    if n < slice.len() {
                        break;
                    }
                }
                total
            }
            PseudoKind::Urandom(seed) => {
                // xorshift64*
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    for b in slice.iter_mut() {
                        let mut x = *seed;
                        x ^= x >> 12;
                        x ^= x << 25;
                        x ^= x >> 27;
                        x = x.wrapping_mul(0x2545F4914F6CDD1D);
                        *seed = x;
                        *b = (x & 0xff) as u8;
                        total += 1;
                    }
                }
                total
            }
            PseudoKind::Null => 0,
            PseudoKind::Zero => {
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    slice.fill(0);
                    total += slice.len();
                }
                total
            }
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        match self.inner.lock().kind {
            PseudoKind::Null => buf.len(),
            _ => 0,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
