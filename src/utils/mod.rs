use crate::println;

pub struct RefCellSafe<T> {
    refcell: core::cell::RefCell<T>,
}
unsafe impl<T> Sync for RefCellSafe<T> {}
impl<T> RefCellSafe<T> {
    pub const fn new(val: T) -> Self {
        Self {
            refcell: core::cell::RefCell::new(val),
        }
    }
    pub fn borrow(&self) -> core::cell::Ref<T> {
        self.refcell.borrow()
    }
    pub fn borrow_mut(&self) -> core::cell::RefMut<T> {
        self.refcell.borrow_mut()
    }
}
