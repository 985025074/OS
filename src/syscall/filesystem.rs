use core::str;

use crate::{
    console::print,
    fs::{OpenFlags, make_pipe, open_file},
    mm::{UserBuffer, translated_byte_buffer, translated_single_address},
    println,
    task::processor::current_task,
    trap::get_current_token,
};

pub fn syscall_open(file_path: usize, open_flags: usize, file_path_len: usize) -> isize {
    let real_path = translated_single_address(get_current_token(), file_path as *const u8);
    let path_str = unsafe { str::from_raw_parts(real_path as *const u8, file_path_len) };

    let now_len: usize;
    let open_flags = OpenFlags::from_bits(open_flags as u32).unwrap();

    let result = open_file(path_str, open_flags).unwrap();
    let task_now = current_task().unwrap();
    let mut task_now_inner = task_now.get_inner();
    task_now_inner.fd_table.push(Some(result));
    now_len = task_now_inner.fd_table.len();
    now_len as isize - 1
}
pub fn syscall_close(fd: usize) -> isize {
    let task_now = current_task().unwrap();
    let mut task_now_inner = task_now.get_inner();
    if fd >= task_now_inner.fd_table.len() {
        return -1;
    }
    task_now_inner.fd_table[fd] = None;
    0
}
pub fn syscall_read(fd: usize, buffer: usize, len: usize) -> isize {
    let task_now = current_task().unwrap();
    let task_now_inner = task_now.get_inner();
    if fd >= task_now_inner.fd_table.len() {
        return -1;
    }
    let file_option = &task_now_inner.fd_table[fd];

    if file_option.is_none() {
        return -1;
    }
    let file = file_option.as_ref().unwrap().clone();
    // get current will need to use task..
    drop(task_now_inner);
    let buf = UserBuffer::new(translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
    ));
    let read_len = file.read(buf);
    read_len as isize
}
pub fn syscall_write(fd: usize, buffer: usize, len: usize) -> isize {
    let task_now = current_task().unwrap();
    let task_now_inner = task_now.get_inner();
    if fd >= task_now_inner.fd_table.len() {
        return -1;
    }
    let file_option = &task_now_inner.fd_table[fd];
    if file_option.is_none() {
        return -1;
    }
    let file = file_option.as_ref().unwrap().clone();

    drop(task_now_inner);
    let buf = UserBuffer::new(translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
    ));
    let write_len = file.write(buf);
    // println!(
    //     "syscall_write wrote {} bytes.,while args {}",
    //     write_len, len
    // );

    write_len as isize
}
/// pipe: outer address of [read_fd, write_fd]
pub fn syscall_pipe(pipe: *mut usize) -> isize {
    let task = current_task().unwrap();
    let token = get_current_token();
    let (pipe_read, pipe_write) = make_pipe();

    let mut inner = task.get_inner();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(pipe_read);
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(pipe_write);
    println!("pipe fds: {}, {}", read_fd, write_fd);
    unsafe {
        let addr = translated_single_address(token, pipe as *const u8) as *mut u8 as *mut usize;
        *addr = read_fd;
    }
    unsafe {
        let addr =
            translated_single_address(token, pipe.add(1) as *const u8) as *mut u8 as *mut usize;
        *addr = write_fd;
    }
    0
}
