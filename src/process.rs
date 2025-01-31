use crate::error::{MemoryError, Result};
use std::ptr;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, HANDLE};
use winapi::shared::minwindef::DWORD;
const ERROR_ACCESS_DENIED: DWORD = 5;
use winapi::um::errhandlingapi::GetLastError;

pub struct Process {
    handle: HANDLE,
    pid: u32,
}

impl Process {
    pub fn attach(pid: u32) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                0,
                pid,
            )
        };

        if handle == ptr::null_mut() {
            let error_code = unsafe { GetLastError() };
            return Err(match error_code {
                ERROR_ACCESS_DENIED => MemoryError::ProcessAccess(
                    format!("Access denied when opening process {}", pid)
                ),
                _ => MemoryError::ProcessAccess(format!(
                    "Failed to open process {} (Error code: {})",
                    pid, error_code
                )),
            });
        }

        Ok(Self { handle, pid })
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                winapi::um::handleapi::CloseHandle(self.handle);
            }
        }
    }
} 