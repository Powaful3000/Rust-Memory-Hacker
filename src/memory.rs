use crate::error::{MemoryError, Result};
use std::mem;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualQueryEx};
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_GUARD, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE};
use winapi::um::errhandlingapi::GetLastError;
use std::collections::HashMap;
use tokio::task;
use std::sync::Arc;
use tracing::debug;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use winapi::shared::minwindef::DWORD;

const ERROR_ACCESS_DENIED: DWORD = 5;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanType {
    ExactValue,
    Increased,
    Decreased,
    Changed,
    Unchanged,
}

#[derive(Debug, Clone, Copy)]
pub enum DataType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

#[derive(Debug)]
pub struct MemoryScan {
    pub scan_type: ScanType,
    pub data_type: DataType,
    pub results: HashMap<usize, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TrackedAddress {
    pub name: String,
    pub address: usize,
    pub value_type: DataType,
    pub description: Option<String>,
    pub frozen_value: Option<Vec<u8>>,
}

// New thread-safe wrapper for HANDLE
#[derive(Debug)]
struct ThreadSafeHandle(HANDLE);

// Implement Send and Sync for our wrapper
unsafe impl Send for ThreadSafeHandle {}
unsafe impl Sync for ThreadSafeHandle {}

#[derive(Clone)]
pub struct MemoryScanner {
    process_handle: Arc<ThreadSafeHandle>,
    region_cache: Arc<Mutex<RegionCache>>,
}

// Implement Send and Sync since we know our usage of HANDLE is thread-safe
unsafe impl Send for MemoryScanner {}
unsafe impl Sync for MemoryScanner {}

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub state: u32,
    pub type_: u32,
}

#[derive(Debug)]
pub struct ScanProgress {
    pub regions_scanned: AtomicUsize,
    pub bytes_scanned: AtomicUsize,
    pub matches_found: AtomicUsize,
    pub errors: ScanErrorStats,
    pub last_update: Mutex<Instant>,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            regions_scanned: AtomicUsize::new(0),
            bytes_scanned: AtomicUsize::new(0),
            matches_found: AtomicUsize::new(0),
            errors: ScanErrorStats::new(),
            last_update: Mutex::new(Instant::now()),
        }
    }

    pub fn should_update(&self) -> bool {
        let mut last_update = self.last_update.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*last_update) >= Duration::from_millis(100) {
            *last_update = now;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct ScanContext {
    pub progress: ScanProgress,
    pub cancel: tokio::sync::watch::Receiver<bool>,
}

#[derive(Debug)]
pub enum ValueConversionError {
    InvalidSize,
    InvalidFormat,
    Overflow,
}

impl DataType {
    pub fn size(&self) -> usize {
        match self {
            DataType::U8 | DataType::I8 => 1,
            DataType::U16 | DataType::I16 => 2,
            DataType::U32 | DataType::I32 | DataType::F32 => 4,
            DataType::U64 | DataType::I64 | DataType::F64 => 8,
        }
    }

    pub fn alignment(&self) -> usize {
        match self {
            DataType::U8 | DataType::I8 => 1,
            DataType::U16 | DataType::I16 => 2,
            DataType::U32 | DataType::I32 | DataType::F32 => 4,
            DataType::U64 | DataType::I64 | DataType::F64 => 8,
        }
    }

    pub fn convert_value(&self, bytes: &[u8]) -> Result<String> {
        if bytes.len() != self.size() {
            return Err(MemoryError::MemoryOperation(
                format!("Invalid value size for {:?}: expected {}, got {}", 
                    self, self.size(), bytes.len())
            ));
        }

        let value = match self {
            DataType::U8 => format!("{}", u8::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::U16 => format!("{}", u16::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::U32 => format!("{}", u32::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::U64 => format!("{}", u64::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::I8 => format!("{}", i8::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::I16 => format!("{}", i16::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::I32 => format!("{}", i32::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::I64 => format!("{}", i64::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::F32 => format!("{}", f32::from_ne_bytes(bytes.try_into().unwrap())),
            DataType::F64 => format!("{}", f64::from_ne_bytes(bytes.try_into().unwrap())),
        };

        Ok(value)
    }

    pub fn parse_value(&self, input: &str) -> Result<Vec<u8>> {
        let bytes = match self {
            DataType::U8 => input.parse::<u8>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid u8 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::U16 => input.parse::<u16>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid u16 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::U32 => input.parse::<u32>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid u32 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::U64 => input.parse::<u64>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid u64 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::I8 => input.parse::<i8>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid i8 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::I16 => input.parse::<i16>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid i16 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::I32 => input.parse::<i32>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid i32 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::I64 => input.parse::<i64>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid i64 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::F32 => input.parse::<f32>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid f32 value".to_string()))?
                .to_ne_bytes().to_vec(),
            DataType::F64 => input.parse::<f64>()
                .map_err(|_| MemoryError::MemoryOperation("Invalid f64 value".to_string()))?
                .to_ne_bytes().to_vec(),
        };
        Ok(bytes)
    }
}

impl ScanType {
    pub fn requires_previous_results(&self) -> bool {
        matches!(self, 
            ScanType::Increased | 
            ScanType::Decreased | 
            ScanType::Changed | 
            ScanType::Unchanged
        )
    }
}

#[derive(Debug)]
pub struct ScanOptions {
    pub scan_type: ScanType,
    pub data_type: DataType,
    pub value: Vec<u8>,
    pub previous_results: Option<HashMap<usize, Vec<u8>>>,
    pub cancel: Arc<AtomicBool>,
}

impl ScanOptions {
    pub fn validate(&self) -> Result<()> {
        // Validate value size matches data type
        let expected_size = self.data_type.size();
        if self.value.len() != expected_size {
            return Err(MemoryError::MemoryOperation(
                format!("Value size mismatch: expected {}, got {}", 
                    expected_size, self.value.len())
            ));
        }

        // Validate previous results for comparison scans
        match self.scan_type {
            ScanType::Changed | ScanType::Unchanged | 
            ScanType::Increased | ScanType::Decreased => {
                if self.previous_results.is_none() {
                    return Err(MemoryError::MemoryOperation(
                        "Previous results required for comparison scan".to_string()
                    ));
                }
            }
            _ => {}
        }

        // Validate alignment requirements
        let alignment = self.data_type.alignment();
        if self.value.as_ptr() as usize % alignment != 0 {
            return Err(MemoryError::MemoryOperation(
                format!("Value buffer not properly aligned for {:?}", self.data_type)
            ));
        }

        Ok(())
    }
}

// Add helper method to create scan options
impl MemoryScanner {
    pub fn create_scan_options(
        scan_type: ScanType,
        data_type: DataType,
        value: Vec<u8>,
        previous_results: Option<HashMap<usize, Vec<u8>>>,
    ) -> ScanOptions {
        ScanOptions {
            scan_type,
            data_type,
            value,
            previous_results,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl MemoryScanner {
    pub fn new(process_handle: HANDLE) -> Self {
        let handle = Arc::new(ThreadSafeHandle(process_handle));
        Self {
            process_handle: handle,
            region_cache: Arc::new(Mutex::new(RegionCache::new())),
        }
    }

    pub fn validate_address(&self, address: usize, size: usize) -> Result<()> {
        let (region_start, region_end) = self.get_region_bounds(address)?;
        
        if address < region_start || address + size > region_end {
            return Err(MemoryError::MemoryOperation(
                format!("Memory range {:#x}-{:#x} crosses region boundary", address, address + size)
            ));
        }

        let protection = self.get_region_permissions(address)?;
        if !self.is_readable_region(protection) {
            return Err(MemoryError::InvalidProtection(address));
        }

        Ok(())
    }

    fn check_alignment<T>(&self, address: usize) -> Result<()> {
        let alignment = std::mem::align_of::<T>();
        if address % alignment != 0 {
            return Err(MemoryError::AlignmentError(address, alignment));
        }
        Ok(())
    }

    pub fn read_memory<T: Copy>(&self, address: usize) -> Result<T> {
        self.check_alignment::<T>(address)?;
        self.validate_address(address, std::mem::size_of::<T>())?;
        let mut buffer: T = unsafe { mem::zeroed() };
        let bytes_read = &mut 0;

        let success = unsafe {
            ReadProcessMemory(
                self.process_handle.0,  // Access the inner HANDLE
                address as *const _,
                &mut buffer as *mut T as *mut _,
                mem::size_of::<T>(),
                bytes_read,
            )
        };

        if success == 0 {
            return Err(MemoryError::MemoryOperation(format!(
                "Failed to read memory at address: {:#x}",
                address
            )));
        }

        Ok(buffer)
    }

    pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> Result<()> {
        self.check_alignment::<T>(address)?;
        self.validate_address(address, std::mem::size_of::<T>())?;
        let bytes_written = &mut 0;

        let success = unsafe {
            WriteProcessMemory(
                self.process_handle.0,
                address as *mut _,
                value as *const T as *const _,
                mem::size_of::<T>(),
                bytes_written,
            )
        };

        if success == 0 {
            return Err(MemoryError::MemoryOperation(format!(
                "Failed to write memory at address: {:#x}",
                address
            )));
        }

        Ok(())
    }

    fn validate_scan_params<T>(&self, scan_type: ScanType, previous_results: Option<&HashMap<usize, T>>) -> Result<()> {
        if scan_type.requires_previous_results() && previous_results.is_none() {
            return Err(MemoryError::MemoryOperation(
                format!("{:?} scan type requires previous results", scan_type)
            ));
        }
        Ok(())
    }

    fn check_cancelled(&self, cancel: &tokio::sync::watch::Receiver<bool>) -> bool {
        if *cancel.borrow() {
            debug!("Scan cancelled by user");
            true
        } else {
            false
        }
    }

    pub async fn scan_memory_with_cancel(
        &self,
        value: Vec<u8>,
        scan_type: ScanType,
        data_type: DataType,
        previous_results: Option<HashMap<usize, Vec<u8>>>,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<HashMap<usize, Vec<u8>>> {
        let cancel_signal = Arc::new(AtomicBool::new(false));
        let cancel_signal_clone = Arc::clone(&cancel_signal);

        // Create a task to monitor the cancel signal
        let _cancel_task = tokio::spawn(async move {
            while !*cancel.borrow() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            cancel_signal_clone.store(true, Ordering::Relaxed);
        });

        let options = ScanOptions {
            scan_type,
            data_type,
            value,
            previous_results,
            cancel: cancel_signal,
        };

        self.scan_with_options(options, None).await
    }

    fn read_memory_chunked(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        const CHUNK_SIZE: usize = 4096; // Use 4KB chunks
        let mut result = Vec::with_capacity(size);
        
        for chunk_offset in (0..size).step_by(CHUNK_SIZE) {
            let chunk_size = std::cmp::min(CHUNK_SIZE, size - chunk_offset);
            let chunk_addr = address + chunk_offset;
            
            let mut buffer = vec![0u8; chunk_size];
            match self.read_memory_raw(chunk_addr, &mut buffer) {
                Ok(_) => result.extend_from_slice(&buffer),
                Err(e) => {
                    debug!("Failed to read chunk at {:#x}: {}", chunk_addr, e);
                    // Fill failed reads with zeros
                    result.extend(std::iter::repeat(0).take(chunk_size));
                }
            }
        }
        
        Ok(result)
    }

    fn read_memory_partial(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        const CHUNK_SIZE: usize = 4096;
        let mut result = Vec::with_capacity(size);
        
        // Get initial region info to validate the starting point
        let initial_region = self.get_memory_region(address)?;
        if !self.is_readable_region(initial_region.protection) {
            return Err(MemoryError::InvalidProtection(address));
        }
        
        let mut current_offset = 0;
        while current_offset < size {
            let chunk_addr = address + current_offset;
            
            // Check if we've crossed into a new region
            let region = self.get_memory_region(chunk_addr)?;
            if !self.is_readable_region(region.protection) {
                debug!("Hit non-readable region at {:#x}", chunk_addr);
                break;
            }
            
            // Calculate how much we can read within the current region
            let region_remaining = (region.base_address + region.size).saturating_sub(chunk_addr);
            let chunk_size = std::cmp::min(
                std::cmp::min(CHUNK_SIZE, size - current_offset),
                region_remaining
            );
            
            if chunk_size == 0 {
                break;
            }
            
            let mut buffer = vec![0u8; chunk_size];
            match self.read_memory_raw(chunk_addr, &mut buffer) {
                Ok(_) => result.extend_from_slice(&buffer),
                Err(e) => {
                    debug!("Failed to read chunk at {:#x}: {}", chunk_addr, e);
                    // Fill failed reads with zeros but track the error
                    result.extend(std::iter::repeat(0).take(chunk_size));
                    // Don't immediately return on error - continue with next chunk
                }
            }
            
            current_offset += chunk_size;
        }
        
        Ok(result)
    }

    fn scan_region(
        &self,
        base_addr: usize,
        size: usize,
        target_value: &[u8],
        data_type: DataType,
        scan_type: ScanType,
        previous_results: Option<&HashMap<usize, Vec<u8>>>,
        results: &mut HashMap<usize, Vec<u8>>,
        stats: &ScanStats,
    ) -> Result<()> {
        // Log only at start of region
        debug!("Scanning region at {:#x} size {}", base_addr, size);
        
        let type_size = data_type.size();
        let aligned_start = (base_addr + data_type.alignment() - 1) & !(data_type.alignment() - 1);
        let end_addr = base_addr.checked_add(size)
            .ok_or_else(|| MemoryError::MemoryOperation("Address overflow".to_string()))?;

        let mut current_addr = aligned_start;
        let mut matches_in_region = 0;

        while current_addr + type_size <= end_addr {
            if let Ok(current_value) = self.safe_read_memory(current_addr, type_size, stats) {
                let matches = match scan_type {
                    ScanType::ExactValue => {
                        if current_value.len() == target_value.len() {
                            current_value == target_value
                        } else {
                            false
                        }
                    },
                    ScanType::Changed | ScanType::Unchanged => {
                        if let Some(prev_map) = previous_results {
                            prev_map.get(&current_addr).map_or(false, |old| {
                                let changed = current_value != *old;
                                if scan_type == ScanType::Changed { changed } else { !changed }
                            })
                        } else {
                            false
                        }
                    },
                    ScanType::Increased | ScanType::Decreased => {
                        if let Some(prev_map) = previous_results {
                            if let Some(old) = prev_map.get(&current_addr) {
                                self.compare_values(&current_value, old, data_type)
                                    .map_or(false, |comparison| {
                                        match scan_type {
                                            ScanType::Increased => comparison > 0,
                                            ScanType::Decreased => comparison < 0,
                                            _ => false,
                                        }
                                    })
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                };

                if matches {
                    results.insert(current_addr, current_value);
                    matches_in_region += 1;
                    // Log matches in batches
                    if matches_in_region % 100 == 0 {
                        debug!("Found {} matches in region {:#x}", matches_in_region, base_addr);
                    }
                }
            }
            
            current_addr += type_size;
        }

        // Log region completion only if matches were found
        if matches_in_region > 0 {
            debug!("Completed region {:#x} scan, found {} matches", base_addr, matches_in_region);
        }
        
        Ok(())
    }

    fn compare_values(&self, current: &[u8], previous: &[u8], data_type: DataType) -> Option<i32> {
        if current.len() != previous.len() {
            return None;
        }

        match data_type {
            DataType::U8 => {
                let curr = u8::from_ne_bytes(current.try_into().ok()?);
                let prev = u8::from_ne_bytes(previous.try_into().ok()?);
                Some((curr as i32).cmp(&(prev as i32)) as i32)
            },
            DataType::U16 => {
                let curr = u16::from_ne_bytes(current.try_into().ok()?);
                let prev = u16::from_ne_bytes(previous.try_into().ok()?);
                Some((curr as i32).cmp(&(prev as i32)) as i32)
            },
            DataType::U32 => {
                let curr = u32::from_ne_bytes(current.try_into().ok()?);
                let prev = u32::from_ne_bytes(previous.try_into().ok()?);
                Some((curr as i64).cmp(&(prev as i64)) as i32)
            },
            DataType::I8 => {
                let curr = i8::from_ne_bytes(current.try_into().ok()?);
                let prev = i8::from_ne_bytes(previous.try_into().ok()?);
                Some(curr.cmp(&prev) as i32)
            },
            DataType::I16 => {
                let curr = i16::from_ne_bytes(current.try_into().ok()?);
                let prev = i16::from_ne_bytes(previous.try_into().ok()?);
                Some(curr.cmp(&prev) as i32)
            },
            DataType::I32 => {
                let curr = i32::from_ne_bytes(current.try_into().ok()?);
                let prev = i32::from_ne_bytes(previous.try_into().ok()?);
                Some(curr.cmp(&prev) as i32)
            },
            DataType::F32 => {
                let curr = f32::from_ne_bytes(current.try_into().ok()?);
                let prev = f32::from_ne_bytes(previous.try_into().ok()?);
                Some(curr.partial_cmp(&prev)? as i32)
            },
            // Add other types as needed...
            _ => None,
        }
    }

    // Add a new method for the menu to use
    pub async fn scan_memory(
        &self,
        value: Vec<u8>,
        scan_type: ScanType,
        data_type: DataType,
        previous_results: Option<HashMap<usize, Vec<u8>>>
    ) -> Result<HashMap<usize, Vec<u8>>> {
        debug!("Starting scan_memory with type {:?}, data_type {:?}", scan_type, data_type);
        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            scan_type,
            data_type,
            value,
            previous_results,
            cancel,
        };
        debug!("Created scan options, calling scan_with_options");
        self.scan_with_options(options, None).await
    }

    fn get_region_permissions(&self, address: usize) -> Result<u32> {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        
        let result = unsafe {
            VirtualQueryEx(
                self.process_handle.0,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            )
        };

        if result == 0 {
            return Err(MemoryError::InvalidAddress(address));
        }

        Ok(mbi.Protect)
    }

    fn is_readable_region(&self, protection: u32) -> bool {
        let readable_flags = [
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY
        ];

        if protection & PAGE_GUARD != 0 || protection & PAGE_NOACCESS != 0 {
            return false;
        }

        readable_flags.iter().any(|&flag| protection & flag != 0)
    }

    fn is_writable_region(&self, protection: u32) -> bool {
        let writable_flags = [
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY
        ];

        if protection & PAGE_GUARD != 0 || protection & PAGE_NOACCESS != 0 {
            return false;
        }

        writable_flags.iter().any(|&flag| protection & flag != 0)
    }

    pub fn get_memory_region(&self, address: usize) -> Result<MemoryRegionInfo> {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        
        let result = unsafe {
            VirtualQueryEx(
                self.process_handle.0,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            )
        };

        if result == 0 {
            return Err(MemoryError::InvalidAddress(address));
        }

        Ok(MemoryRegionInfo {
            base_address: mbi.BaseAddress as usize,
            size: mbi.RegionSize,
            protection: mbi.Protect,
            state: mbi.State,
            type_: mbi.Type,
        })
    }

    pub fn enumerate_memory_regions(&self) -> Result<Vec<MemoryRegionInfo>> {
        debug!("Starting memory region enumeration");
        let mut regions = Vec::new();
        let mut address = 0usize;
        let mut valid_regions = 0;
        
        while let Ok(region) = self.get_memory_region(address) {
            if region.state == MEM_COMMIT && self.is_readable_region(region.protection) {
                // Log only every 100th region
                if valid_regions % 100 == 0 {
                    debug!("Found {} valid regions, current: base={:#x}", 
                        valid_regions, region.base_address);
                }
                regions.push(region.clone());
                valid_regions += 1;
            }
            
            if let Some(next_addr) = region.base_address.checked_add(region.size) {
                address = next_addr;
            } else {
                debug!("Region enumeration complete: address overflow");
                break;
            }
        }
        
        debug!("Memory enumeration complete. Found {} valid regions", regions.len());
        Ok(regions)
    }

    fn get_region_bounds(&self, address: usize) -> Result<(usize, usize)> {
        let region = self.get_memory_region(address)?;
        let end = region.base_address.checked_add(region.size)
            .ok_or_else(|| MemoryError::MemoryOperation(
                format!("Region size overflow at {:#x}", address)
            ))?;
            
        Ok((region.base_address, end))
    }

    fn update_scan_stats(&self, stats: &ScanStats, chunk_size: usize, matches: usize) {
        stats.bytes_scanned.fetch_add(chunk_size, Ordering::Relaxed);
        stats.matches_found.fetch_add(matches, Ordering::Relaxed);
        
        if stats.should_update() {
            debug!("Scan progress:");
            debug!("- Bytes scanned: {}", stats.bytes_scanned.load(Ordering::Relaxed));
            debug!("- Matches found: {}", stats.matches_found.load(Ordering::Relaxed));
            debug!("- Regions processed: {}", stats.regions_scanned.load(Ordering::Relaxed));
            
            // Add error statistics if any
            let errors = &stats.errors;
            if errors.read_errors.load(Ordering::Relaxed) > 0 
               || errors.protection_errors.load(Ordering::Relaxed) > 0 
               || errors.alignment_errors.load(Ordering::Relaxed) > 0 
            {
                debug!("Errors encountered:");
                debug!("- Read errors: {}", errors.read_errors.load(Ordering::Relaxed));
                debug!("- Protection errors: {}", errors.protection_errors.load(Ordering::Relaxed));
                debug!("- Alignment errors: {}", errors.alignment_errors.load(Ordering::Relaxed));
            }
        }
    }

    pub fn read_value(&self, address: usize, data_type: DataType) -> Result<Vec<u8>> {
        self.validate_address(address, data_type.size())?;
        let mut buffer = vec![0u8; data_type.size()];
        self.read_memory_raw(address, &mut buffer)?;
        Ok(buffer)
    }

    pub fn write_value(&self, address: usize, value: &[u8], data_type: DataType) -> Result<()> {
        if value.len() != data_type.size() {
            return Err(MemoryError::MemoryOperation(
                format!("Value size mismatch: expected {}, got {}", data_type.size(), value.len())
            ));
        }
        self.validate_address(address, data_type.size())?;
        self.write_memory_raw(address, value)
    }

    fn get_cached_region(&self, address: usize) -> Option<MemoryRegionInfo> {
        let cache = self.region_cache.lock().unwrap();
        if cache.validate_cache() {
            return cache.regions.range(..=address).next_back()
                .filter(|(start, region)| {
                    address >= **start && address < **start + region.size
                })
                .map(|(_, region)| region.clone());
        }
        None
    }

    fn refresh_region_cache(&self) -> Result<()> {
        let regions = self.enumerate_memory_regions()?;
        let mut cache = self.region_cache.lock().unwrap();
        cache.update(regions);
        Ok(())
    }

    pub async fn scan_with_options(
        &self,
        options: ScanOptions,
        progress_handler: Option<Box<dyn ScanProgressHandler>>,
    ) -> Result<HashMap<usize, Vec<u8>>> {
        options.validate()?;
        debug!("Starting memory scan with {:?} for type {:?}", options.scan_type, options.data_type);

        let stats = Arc::new(ScanStats::new());
        let stats_clone = Arc::clone(&stats);
        let scanner = self.clone();
        let target_value = options.value.clone();
        let total_memory = self.calculate_total_memory()?;
        debug!("Total memory to scan: {} bytes", total_memory);
        let progress_handler = Arc::new(progress_handler);

        debug!("Spawning blocking scan task...");
        let results = task::spawn_blocking(move || -> Result<HashMap<usize, Vec<u8>>> {
            let mut results = HashMap::new();
            
            if let Some(previous_results) = options.previous_results {
                // Next scan mode - only check previous addresses
                for (address, prev_value) in previous_results {
                    if options.cancel.load(Ordering::Relaxed) {
                        break;
                    }

                    // Validate memory access
                    if let Err(_) = scanner.validate_memory_region(address, options.data_type.size()) {
                        continue;
                    }

                    // Read current value
                    match scanner.safe_read_memory(address, options.data_type.size(), &stats_clone) {
                        Ok(current_value) => {
                            let matches = match options.scan_type {
                                ScanType::ExactValue => current_value == target_value,
                                ScanType::Increased => {
                                    // Compare as numbers based on data_type
                                    scanner.compare_values(&current_value, &prev_value, options.data_type)
                                        .map_or(false, |result| result > 0)
                                },
                                ScanType::Decreased => {
                                    scanner.compare_values(&current_value, &prev_value, options.data_type)
                                        .map_or(false, |result| result < 0)
                                },
                                ScanType::Changed => current_value != prev_value,
                                ScanType::Unchanged => current_value == prev_value,
                            };

                            if matches {
                                results.insert(address, current_value);
                                stats_clone.matches_found.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                        Err(e) => scanner.handle_read_error(e, address, options.data_type.size(), &stats_clone),
                    }
                    
                    stats_clone.bytes_scanned.fetch_add(options.data_type.size(), Ordering::Relaxed);
                }
            } else {
                // Initial scan - process all regions
                let regions = scanner.enumerate_memory_regions()?;
                debug!("Found {} memory regions to scan", regions.len());
                
                for (region_index, region) in regions.iter().enumerate() {
                    if options.cancel.load(Ordering::Relaxed) {
                        debug!("Scan cancelled");
                        break;
                    }

                    // Skip image regions
                    if region.type_ == MEM_IMAGE {
                        debug!("Skipping image region {}/{} at {:#x}", 
                            region_index + 1, regions.len(), region.base_address);
                        continue;
                    }

                    // Use region_index for progress updates
                    if region_index % 10 == 0 {
                        if let Some(handler) = progress_handler.as_ref() {
                            let progress = ScanProgressUpdate {
                                regions_scanned: region_index,
                                bytes_scanned: stats_clone.bytes_scanned.load(Ordering::Relaxed),
                                matches_found: stats_clone.matches_found.load(Ordering::Relaxed),
                                current_address: region.base_address,
                                total_memory,
                            };
                            let _ = handler.update(progress);
                        }
                    }

                    if region.state == MEM_COMMIT && scanner.is_readable_region(region.protection) {
                        let type_size = options.data_type.size();
                        let alignment = options.data_type.alignment();
                        const CHUNK_SIZE: usize = 4096;

                        // Align the start address properly
                        let aligned_start = (region.base_address + alignment - 1) & !(alignment - 1);
                        let offset = aligned_start - region.base_address;

                        if offset < region.size {
                            let adjusted_size = region.size - offset;
                            
                            for chunk_offset in (0..adjusted_size).step_by(CHUNK_SIZE) {
                                let chunk_addr = aligned_start + chunk_offset;
                                let chunk_size = std::cmp::min(CHUNK_SIZE, adjusted_size - chunk_offset);

                                if let Ok(()) = scanner.validate_memory_region(chunk_addr, chunk_size) {
                                    if let Ok(current_data) = scanner.safe_read_memory(chunk_addr, chunk_size, &stats_clone) {
                                        // Scan the chunk for matches
                                        for offset in (0..chunk_size).step_by(type_size) {
                                            if chunk_addr + offset + type_size <= chunk_addr + chunk_size {
                                                let value_slice = &current_data[offset..offset + type_size];
                                                if value_slice == target_value {
                                                    results.insert(chunk_addr + offset, value_slice.to_vec());
                                                    stats_clone.matches_found.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                stats_clone.bytes_scanned.fetch_add(chunk_size, Ordering::Relaxed);
                            }
                        }
                    }
                    
                    stats_clone.regions_scanned.fetch_add(1, Ordering::Relaxed);
                }
            }

            Ok(results)
        }).await??;

        debug!("Blocking task completed successfully");
        Ok(results)
    }

    fn calculate_total_memory(&self) -> Result<usize> {
        let regions = self.enumerate_memory_regions()?;
        Ok(regions.iter().map(|r| r.size).sum())
    }

    fn report_progress(&self, stats: &ScanStats, current_address: usize, total_memory: usize) {
        let progress = ScanProgressUpdate {
            regions_scanned: stats.regions_scanned.load(Ordering::Relaxed),
            bytes_scanned: stats.bytes_scanned.load(Ordering::Relaxed),
            matches_found: stats.matches_found.load(Ordering::Relaxed),
            current_address,
            total_memory,
        };

        let percent = (progress.bytes_scanned as f64 / total_memory as f64 * 100.0) as u32;
        debug!("Scan progress: {}% ({}/{} bytes, {} matches)", 
            percent,
            progress.bytes_scanned,
            total_memory,
            progress.matches_found
        );
    }

    pub async fn scan_with_timeout(
        &self,
        options: ScanOptions,
        duration: Duration
    ) -> Result<HashMap<usize, Vec<u8>>> {
        match timeout(duration, self.scan_with_options(options, None)).await {
            Ok(result) => result,
            Err(_) => {
                debug!("Scan timed out after {:?}", duration);
                Err(MemoryError::MemoryOperation("Scan timed out".to_string()))
            }
        }
    }

    fn cleanup_cancelled_scan_sync(&self, stats: &ScanStats) -> Result<()> {
        debug!("Cleaning up cancelled scan...");
        debug!("Scanned {} regions, {} bytes, found {} matches",
            stats.regions_scanned.load(Ordering::Relaxed),
            stats.bytes_scanned.load(Ordering::Relaxed),
            stats.matches_found.load(Ordering::Relaxed)
        );
        
        if stats.errors.read_errors.load(Ordering::Relaxed) > 0 {
            debug!("Encountered {} read errors", 
                stats.errors.read_errors.load(Ordering::Relaxed));
        }

        // Clear cache synchronously
        if let Ok(mut cache) = self.region_cache.lock() {
            cache.clear();
        }
        
        Ok(())
    }

    fn new_scanner(&self) -> Self {
        Self {
            process_handle: Arc::clone(&self.process_handle),
            region_cache: Arc::clone(&self.region_cache),
        }
    }

    fn read_memory_raw(&self, address: usize, buffer: &mut [u8]) -> Result<()> {
        self.validate_address(address, buffer.len())?;
        self.validate_memory_region(address, buffer.len())?;

        let bytes_read = &mut 0;
        let success = unsafe {
            ReadProcessMemory(
                self.process_handle.0,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                bytes_read,
            )
        };

        if success == 0 {
            let error_code = unsafe { GetLastError() };
            debug!("ReadProcessMemory failed at {:#x}: error code {}", address, error_code);
            return Err(MemoryError::MemoryOperation(
                format!("Failed to read memory at {:#x} (Error code: {})", address, error_code)
            ));
        }

        if *bytes_read != buffer.len() {
            debug!("Partial read at {:#x}: {} of {} bytes", address, bytes_read, buffer.len());
        }

        Ok(())
    }

    pub fn write_memory_raw(&self, address: usize, buffer: &[u8]) -> Result<()> {
        // Add validation before writing
        self.validate_address(address, buffer.len())?;
        
        let bytes_written = &mut 0;

        let success = unsafe {
            WriteProcessMemory(
                self.process_handle.0,
                address as *mut _,
                buffer.as_ptr() as *const _,
                buffer.len(),
                bytes_written,
            )
        };

        if success == 0 {
            return Err(MemoryError::MemoryOperation(format!(
                "Failed to write raw memory at address: {:#x}",
                address
            )));
        }

        Ok(())
    }

    fn validate_memory_region(&self, address: usize, size: usize) -> Result<()> {
        let region = self.get_memory_region(address)?;
        
        // Check if region is an image (DLL/executable) section
        if region.type_ == MEM_IMAGE {
            return Err(MemoryError::MemoryOperation(
                format!("Memory at {:#x} is in image section", address)
            ));
        }
        
        // Check if address is within region bounds
        if address < region.base_address || 
           address + size > region.base_address + region.size {
            return Err(MemoryError::MemoryOperation(
                format!("Memory range {:#x}-{:#x} crosses region boundary", 
                    address, address + size)
            ));
        }

        // Validate protection flags
        if region.protection & PAGE_GUARD != 0 {
            return Err(MemoryError::MemoryOperation(
                format!("Memory at {:#x} is guard page", address)
            ));
        }

        if region.protection & PAGE_NOACCESS != 0 {
            return Err(MemoryError::MemoryOperation(
                format!("Memory at {:#x} is not accessible", address)
            ));
        }

        if !self.is_readable_region(region.protection) {
            return Err(MemoryError::MemoryOperation(
                format!("Memory at {:#x} is not readable", address)
            ));
        }

        // Validate memory state
        if region.state != MEM_COMMIT {
            return Err(MemoryError::MemoryOperation(
                format!("Memory at {:#x} is not committed", address)
            ));
        }

        Ok(())
    }

    fn handle_read_error(&self, error: MemoryError, address: usize, size: usize, stats: &ScanStats) {
        match error {
            MemoryError::InvalidProtection(_) => {
                debug!("Protection error at {:#x}: {}", address, error);
                stats.errors.protection_errors.fetch_add(1, Ordering::Relaxed);
            },
            MemoryError::AlignmentError(addr, align) => {
                debug!("Alignment error at {:#x}: required {} bytes", addr, align);
                stats.errors.alignment_errors.fetch_add(1, Ordering::Relaxed);
            },
            MemoryError::MemoryOperation(msg) if msg.contains("boundary") => {
                debug!("Region boundary violation: {:#x}-{:#x}", address, address + size);
                stats.errors.boundary_errors.fetch_add(1, Ordering::Relaxed);
            },
            _ => {
                debug!("Memory error at {:#x}: {}", address, error);
                stats.errors.read_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn handle_validation_error(&self, error: &MemoryError, address: usize, size: usize, stats: &ScanStats) {
        match error {
            MemoryError::InvalidProtection(_) => {
                stats.errors.protection_errors.fetch_add(1, Ordering::Relaxed);
                debug!("Protection violation at {:#x}", address);
            },
            MemoryError::MemoryOperation(msg) if msg.contains("boundary") => {
                stats.errors.boundary_errors.fetch_add(1, Ordering::Relaxed);
                debug!("Region boundary violation: {:#x}-{:#x}", address, address + size);
            },
            MemoryError::AlignmentError(addr, align) => {
                stats.errors.alignment_errors.fetch_add(1, Ordering::Relaxed);
                debug!("Alignment error at {:#x}: required {}", addr, align);
            },
            _ => {
                stats.errors.read_errors.fetch_add(1, Ordering::Relaxed);
                debug!("Memory error at {:#x}: {}", address, error);
            }
        }
    }

    fn safe_read_memory(&self, address: usize, size: usize, stats: &ScanStats) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        
        let result = unsafe {
            ReadProcessMemory(
                self.process_handle.0,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                std::ptr::null_mut(),
            )
        };

        if result == 0 {
            let error = unsafe { GetLastError() };
            // Only log read errors
            debug!("Memory read failed at {:#x}: error {}", address, error);
            stats.errors.read_errors.fetch_add(1, Ordering::Relaxed);
            return Err(MemoryError::MemoryOperation(
                format!("Failed to read memory at {:#x}: error {}", address, error)
            ));
        }

        Ok(buffer)
    }
}

#[derive(Debug)]
pub struct ScanStats {
    pub regions_scanned: AtomicUsize,
    pub bytes_scanned: AtomicUsize,
    pub matches_found: AtomicUsize,
    pub errors: ScanErrorStats,
    pub last_update: Mutex<Instant>,
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            regions_scanned: AtomicUsize::new(0),
            bytes_scanned: AtomicUsize::new(0),
            matches_found: AtomicUsize::new(0),
            errors: ScanErrorStats::new(),
            last_update: Mutex::new(Instant::now()),
        }
    }
}

#[derive(Debug)]
struct RegionCache {
    regions: BTreeMap<usize, MemoryRegionInfo>,
    last_update: Instant,
    cache_duration: Duration,
}

impl RegionCache {
    fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            last_update: Instant::now(),
            cache_duration: Duration::from_secs(1),
        }
    }

    fn validate_cache(&self) -> bool {
        self.last_update.elapsed() < self.cache_duration
    }

    fn update(&mut self, regions: Vec<MemoryRegionInfo>) {
        self.regions.clear();
        for region in regions {
            self.regions.insert(region.base_address, region);
        }
        self.last_update = Instant::now();
    }

    fn clear(&mut self) {
        self.regions.clear();
        self.last_update = Instant::now();
    }
}

#[derive(Debug)]
pub struct ScanProgressUpdate {
    pub regions_scanned: usize,
    pub bytes_scanned: usize,
    pub matches_found: usize,
    pub current_address: usize,
    pub total_memory: usize,
}

pub struct ScanProgressSender {
    tx: mpsc::Sender<ScanProgressUpdate>,
}

pub struct ScanProgressReceiver {
    rx: mpsc::Receiver<ScanProgressUpdate>,
}

impl MemoryScanner {
    pub async fn scan_with_progress(
        &self,
        options: ScanOptions,
        progress_tx: mpsc::Sender<ScanProgressUpdate>
    ) -> Result<HashMap<usize, Vec<u8>>> {
        self.scan_with_options(options, Some(Box::new(progress_tx))).await
    }
}

#[derive(Debug)]
pub enum ScanError {
    InvalidRegion(usize),
    ReadError { address: usize, error: MemoryError },
    ComparisonError { address: usize, data_type: DataType },
    AlignmentError { address: usize, required: usize },
    ProtectionError { address: usize, protection: u32 },
    BoundaryError { address: usize, size: usize },
    Cancelled,
    Timeout(Duration),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRegion(addr) => write!(f, "Invalid memory region at {:#x}", addr),
            Self::ReadError { address, error } => write!(f, "Failed to read memory at {:#x}: {}", address, error),
            Self::ComparisonError { address, data_type } => write!(f, "Failed to compare values at {:#x} of type {:?}", address, data_type),
            Self::AlignmentError { address, required } => write!(f, "Address {:#x} not aligned to {} bytes", address, required),
            Self::ProtectionError { address, protection } => write!(f, "Invalid protection {:#x} at address {:#x}", protection, address),
            Self::BoundaryError { address, size } => write!(f, "Memory range {:#x}-{:#x} crosses region boundary", address, address + size),
            Self::Cancelled => write!(f, "Scan cancelled by user"),
            Self::Timeout(duration) => write!(f, "Scan timed out after {:?}", duration),
        }
    }
}

impl From<ScanError> for MemoryError {
    fn from(error: ScanError) -> Self {
        MemoryError::MemoryOperation(error.to_string())
    }
}

#[derive(Debug)]
pub struct ScanStatistics {
    pub duration: Duration,
    pub regions_scanned: usize,
    pub bytes_scanned: usize,
    pub matches_found: usize,
    pub errors_encountered: usize,
}

impl MemoryScanner {
    fn collect_scan_statistics(&self, stats: &ScanStats, start_time: Instant) -> ScanStatistics {
        ScanStatistics {
            duration: start_time.elapsed(),
            regions_scanned: stats.regions_scanned.load(Ordering::Relaxed),
            bytes_scanned: stats.bytes_scanned.load(Ordering::Relaxed),
            matches_found: stats.matches_found.load(Ordering::Relaxed),
            errors_encountered: stats.errors.read_errors.load(Ordering::Relaxed) +
                stats.errors.comparison_errors.load(Ordering::Relaxed) +
                stats.errors.protection_errors.load(Ordering::Relaxed) +
                stats.errors.alignment_errors.load(Ordering::Relaxed) +
                stats.errors.boundary_errors.load(Ordering::Relaxed),
        }
    }

    pub async fn scan_with_statistics(
        &self,
        options: ScanOptions,
    ) -> Result<(HashMap<usize, Vec<u8>>, ScanStatistics)> {
        let start_time = Instant::now();
        let results = self.scan_with_options(options, None).await?;
        let stats = self.collect_scan_statistics(&ScanStats::new(), start_time);
        Ok((results, stats))
    }
}

#[derive(Debug)]
pub struct ScanCheckpoint {
    pub last_address: usize,
    pub results: HashMap<usize, Vec<u8>>,
    pub statistics: ScanStatistics,
}

impl MemoryScanner {
    pub async fn resume_scan(
        &self,
        options: ScanOptions,
        checkpoint: ScanCheckpoint,
    ) -> Result<HashMap<usize, Vec<u8>>> {
        let options = options;
        let mut results = checkpoint.results;
        
        let results_from_checkpoint = self.scan_with_options(options, None).await?;
        
        results.extend(results_from_checkpoint);
        
        Ok(results)
    }
}

#[derive(Debug)]
pub struct ScanErrorStats {
    pub read_errors: AtomicUsize,
    pub comparison_errors: AtomicUsize,
    pub protection_errors: AtomicUsize,
    pub alignment_errors: AtomicUsize,
    pub boundary_errors: AtomicUsize,
}

impl ScanErrorStats {
    fn new() -> Self {
        Self {
            read_errors: AtomicUsize::new(0),
            comparison_errors: AtomicUsize::new(0),
            protection_errors: AtomicUsize::new(0),
            alignment_errors: AtomicUsize::new(0),
            boundary_errors: AtomicUsize::new(0),
        }
    }
}

impl MemoryScanner {
    async fn handle_scan_cancellation(
        &self,
        stats: &ScanStats,
        progress_handler: Option<&Box<dyn ScanProgressHandler>>,
        total_memory: usize
    ) -> Result<()> {
        debug!("Handling scan cancellation...");
        
        // Send final progress update if handler is available
        if let Some(handler) = progress_handler {
            let final_progress = ScanProgressUpdate {
                regions_scanned: stats.regions_scanned.load(Ordering::Relaxed),
                bytes_scanned: stats.bytes_scanned.load(Ordering::Relaxed),
                matches_found: stats.matches_found.load(Ordering::Relaxed),
                current_address: 0,
                total_memory,
            };

            handler.update(final_progress)?;
        }

        Ok(())
    }

    async fn cleanup_scan_resources(&self) -> Result<()> {
        // Implement resource cleanup
        debug!("Cleaning up scan resources...");
        
        // Reset any cached data
        if let Ok(mut cache) = self.region_cache.lock() {
            cache.clear();
        }

        // Yield to allow other tasks to run
        task::yield_now().await;
        
        Ok(())
    }
}

// Add type-safe comparison trait and result struct
#[derive(Debug)]
pub struct ComparisonResult {
    pub is_equal: bool,
    pub is_greater: bool,
    pub is_less: bool,
    pub current_value: String,
    pub target_value: String,
}

pub trait TypedComparison: Sized {
    fn compare_values(current: &[u8], target: &[u8]) -> Option<ComparisonResult>;
    fn size() -> usize;
    fn alignment() -> usize;
}

// Implement for numeric types
macro_rules! impl_typed_comparison {
    ($type:ty) => {
        impl TypedComparison for $type {
            fn compare_values(current: &[u8], target: &[u8]) -> Option<ComparisonResult> {
                if current.len() != std::mem::size_of::<$type>() || 
                   target.len() != std::mem::size_of::<$type>() {
                    return None;
                }

                let current_val = <$type>::from_ne_bytes(current.try_into().ok()?);
                let target_val = <$type>::from_ne_bytes(target.try_into().ok()?);

                Some(ComparisonResult {
                    is_equal: current_val == target_val,
                    is_greater: current_val > target_val,
                    is_less: current_val < target_val,
                    current_value: format!("{:?}", current_val),
                    target_value: format!("{:?}", target_val),
                })
            }

            fn size() -> usize {
                std::mem::size_of::<$type>()
            }

            fn alignment() -> usize {
                std::mem::align_of::<$type>()
            }
        }
    };
}

impl_typed_comparison!(u8);
impl_typed_comparison!(u16);
impl_typed_comparison!(u32);
impl_typed_comparison!(u64);
impl_typed_comparison!(i8);
impl_typed_comparison!(i16);
impl_typed_comparison!(i32);
impl_typed_comparison!(i64);
impl_typed_comparison!(f32);
impl_typed_comparison!(f64);

trait ShouldUpdate {
    fn should_update(&self) -> bool;
}

impl ShouldUpdate for ScanStats {
    fn should_update(&self) -> bool {
        // Use a mutex-protected last update time instead of static AtomicU64
        let mut last_update = self.last_update.lock().unwrap();
        let now = Instant::now();
        
        if now.duration_since(*last_update) >= Duration::from_millis(100) {
            *last_update = now;
            true
        } else {
            false
        }
    }
}

impl From<tokio::sync::watch::error::RecvError> for MemoryError {
    fn from(error: tokio::sync::watch::error::RecvError) -> Self {
        MemoryError::MemoryOperation(format!("Cancel signal error: {}", error))
    }
}

// Add missing ScanProgressHandler trait
pub trait ScanProgressHandler: Send + Sync {
    fn update(&self, progress: ScanProgressUpdate) -> Result<()>;
}

// Implement for mpsc::Sender
impl ScanProgressHandler for mpsc::Sender<ScanProgressUpdate> {
    fn update(&self, progress: ScanProgressUpdate) -> Result<()> {
        self.try_send(progress).map_err(|e| {
            MemoryError::MemoryOperation(format!("Failed to send progress update: {}", e))
        })
    }
} 