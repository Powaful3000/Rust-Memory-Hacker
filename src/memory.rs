use crate::error::{MemoryError, Result};
use std::mem;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualQueryEx};
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_GUARD, MEM_COMMIT};
use std::collections::HashMap;
use tokio::task;
use std::sync::Arc;
use tracing::debug;
use std::cmp::PartialOrd;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use winapi::shared::minwindef::DWORD;

const ERROR_ACCESS_DENIED: DWORD = 5;

#[derive(Debug, Clone, Copy)]
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
}

#[derive(Debug)]
pub struct ScanProgress {
    pub regions_scanned: usize,
    pub bytes_scanned: usize,
    pub matches_found: usize,
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

    pub async fn scan_memory_with_cancel<T: Copy + PartialEq + Send + Sync + 'static>(
        self,
        value: T,
        scan_type: ScanType,
        data_type: DataType,
        previous_results: Option<HashMap<usize, Vec<u8>>>,
        _cancel: tokio::sync::watch::Receiver<bool>
    ) -> Result<HashMap<usize, Vec<u8>>> {
        debug!("Starting memory scan with {:?}", scan_type);
        
        let value_bytes = unsafe {
            std::slice::from_raw_parts(
                &value as *const T as *const u8,
                std::mem::size_of::<T>()
            ).to_vec()
        };

        let options = ScanOptions {
            scan_type,
            data_type,
            value: value_bytes,
            previous_results,
            cancel: Arc::new(AtomicBool::new(false)),
        };

        self.scan_with_options(options).await
    }

    fn scan_region(
        &self,
        address: usize,
        size: usize,
        value: &[u8],
        data_type: DataType,
        scan_type: ScanType,
        previous_results: Option<&HashMap<usize, Vec<u8>>>,
        results: &mut HashMap<usize, Vec<u8>>,
        stats: &ScanStats,
    ) -> Result<()> {
        debug!("Scanning region at {:#x} with size {} bytes", address, size);
        debug!("Protection flags: {:#x}", self.get_region_permissions(address)?);
        debug!("Data type: {:?}, Scan type: {:?}", data_type, scan_type);

        const CHUNK_SIZE: usize = 4096;
        let mut buffer = vec![0u8; std::cmp::min(CHUNK_SIZE, size)];

        for chunk_start in (0..size).step_by(CHUNK_SIZE) {
            let chunk_size = std::cmp::min(CHUNK_SIZE, size - chunk_start);
            let chunk_addr = address + chunk_start;
            buffer.resize(chunk_size, 0);
            
            debug!("Scanning chunk at {:#x} with size {} bytes", chunk_addr, chunk_size);
            
            match self.read_memory_raw(chunk_addr, &mut buffer) {
                Ok(_) => {
                    let matches_before = results.len();
                    for offset in (0..chunk_size).step_by(data_type.size()) {
                        if offset + data_type.size() > chunk_size {
                            break;
                        }

                        let addr = chunk_addr + offset;
                        let current = &buffer[offset..offset + data_type.size()];

                        if let Some(comparison_result) = self.compare_bytes(current, value, data_type) {
                            debug!("Value comparison at {:#x}: {:?}", addr, comparison_result);
                        }

                        let matches = match scan_type {
                            ScanType::ExactValue => current == value,
                            ScanType::Changed => {
                                if let Some(prev_map) = previous_results {
                                    if let Some(old) = prev_map.get(&addr) {
                                        current != old
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            },
                            ScanType::Increased => {
                                if let (Some(prev_map), Some(comparison)) = (previous_results, self.compare_bytes(current, value, data_type)) {
                                    if let Some(old) = prev_map.get(&addr) {
                                        if let Some(old_comparison) = self.compare_bytes(old, value, data_type) {
                                            comparison.is_greater
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            },
                            ScanType::Decreased => {
                                if let (Some(prev_map), Some(comparison)) = (previous_results, self.compare_bytes(current, value, data_type)) {
                                    if let Some(old) = prev_map.get(&addr) {
                                        if let Some(old_comparison) = self.compare_bytes(old, value, data_type) {
                                            comparison.is_less
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            },
                            ScanType::Unchanged => {
                                if let Some(prev_map) = previous_results {
                                    if let Some(old) = prev_map.get(&addr) {
                                        current == old
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            },
                        };

                        if matches {
                            results.insert(addr, current.to_vec());
                        }
                    }
                    
                    let new_matches = results.len() - matches_before;
                    if new_matches > 0 {
                        debug!("Found {} matches in chunk at {:#x}", new_matches, chunk_addr);
                    }
                    stats.matches_found.fetch_add(new_matches, Ordering::Relaxed);
                },
                Err(e) => {
                    debug!("Failed to read chunk at {:#x}: {}", chunk_addr, e);
                    stats.errors.read_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }

    // Add a new method for the menu to use
    pub async fn scan_memory(
        &self,
        value: Vec<u8>,
        scan_type: ScanType,
        data_type: DataType,
        previous_results: Option<HashMap<usize, Vec<u8>>>
    ) -> Result<HashMap<usize, Vec<u8>>> {
        let cancel = Arc::new(AtomicBool::new(false));
        let options = ScanOptions {
            scan_type,
            data_type,
            value,
            previous_results,
            cancel,
        };
        self.scan_with_options(options).await
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
        })
    }

    fn read_memory_partial(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        const PAGE_SIZE: usize = 4096;
        let mut result = Vec::with_capacity(size);
        
        for offset in (0..size).step_by(PAGE_SIZE) {
            let chunk_size = std::cmp::min(PAGE_SIZE, size - offset);
            let chunk_addr = address + offset;
            
            match self.get_memory_region(chunk_addr) {
                Ok(region) if self.is_readable_region(region.protection) => {
                    let mut buffer = vec![0u8; chunk_size];
                    match self.read_memory_raw(chunk_addr, &mut buffer) {
                        Ok(_) => result.extend_from_slice(&buffer),
                        Err(e) => {
                            debug!("Failed to read chunk at {:#x}: {}", chunk_addr, e);
                            result.extend(std::iter::repeat(0).take(chunk_size));
                        }
                    }
                },
                _ => {
                    // Fill unreadable regions with zeros
                    result.extend(std::iter::repeat(0).take(chunk_size));
                }
            }
        }
        
        Ok(result)
    }

    pub fn enumerate_memory_regions(&self) -> Result<Vec<MemoryRegionInfo>> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        
        while let Ok(region) = self.get_memory_region(address) {
            if region.state == MEM_COMMIT {
                regions.push(region.clone());
            }
            
            // Handle potential overflow
            if let Some(next_addr) = region.base_address.checked_add(region.size) {
                address = next_addr;
            } else {
                break;
            }
        }
        
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

    fn update_scan_progress(&self, progress: &mut ScanProgress, region_size: usize, matches: usize) {
        progress.regions_scanned += 1;
        progress.bytes_scanned += region_size;
        progress.matches_found += matches;
        
        debug!("Progress: {} regions, {} bytes, {} matches", 
            progress.regions_scanned,
            progress.bytes_scanned,
            progress.matches_found
        );
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

    pub async fn scan_with_options(&self, options: ScanOptions) -> Result<HashMap<usize, Vec<u8>>> {
        let options = options;
        options.validate()?;
        debug!("Starting memory scan with {:?} for type {:?}", 
            options.scan_type, options.data_type);

        let stats = Arc::new(ScanStats::new());
        let stats_clone = Arc::clone(&stats);
        let handle = Arc::clone(&self.process_handle);
        let scanner = self.clone(); // Clone self to move into closure

        let results = task::spawn_blocking(move || -> Result<HashMap<usize, Vec<u8>>> {
            let mut results = HashMap::new();
            let mut address = 0usize;
            
            while !options.cancel.load(Ordering::Relaxed) {
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                
                let result = unsafe {
                    VirtualQueryEx(
                        handle.0,
                        address as *const _,
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                    )
                };

                if result == 0 {
                    break;
                }

                if mbi.State == MEM_COMMIT {
                    let scanner = scanner.new_scanner();
                    if scanner.is_readable_region(mbi.Protect) {
                        let region_size = mbi.RegionSize;
                        let base_addr = mbi.BaseAddress as usize;
                        
                        let value_bytes = scanner.read_memory_partial(base_addr, region_size)?;
                        scanner.scan_region(
                            base_addr,
                            region_size,
                            &value_bytes,
                            options.data_type,
                            options.scan_type,
                            options.previous_results.as_ref(),
                            &mut results,
                            &stats_clone
                        )?;
                        
                        stats_clone.regions_scanned.fetch_add(1, Ordering::Relaxed);
                        stats_clone.bytes_scanned.fetch_add(region_size, Ordering::Relaxed);
                    }
                }
                
                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
                
                if options.cancel.load(Ordering::Relaxed) {
                    debug!("Scan cancelled");
                    break;
                }
            }

            Ok(results)
        }).await??;

        debug!("Scan complete: {} matches found", results.len());
        Ok(results)
    }

    fn compare_bytes(&self, current: &[u8], value: &[u8], data_type: DataType) -> Option<ComparisonResult> {
        if current.len() != value.len() {
            debug!("Size mismatch in comparison: current={}, value={}", current.len(), value.len());
            return None;
        }

        match data_type {
            DataType::U8 => self.compare_numeric::<u8>(current, value),
            DataType::U16 => self.compare_numeric::<u16>(current, value),
            DataType::U32 => self.compare_numeric::<u32>(current, value),
            DataType::U64 => self.compare_numeric::<u64>(current, value),
            DataType::I8 => self.compare_numeric::<i8>(current, value),
            DataType::I16 => self.compare_numeric::<i16>(current, value),
            DataType::I32 => self.compare_numeric::<i32>(current, value),
            DataType::I64 => self.compare_numeric::<i64>(current, value),
            DataType::F32 => self.compare_numeric::<f32>(current, value),
            DataType::F64 => self.compare_numeric::<f64>(current, value),
        }
    }

    fn compare_numeric<T>(&self, current: &[u8], value: &[u8]) -> Option<ComparisonResult> 
    where
        T: Copy + PartialOrd + FromBytes + std::fmt::Debug,
    {
        let current_val = T::from_bytes(current)?;
        let value_val = T::from_bytes(value)?;

        Some(ComparisonResult {
            is_equal: current_val == value_val,
            is_greater: current_val > value_val,
            is_less: current_val < value_val,
            current_value: format!("{:?}", current_val),
            target_value: format!("{:?}", value_val),
        })
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
        match timeout(duration, self.scan_with_options(options)).await {
            Ok(result) => result,
            Err(_) => {
                debug!("Scan timed out after {:?}", duration);
                Err(MemoryError::MemoryOperation("Scan timed out".to_string()))
            }
        }
    }

    async fn cleanup_cancelled_scan(&self, stats: &ScanStats) -> Result<()> {
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
            let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
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
        
        if !self.is_readable_region(region.protection) {
            debug!("Region at {:#x} is not readable (protection: {:#x})", 
                address, region.protection);
            return Err(MemoryError::InvalidProtection(address));
        }

        if address + size > region.base_address + region.size {
            debug!("Access would cross region boundary at {:#x}", address);
            return Err(MemoryError::MemoryOperation(
                format!("Memory access would cross region boundary at {:#x}", address)
            ));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ScanStats {
    pub regions_scanned: AtomicUsize,
    pub bytes_scanned: AtomicUsize,
    pub matches_found: AtomicUsize,
    pub errors: ScanErrorStats,
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            regions_scanned: AtomicUsize::new(0),
            bytes_scanned: AtomicUsize::new(0),
            matches_found: AtomicUsize::new(0),
            errors: ScanErrorStats {
                read_errors: AtomicUsize::new(0),
                comparison_errors: AtomicUsize::new(0),
                protection_errors: AtomicUsize::new(0),
            },
        }
    }
}

impl MemoryScanner {
    fn update_scan_stats(&self, stats: &ScanStats, region_size: usize, matches: usize) {
        stats.regions_scanned.fetch_add(1, Ordering::Relaxed);
        stats.bytes_scanned.fetch_add(region_size, Ordering::Relaxed);
        stats.matches_found.fetch_add(matches, Ordering::Relaxed);
        
        debug!("Progress: {} regions, {} bytes, {} matches", 
            stats.regions_scanned.load(Ordering::Relaxed),
            stats.bytes_scanned.load(Ordering::Relaxed),
            stats.matches_found.load(Ordering::Relaxed)
        );
    }
}

#[derive(Debug)]
pub struct RegionCache {
    regions: BTreeMap<usize, MemoryRegionInfo>,
    last_update: std::time::Instant,
}

impl RegionCache {
    const CACHE_DURATION: Duration = Duration::from_secs(1);

    fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            last_update: std::time::Instant::now(),
        }
    }

    fn validate_cache(&self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_update) > Duration::from_secs(1) {
            debug!("Region cache is stale, needs refresh");
            return false;
        }
        true
    }

    fn update(&mut self, regions: Vec<MemoryRegionInfo>) {
        debug!("Updating region cache with {} regions", regions.len());
        self.regions.clear();
        for region in regions {
            self.regions.insert(region.base_address, region);
        }
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
        let total_memory = self.calculate_total_memory()?;
        let stats = Arc::new(ScanStats::new());
        let stats_clone = Arc::clone(&stats);
        let progress_tx = Arc::new(progress_tx);
        let progress_tx_clone = Arc::clone(&progress_tx);
        let scanner = self.clone(); // Clone self to move into closure

        let results = task::spawn_blocking(move || -> Result<HashMap<usize, Vec<u8>>> {
            let mut results = HashMap::new();
            let mut address = 0usize;
            
            while !options.cancel.load(Ordering::Relaxed) {
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                
                let result = unsafe {
                    VirtualQueryEx(
                        scanner.process_handle.0,  // Use scanner instead of self
                        address as *const _,
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                    )
                };

                if result == 0 {
                    break;
                }

                if mbi.State == MEM_COMMIT {
                    let scanner = scanner.new_scanner();
                    if scanner.is_readable_region(mbi.Protect) {
                        let region_size = mbi.RegionSize;
                        let base_addr = mbi.BaseAddress as usize;
                        
                        let value_bytes = scanner.read_memory_partial(base_addr, region_size)?;
                        scanner.scan_region(
                            base_addr,
                            region_size,
                            &value_bytes,
                            options.data_type,
                            options.scan_type,
                            options.previous_results.as_ref(),
                            &mut results,
                            &stats_clone
                        )?;
                        
                        stats_clone.regions_scanned.fetch_add(1, Ordering::Relaxed);
                        stats_clone.bytes_scanned.fetch_add(region_size, Ordering::Relaxed);
                    }
                }
                
                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
                
                if options.cancel.load(Ordering::Relaxed) {
                    debug!("Scan cancelled");
                    break;
                }

                // Update progress periodically
                if stats_clone.bytes_scanned.load(Ordering::Relaxed) % (1024 * 1024) == 0 {
                    let progress = ScanProgressUpdate {
                        regions_scanned: stats_clone.regions_scanned.load(Ordering::Relaxed),
                        bytes_scanned: stats_clone.bytes_scanned.load(Ordering::Relaxed),
                        matches_found: stats_clone.matches_found.load(Ordering::Relaxed),
                        current_address: address,
                        total_memory,
                    };
                    
                    if let Err(e) = progress_tx_clone.try_send(progress) {
                        debug!("Failed to send progress update: {}", e);
                    }
                }
            }

            Ok(results)
        }).await??;

        Ok(results)
    }
}

#[derive(Debug)]
pub enum ScanError {
    InvalidRegion(usize),
    ReadError { address: usize, error: MemoryError },
    ComparisonError { address: usize, data_type: DataType },
    Cancelled,
    Timeout(Duration),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRegion(addr) => write!(f, "Invalid memory region at {:#x}", addr),
            Self::ReadError { address, error } => write!(f, "Failed to read memory at {:#x}: {}", address, error),
            Self::ComparisonError { address, data_type } => write!(f, "Failed to compare values at {:#x} of type {:?}", address, data_type),
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
                stats.errors.protection_errors.load(Ordering::Relaxed),
        }
    }

    pub async fn scan_with_statistics(
        &self,
        options: ScanOptions,
    ) -> Result<(HashMap<usize, Vec<u8>>, ScanStatistics)> {
        let start_time = Instant::now();
        let results = self.scan_with_options(options).await?;
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
        
        let results_from_checkpoint = self.scan_with_options(options).await?;
        
        results.extend(results_from_checkpoint);
        
        Ok(results)
    }
}

#[derive(Debug)]
pub struct ScanErrorStats {
    pub read_errors: AtomicUsize,
    pub comparison_errors: AtomicUsize,
    pub protection_errors: AtomicUsize,
}

impl ScanOptions {
    pub fn validate(&self) -> Result<()> {
        // Check value size matches data type
        if self.value.len() != self.data_type.size() {
            return Err(MemoryError::MemoryOperation(
                format!("Value size mismatch: expected {}, got {}", 
                    self.data_type.size(), self.value.len())
            ));
        }

        // Check previous results for comparison scans
        if self.scan_type.requires_previous_results() && self.previous_results.is_none() {
            return Err(MemoryError::MemoryOperation(
                format!("{:?} scan type requires previous results", self.scan_type)
            ));
        }

        Ok(())
    }
}

#[derive(Debug)]
struct ComparisonResult {
    is_equal: bool,
    is_greater: bool,
    is_less: bool,
    current_value: String,
    target_value: String,
}

trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

impl<T> FromBytes for T
where
    T: Copy,
{
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<T>() {
            return None;
        }
        let mut data = Vec::with_capacity(std::mem::size_of::<T>());
        data.extend_from_slice(bytes);
        Some(unsafe { 
            *(data.as_ptr() as *const T)
        })
    }
} 