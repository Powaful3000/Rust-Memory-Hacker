use crate::error::{MemoryError, Result};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualQueryEx};
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_GUARD, MEM_COMMIT, MEM_IMAGE};
use winapi::um::errhandlingapi::GetLastError;
use std::collections::HashMap;
use tokio::task;
use std::sync::Arc;
use tracing::debug;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanType {
    ExactValue,
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

#[allow(dead_code)]
pub struct ScanProgress {
    pub regions_scanned: AtomicUsize,
    pub bytes_scanned: AtomicUsize,
    pub matches_found: AtomicUsize,
    pub errors: ScanErrorStats,
    pub last_update: Mutex<Instant>,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub struct ScanContext {
    pub progress: ScanProgress,
    pub cancel: tokio::sync::watch::Receiver<bool>,
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

#[allow(dead_code)]
impl ScanType {
    pub fn requires_previous_results(&self) -> bool {
        false
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
            ScanType::ExactValue => {}
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
#[allow(dead_code)]
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
    pub fn new(handle: HANDLE) -> Self {
        Self {
            process_handle: Arc::new(ThreadSafeHandle(handle)),
        }
    }

    pub fn validate_address(&self, address: usize, _size: usize) -> Result<()> {
        if address == 0 {
            return Err(MemoryError::InvalidAddress(address));
        }
        
        // Add basic alignment check
        if address % std::mem::align_of::<usize>() != 0 {
            return Err(MemoryError::AlignmentError(
                address,
                std::mem::align_of::<usize>()
            ));
        }
        
        Ok(())
    }

    pub fn read_memory<T: Copy>(&self, address: usize) -> Result<T> {
        let mut buffer = vec![0u8; std::mem::size_of::<T>()];
        self.read_memory_raw(address, &mut buffer)?;
        let value = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr() as *const T)
        };
        Ok(value)
    }

    pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> Result<()> {
        let buffer = unsafe {
            std::slice::from_raw_parts(
                value as *const T as *const u8,
                std::mem::size_of::<T>(),
            )
        };
        self.write_memory_raw(address, buffer)
    }

    pub async fn scan_memory(
        &self,
        value: Vec<u8>,
        scan_type: ScanType,
        data_type: DataType,
        previous_results: Option<HashMap<usize, Vec<u8>>>,
    ) -> Result<HashMap<usize, Vec<u8>>> {
        let options = ScanOptions {
            value,
            scan_type,
            data_type,
            previous_results,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        
        self.scan_with_options(options, None).await
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
                for (address, _prev_value) in previous_results {
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
pub struct ScanProgressUpdate {
    pub regions_scanned: usize,
    pub bytes_scanned: usize,
    pub matches_found: usize,
    pub current_address: usize,
    pub total_memory: usize,
}

#[allow(dead_code)]
pub struct ScanProgressSender {
    tx: mpsc::Sender<ScanProgressUpdate>,
}

#[allow(dead_code)]
pub struct ScanProgressReceiver {
    rx: mpsc::Receiver<ScanProgressUpdate>,
}

impl MemoryScanner {
    #[allow(dead_code)]
    pub async fn scan_with_progress(
        &self,
        options: ScanOptions,
        progress_tx: mpsc::Sender<ScanProgressUpdate>
    ) -> Result<HashMap<usize, Vec<u8>>> {
        self.scan_with_options(options, Some(Box::new(progress_tx))).await
    }

    #[allow(dead_code)]
    pub async fn scan_with_statistics(
        &self,
        options: ScanOptions,
    ) -> Result<(HashMap<usize, Vec<u8>>, ScanStatistics)> {
        let start_time = Instant::now();
        let results = self.scan_with_options(options, None).await?;
        let stats = ScanStatistics {
            duration: start_time.elapsed(),
            regions_scanned: 0, // Update with actual values
            bytes_scanned: 0,
            matches_found: results.len(),
            errors_encountered: 0,
        };
        Ok((results, stats))
    }

    #[allow(dead_code)]
    pub async fn resume_scan(
        &self,
        options: ScanOptions,
        checkpoint: ScanCheckpoint,
    ) -> Result<HashMap<usize, Vec<u8>>> {
        let mut results = checkpoint.results;
        let results_from_checkpoint = self.scan_with_options(options, None).await?;
        results.extend(results_from_checkpoint);
        Ok(results)
    }

    #[allow(dead_code)]
    async fn handle_scan_cancellation(
        &self,
        stats: &ScanStats,
        progress_handler: Option<&Box<dyn ScanProgressHandler>>,
        total_memory: usize
    ) -> Result<()> {
        debug!("Handling scan cancellation...");
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

    #[allow(dead_code)]
    async fn cleanup_scan_resources(&self) -> Result<()> {
        debug!("Cleaning up scan resources...");
        Ok(())
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

#[derive(Debug)]
pub struct ScanStatistics {
    pub duration: Duration,
    pub regions_scanned: usize,
    pub bytes_scanned: usize,
    pub matches_found: usize,
    pub errors_encountered: usize,
}

#[derive(Debug)]
pub struct ScanCheckpoint {
    pub last_address: usize,
    pub results: HashMap<usize, Vec<u8>>,
    pub statistics: ScanStatistics,
} 