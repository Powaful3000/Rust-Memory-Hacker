use crate::error::{MemoryError, Result};
use crate::process::Process;
use crate::memory::{MemoryScanner, MemoryScan, TrackedAddress, DataType, ScanType};
use dialoguer::{theme::ColorfulTheme, Select, Input};
use sysinfo::System;
use tracing::{info, error};
use tokio::time::{interval, Duration};
use tokio::sync::mpsc;

pub struct Menu {
    sys: System,
    current_process: Option<(Process, MemoryScanner)>,
    active_scan: Option<MemoryScan>,
    tracked_addresses: Vec<TrackedAddress>,
    freeze_tx: Option<mpsc::Sender<()>>,
}

impl Menu {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
            current_process: None,
            active_scan: None,
            tracked_addresses: Vec::new(),
            freeze_tx: None,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let choices = vec![
                "Select Process",
                "Memory Scanner",
                "Address List",
                "Quit"
            ];

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Main Menu")
                .items(&choices)
                .default(0)
                .interact()
                .unwrap();

            match selection {
                0 => self.select_process().await?,
                1 => self.memory_scanner_menu().await?,
                2 => self.address_list_menu().await?,
                3 => break,
                _ => error!("Invalid selection"),
            }
        }

        Ok(())
    }

    async fn select_process(&mut self) -> Result<()> {
        self.sys.refresh_processes();
        
        let processes: Vec<_> = self.sys
            .processes()
            .values()
            .map(|p| format!("{}: {}", p.pid(), p.name()))
            .collect();

        if let Ok(selection) = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a process")
            .items(&processes)
            .interact()
        {
            let pid = processes[selection]
                .split(':')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| MemoryError::ProcessAccess("Invalid PID".to_string()))?;

            let process = Process::attach(pid)?;
            let scanner = MemoryScanner::new(process.handle());
            self.current_process = Some((process, scanner));
            
            // Start the freeze task when attaching to a new process
            self.start_freeze_task().await?;
            
            info!("Successfully attached to process {}", pid);
        }

        Ok(())
    }

    async fn read_memory(&self) -> Result<()> {
        if let Some((_, scanner)) = &self.current_process {
            let address: usize = Input::new()
                .with_prompt("Enter memory address (hex)")
                .interact_text()
                .map_err(|_| MemoryError::InvalidAddress(0))?;

            match scanner.read_memory::<u32>(address) {
                Ok(value) => info!("Value at {:#x}: {}", address, value),
                Err(e) => error!("Failed to read memory: {}", e),
            }
        } else {
            error!("No process selected!");
        }
        Ok(())
    }

    async fn write_memory(&self) -> Result<()> {
        if let Some((_, scanner)) = &self.current_process {
            let address: usize = Input::new()
                .with_prompt("Enter memory address (hex)")
                .interact_text()
                .map_err(|_| MemoryError::InvalidAddress(0))?;

            let value: u32 = Input::new()
                .with_prompt("Enter value")
                .interact_text()
                .map_err(|_| MemoryError::MemoryOperation("Invalid value".to_string()))?;

            match scanner.write_memory(address, &value) {
                Ok(_) => info!("Successfully wrote {} to {:#x}", value, address),
                Err(e) => error!("Failed to write memory: {}", e),
            }
        } else {
            error!("No process selected!");
        }
        Ok(())
    }

    async fn memory_scanner_menu(&mut self) -> Result<()> {
        if self.current_process.is_none() {
            error!("No process selected!");
            return Ok(());
        }

        loop {
            let choices = vec![
                "New Scan",
                "Next Scan",
                "Add to Address List",
                "Back"
            ];

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Memory Scanner")
                .items(&choices)
                .default(0)
                .interact()
                .unwrap();

            match selection {
                0 => self.new_scan().await?,
                1 => self.next_scan().await?,
                2 => self.add_to_address_list().await?,
                3 => break,
                _ => error!("Invalid selection"),
            }
        }
        Ok(())
    }

    async fn new_scan(&mut self) -> Result<()> {
        if let Some((_, scanner)) = &self.current_process {
            let scanner = scanner.clone();
            
            let data_type_choices = vec![
                "U8 (Unsigned 8-bit)",
                "U16 (Unsigned 16-bit)", 
                "U32 (Unsigned 32-bit)",
                "U64 (Unsigned 64-bit)",
                "I8 (Signed 8-bit)",
                "I16 (Signed 16-bit)",
                "I32 (Signed 32-bit)",
                "I64 (Signed 64-bit)",
                "F32 (32-bit Float)",
                "F64 (64-bit Float)",
            ];

            let data_type = match Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Select data type")
                .items(&data_type_choices)
                .interact()? 
            {
                0 => DataType::U8,
                1 => DataType::U16,
                2 => DataType::U32,
                3 => DataType::U64,
                4 => DataType::I8,
                5 => DataType::I16,
                6 => DataType::I32,
                7 => DataType::I64,
                8 => DataType::F32,
                9 => DataType::F64,
                _ => return Err(MemoryError::MemoryOperation("Invalid data type".to_string())),
            };

            let value_str: String = Input::new()
                .with_prompt("Enter value to scan for")
                .interact_text()?;

            let value_bytes = match data_type {
                DataType::U8 => value_str.parse::<u8>()?.to_ne_bytes().to_vec(),
                DataType::U16 => value_str.parse::<u16>()?.to_ne_bytes().to_vec(),
                DataType::U32 => value_str.parse::<u32>()?.to_ne_bytes().to_vec(),
                DataType::U64 => value_str.parse::<u64>()?.to_ne_bytes().to_vec(),
                DataType::I8 => value_str.parse::<i8>()?.to_ne_bytes().to_vec(),
                DataType::I16 => value_str.parse::<i16>()?.to_ne_bytes().to_vec(),
                DataType::I32 => value_str.parse::<i32>()?.to_ne_bytes().to_vec(),
                DataType::I64 => value_str.parse::<i64>()?.to_ne_bytes().to_vec(),
                DataType::F32 => value_str.parse::<f32>()?.to_ne_bytes().to_vec(),
                DataType::F64 => value_str.parse::<f64>()?.to_ne_bytes().to_vec(),
            };

            let scan_results = scanner.scan_memory(
                value_bytes,
                ScanType::ExactValue,
                data_type,
                None
            ).await?;

            let results_len = scan_results.len();
            self.active_scan = Some(MemoryScan {
                scan_type: ScanType::ExactValue,
                data_type,
                results: scan_results,
            });

            info!("Found {} matches", results_len);
        }
        Ok(())
    }

    async fn next_scan(&mut self) -> Result<()> {
        if let Some((_, scanner)) = &self.current_process {
            let scanner = scanner.clone();
            
            if let Some(prev_scan) = &self.active_scan {
                let value: Option<String> = Input::new()
                    .with_prompt("Enter value (leave empty for unchanged)")
                    .allow_empty(true)
                    .interact_text()
                    .ok();

                let value_bytes = match value {
                    Some(v) => v.parse::<u32>()
                        .map(|n| n.to_ne_bytes().to_vec())
                        .map_err(|_| MemoryError::MemoryOperation("Invalid number".to_string()))?,
                    None => vec![0; 4],
                };

                let results = scanner.scan_memory(
                    value_bytes,
                    prev_scan.scan_type,
                    prev_scan.data_type,
                    Some(prev_scan.results.clone())
                ).await?;

                let results_len = results.len();
                self.active_scan = Some(MemoryScan {
                    scan_type: prev_scan.scan_type,
                    data_type: prev_scan.data_type,
                    results,
                });

                info!("Found {} matches", results_len);
            }
        }
        Ok(())
    }

    async fn add_to_address_list(&mut self) -> Result<()> {
        let scan = match &self.active_scan {
            Some(scan) => scan,
            None => {
                error!("No active scan!");
                return Ok(());
            }
        };

        let addresses: Vec<_> = scan.results.keys()
            .map(|addr| format!("{:#x}", addr))
            .collect();

        if addresses.is_empty() {
            error!("No addresses to add!");
            return Ok(());
        }

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select address to add")
            .items(&addresses)
            .default(0)
            .interact()
            .unwrap();

        let address = *scan.results.keys().nth(selection).unwrap();
        
        let name: String = Input::new()
            .with_prompt("Enter description for this address")
            .interact_text()
            .unwrap_or_else(|_| format!("Address {:#x}", address));

        self.tracked_addresses.push(TrackedAddress {
            name,
            address,
            value_type: scan.data_type,
            description: None,
            frozen_value: None,
        });

        info!("Added address {:#x} to tracking list", address);
        Ok(())
    }

    async fn address_list_menu(&mut self) -> Result<()> {
        loop {
            if self.tracked_addresses.is_empty() {
                info!("No addresses being tracked");
                break;
            }

            let choices: Vec<_> = self.tracked_addresses.iter()
                .map(|addr| format!("{}: {:#x} ({})", addr.name, addr.address, addr.value_type as u8))
                .collect();

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Address List")
                .items(&choices)
                .default(0)
                .interact()
                .unwrap();

            let address_actions = vec![
                "Edit Value",
                "Freeze Value",
                "Remove from List",
                "Back"
            ];

            let action = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Address Actions")
                .items(&address_actions)
                .default(0)
                .interact()
                .unwrap();

            match action {
                0 => self.edit_address_value(selection).await?,
                1 => self.toggle_freeze_address(selection).await?,
                2 => {
                    self.tracked_addresses.remove(selection);
                    info!("Address removed from tracking list");
                },
                3 => break,
                _ => error!("Invalid selection"),
            }
        }
        Ok(())
    }

    async fn edit_address_value(&mut self, index: usize) -> Result<()> {
        let scanner = match &self.current_process {
            Some((_, scanner)) => scanner,
            None => return Ok(()),
        };

        let address = &self.tracked_addresses[index];
        let current_value = match address.value_type {
            DataType::U32 => {
                let val: u32 = scanner.read_memory(address.address)?;
                format!("{}", val)
            },
            DataType::I32 => {
                let val: i32 = scanner.read_memory(address.address)?;
                format!("{}", val)
            },
            DataType::F32 => {
                let val: f32 = scanner.read_memory(address.address)?;
                format!("{}", val)
            },
            // Add other types...
            _ => return Ok(()),
        };

        info!("Current value: {}", current_value);

        let new_value: String = Input::new()
            .with_prompt("Enter new value")
            .interact_text()
            .map_err(|_| MemoryError::MemoryOperation("Invalid input".to_string()))?;

        match address.value_type {
            DataType::U32 => {
                let val = new_value.parse::<u32>()
                    .map_err(|_| MemoryError::MemoryOperation("Invalid u32 value".to_string()))?;
                scanner.write_memory(address.address, &val)?;
            },
            DataType::I32 => {
                let val = new_value.parse::<i32>()
                    .map_err(|_| MemoryError::MemoryOperation("Invalid i32 value".to_string()))?;
                scanner.write_memory(address.address, &val)?;
            },
            DataType::F32 => {
                let val = new_value.parse::<f32>()
                    .map_err(|_| MemoryError::MemoryOperation("Invalid f32 value".to_string()))?;
                scanner.write_memory(address.address, &val)?;
            },
            // Add other types...
            _ => return Ok(()),
        }

        info!("Value updated successfully");
        Ok(())
    }

    async fn toggle_freeze_address(&mut self, index: usize) -> Result<()> {
        let scanner = match &self.current_process {
            Some((_, scanner)) => scanner,
            None => return Ok(()),
        };

        let address = &mut self.tracked_addresses[index];
        
        if address.frozen_value.is_some() {
            address.frozen_value = None;
            info!("Address unfrozen");
        } else {
            let value = match address.value_type {
                DataType::U32 => {
                    let val: u32 = scanner.read_memory(address.address)?;
                    val.to_ne_bytes().to_vec()
                },
                DataType::I32 => {
                    let val: i32 = scanner.read_memory(address.address)?;
                    val.to_ne_bytes().to_vec()
                },
                DataType::F32 => {
                    let val: f32 = scanner.read_memory(address.address)?;
                    val.to_ne_bytes().to_vec()
                },
                // Add other types...
                _ => return Ok(()),
            };
            
            address.frozen_value = Some(value);
            info!("Address frozen at current value");
        }
        
        Ok(())
    }

    async fn start_freeze_task(&mut self) -> Result<()> {
        if self.freeze_tx.is_some() {
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel(1);
        self.freeze_tx = Some(tx);

        let tracked_addresses = self.tracked_addresses.clone();
        let scanner = match &self.current_process {
            Some((_, scanner)) => scanner.clone(),
            None => return Ok(()),
        };

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        for addr in &tracked_addresses {
                            if let Some(frozen_value) = &addr.frozen_value {
                                let _ = scanner.write_memory_raw(addr.address, frozen_value);
                            }
                        }
                    }
                    _ = rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }
} 