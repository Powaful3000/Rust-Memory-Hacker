mod process;
mod memory;
mod menu;
mod error;

use tracing::info;
use menu::Menu;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("Starting Memory Hacker...");
    
    let mut menu = Menu::new();
    menu.run().await?;
    
    Ok(())
}
