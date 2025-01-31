mod process;
mod memory;
mod menu;
mod error;

use tracing::info;
use menu::Menu;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging with debug level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    
    info!("Starting Memory Hacker...");
    
    let mut menu = Menu::new();
    menu.run().await?;
    
    Ok(())
}
