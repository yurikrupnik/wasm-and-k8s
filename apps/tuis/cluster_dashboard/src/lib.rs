//! Cluster Dashboard - Local TUI for cluster management
//!
//! A terminal-based dashboard that shows:
//! - Cluster information and health
//! - Applications and their state
//! - Security vulnerabilities and best practices
//! - FinOps cost analysis

pub mod app_definition;
pub mod data;
pub mod kube_client;
pub mod ui;
pub mod views;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub use app_definition::AppDefinition;
pub use data::DashboardData;
pub use views::View;

/// Dashboard application state
pub struct Dashboard {
    /// Current view
    pub current_view: View,
    /// Dashboard data
    pub data: Arc<RwLock<DashboardData>>,
    /// Should quit
    pub should_quit: bool,
    /// Status message
    pub status_message: Option<String>,
    /// Search query
    pub search_query: String,
    /// Is searching
    pub is_searching: bool,
    /// Selected index in current view
    pub selected_index: usize,
    /// Scroll offset
    pub scroll_offset: usize,
}

impl Dashboard {
    /// Create new dashboard
    pub async fn new() -> anyhow::Result<Self> {
        let data = DashboardData::load().await?;

        Ok(Self {
            current_view: View::Overview,
            data: Arc::new(RwLock::new(data)),
            should_quit: false,
            status_message: None,
            search_query: String::new(),
            is_searching: false,
            selected_index: 0,
            scroll_offset: 0,
        })
    }

    /// Run the dashboard
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Start background data refresh
        let data = self.data.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if let Ok(new_data) = DashboardData::load().await {
                    let mut guard = data.write().await;
                    *guard = new_data;
                }
            }
        });

        // Main loop
        let result = self.main_loop(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    async fn main_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> anyhow::Result<()> {
        loop {
            // Draw UI
            let data = self.data.read().await;
            if let Some(max) = self.current_view_max(&data) {
                self.selected_index = self.selected_index.min(max);
            }
            terminal.draw(|f| {
                ui::render(f, self, &data);
            })?;
            drop(data);

            // Handle events
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Mouse(m) if !self.is_searching => match m.kind {
                        MouseEventKind::ScrollDown => {
                            self.selected_index = self.selected_index.saturating_add(3);
                        }
                        MouseEventKind::ScrollUp => {
                            self.selected_index = self.selected_index.saturating_sub(3);
                        }
                        _ => {}
                    },
                    Event::Key(key) => {
                        if self.is_searching {
                            match key.code {
                                KeyCode::Esc => {
                                    self.is_searching = false;
                                    self.search_query.clear();
                                }
                                KeyCode::Enter => {
                                    self.is_searching = false;
                                }
                                KeyCode::Backspace => {
                                    self.search_query.pop();
                                }
                                KeyCode::Char(c) => {
                                    self.search_query.push(c);
                                }
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Char('q') => {
                                    self.should_quit = true;
                                }
                                KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    self.should_quit = true;
                                }
                                KeyCode::Char('/') => {
                                    self.is_searching = true;
                                }
                                KeyCode::Char('?') => {
                                    self.current_view = View::Help;
                                }
                                // Navigation
                                KeyCode::Char('1') => {
                                    self.current_view = View::Overview;
                                    self.selected_index = 0;
                                }
                                KeyCode::Char('2') => {
                                    self.current_view = View::Nodes;
                                    self.selected_index = 0;
                                }
                                KeyCode::Char('3') => {
                                    self.current_view = View::Security;
                                    self.selected_index = 0;
                                }
                                KeyCode::Char('4') => {
                                    self.current_view = View::FinOps;
                                    self.selected_index = 0;
                                }
                                KeyCode::Char('5') => {
                                    self.current_view = View::Providers;
                                    self.selected_index = 0;
                                }
                                KeyCode::Char('6') => {
                                    self.current_view = View::Rightsizing;
                                    self.selected_index = 0;
                                }
                                // List navigation
                                KeyCode::Up | KeyCode::Char('k') => {
                                    if self.selected_index > 0 {
                                        self.selected_index -= 1;
                                    }
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    self.selected_index += 1;
                                }
                                KeyCode::PageUp => {
                                    self.selected_index = self.selected_index.saturating_sub(10);
                                }
                                KeyCode::PageDown => {
                                    self.selected_index += 10;
                                }
                                KeyCode::Home => {
                                    self.selected_index = 0;
                                }
                                // Actions
                                KeyCode::Char('r') => {
                                    self.status_message = Some("Refreshing...".to_string());
                                    if let Ok(new_data) = DashboardData::load().await {
                                        let mut guard = self.data.write().await;
                                        *guard = new_data;
                                        self.status_message = Some("Refreshed!".to_string());
                                    }
                                }
                                KeyCode::Enter => {
                                    // Action on selected item
                                    self.handle_enter().await;
                                }
                                KeyCode::Esc => {
                                    // Esc only escapes a detail view back to its
                                    // parent list. From a top-level view it does
                                    // nothing — pressing 1 is the way home.
                                    match self.current_view {
                                        View::VulnerabilityDetail => {
                                            self.current_view = View::Security;
                                        }
                                        View::ProviderDetail => {
                                            self.current_view = View::Providers;
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    fn current_view_max(&self, data: &DashboardData) -> Option<usize> {
        let len = match self.current_view {
            View::Nodes => data.nodes.len(),
            View::Security => data.security.issues.len(),
            View::FinOps => data.finops.cost_by_namespace.len(),
            View::Providers => data.provider_configs.len() + data.auth_providers.len(),
            View::Rightsizing => data.rightsizing.len(),
            _ => return None,
        };
        if len == 0 {
            None
        } else {
            Some(len - 1)
        }
    }

    async fn handle_enter(&mut self) {
        match self.current_view {
            View::Security => {
                // Show selected finding's detail
                self.current_view = View::VulnerabilityDetail;
            }
            View::Providers => {
                // Show provider details
                self.current_view = View::ProviderDetail;
            }
            View::ProviderDetail => {
                // Return to providers list
                self.current_view = View::Providers;
            }
            _ => {}
        }
    }
}
