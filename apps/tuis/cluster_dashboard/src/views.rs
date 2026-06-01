//! View definitions for the cluster dashboard

/// Tab/view identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Overview,
    Nodes,
    Security,
    FinOps,
    Providers,
    Rightsizing,
    Help,
    VulnerabilityDetail,
    ProviderDetail,
}

impl View {
    /// Get the display title for this view
    pub fn title(&self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Nodes => "Nodes",
            View::Security => "Security",
            View::FinOps => "FinOps",
            View::Providers => "Providers",
            View::Rightsizing => "Rightsizing",
            View::Help => "Help",
            View::VulnerabilityDetail => "Security Detail",
            View::ProviderDetail => "Provider Detail",
        }
    }

    /// Get the keyboard shortcut key for this view
    pub fn key(&self) -> char {
        match self {
            View::Overview => '1',
            View::Nodes => '2',
            View::Security => '3',
            View::FinOps => '4',
            View::Providers => '5',
            View::Rightsizing => '6',
            View::Help => '?',
            _ => ' ',
        }
    }

    /// Get all navigable views (shown in tab bar)
    pub fn navigable_views() -> &'static [View] {
        &[
            View::Overview,
            View::Nodes,
            View::Security,
            View::FinOps,
            View::Providers,
            View::Rightsizing,
        ]
    }

    /// Check if this is a detail view
    pub fn is_detail_view(&self) -> bool {
        matches!(self, View::VulnerabilityDetail | View::ProviderDetail)
    }
}
