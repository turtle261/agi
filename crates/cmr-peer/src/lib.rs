//! Library entry points for the CMR peer daemon.

pub mod app;
pub mod compressor_client;
pub mod config;
pub mod dashboard;
pub mod transport;
#[cfg(feature = "tui")]
pub mod tui;
