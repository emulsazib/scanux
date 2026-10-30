//! Windows sensor backend. Everything OS-specific is behind `cfg(windows)`;
//! the crate still builds (empty) elsewhere, so `cargo test --workspace` works
//! on macOS/Linux. Type-check with `make check-windows`.

#[cfg(windows)]
pub mod driver;
#[cfg(windows)]
pub mod etw;
#[cfg(windows)]
pub mod eventlog;
#[cfg(windows)]
pub mod keys;
#[cfg(windows)]
pub mod paths;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod wfp;

/// FILETIME (100 ns ticks since 1601-01-01) → unix milliseconds.
pub fn filetime_to_unix_ms(ft: u64) -> u64 {
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    ft.saturating_sub(EPOCH_DIFF_100NS) / 10_000
}

#[cfg(test)]
mod tests {
    #[test]
    fn filetime_conversion() {
        // 2024-01-01T00:00:00Z
        assert_eq!(super::filetime_to_unix_ms(133_485_408_000_000_000), 1_704_067_200_000);
    }
}
