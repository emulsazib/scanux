//! scanu-sensor.exe: Windows service (or `--console` for debugging).
//!
//! Wires: ETW + Event Log → engine; minifilter port → canary freeze and
//! pre-exec verdicts; engine notices → desktop named pipe; engine ⇄ cloud uplink.

#[cfg(windows)]
mod win;

#[cfg(windows)]
fn main() {
    win::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("scanu-sensor is the Windows service; on this OS use `sensor-sim` (see README).");
    std::process::exit(2);
}
