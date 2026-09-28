#[cfg(target_os = "macos")]
use std::io::{self, Read};

#[cfg(target_os = "macos")]
const PRESSURE_BYTES: usize = 512 * 1024 * 1024;

#[cfg(target_os = "macos")]
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: i08_memory_pressure");
        std::process::exit(2);
    }
    let mut allocation = Vec::new();
    if allocation.try_reserve_exact(PRESSURE_BYTES).is_err() {
        eprintln!("pressure_allocation_failed");
        std::process::exit(1);
    }
    allocation.resize(PRESSURE_BYTES, 0u8);
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    for chunk in allocation.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    let initial_checksum = allocation
        .iter()
        .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)));
    // SAFETY: The vector owns a live, initialized allocation of this exact
    // length until munlock below, and no operation can resize it meanwhile.
    if unsafe { libc::mlock(allocation.as_ptr().cast(), allocation.len()) } != 0 {
        eprintln!("pressure_lock_failed");
        std::process::exit(1);
    }
    println!(
        "pressure_resident_bytes={PRESSURE_BYTES} pressure_locked=true pressure_checksum={initial_checksum}"
    );

    let mut release = [0u8; 1];
    let read_result = io::stdin().read(&mut release);
    std::hint::black_box(&allocation);
    let final_checksum = allocation
        .iter()
        .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)));
    // SAFETY: This is the same still-live allocation passed to mlock.
    let unlock_result = unsafe { libc::munlock(allocation.as_ptr().cast(), allocation.len()) };
    drop(allocation);
    if unlock_result != 0 {
        eprintln!("pressure_unlock_failed");
        std::process::exit(1);
    }
    if final_checksum != initial_checksum {
        eprintln!("pressure_checksum_mismatch");
        std::process::exit(1);
    }
    if read_result.is_err() {
        eprintln!("pressure_input_failed");
        std::process::exit(1);
    }
    println!("pressure_released=true");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("i08_memory_pressure_requires_macos");
    std::process::exit(2);
}
