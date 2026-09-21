use std::time::{Duration, Instant};

use super::{
    hierarchy::Argon2Profile,
    primitives::{CryptoResult, derive_argon2id},
};

pub const BENCHMARK_WARMUPS: usize = 3;
pub const BENCHMARK_SAMPLES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2BenchmarkResult {
    pub profile: Argon2Profile,
    pub warmups: usize,
    pub samples: usize,
    pub median: Duration,
    pub p95: Duration,
    pub maximum: Duration,
}

pub fn benchmark_argon2_profile(profile: Argon2Profile) -> CryptoResult<Argon2BenchmarkResult> {
    profile.validate()?;
    const SYNTHETIC_PASSWORD: &[u8] = b"AETERNA-I02-SYNTHETIC-BENCHMARK-PASSWORD";
    const SYNTHETIC_SALT: &[u8; 16] = b"I02-SYNTH-SALT!!";

    for _ in 0..BENCHMARK_WARMUPS {
        let key = derive_argon2id(
            SYNTHETIC_PASSWORD,
            SYNTHETIC_SALT,
            profile.memory_kib,
            profile.time_cost,
            profile.parallelism,
        )?;
        drop(key);
    }

    let mut timings = Vec::with_capacity(BENCHMARK_SAMPLES);
    for _ in 0..BENCHMARK_SAMPLES {
        let started = Instant::now();
        let key = derive_argon2id(
            SYNTHETIC_PASSWORD,
            SYNTHETIC_SALT,
            profile.memory_kib,
            profile.time_cost,
            profile.parallelism,
        )?;
        timings.push(started.elapsed());
        drop(key);
    }
    timings.sort_unstable();
    let middle = BENCHMARK_SAMPLES / 2;
    let median = (timings[middle - 1] + timings[middle]) / 2;
    let p95_index = (BENCHMARK_SAMPLES * 95).div_ceil(100) - 1;
    let maximum = timings[BENCHMARK_SAMPLES - 1];
    Ok(Argon2BenchmarkResult {
        profile,
        warmups: BENCHMARK_WARMUPS,
        samples: BENCHMARK_SAMPLES,
        median,
        p95: timings[p95_index],
        maximum,
    })
}
