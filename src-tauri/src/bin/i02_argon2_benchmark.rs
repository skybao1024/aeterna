use aeterna_lib::crypto::{Argon2Profile, benchmark_argon2_profile};

fn profile_named(name: &str) -> Option<Argon2Profile> {
    match name {
        "A" => Some(Argon2Profile::new(65_536, 3, 1)),
        "B" => Some(Argon2Profile::new(65_536, 3, 4)),
        "C" => Some(Argon2Profile::new(131_072, 3, 1)),
        "D" => Some(Argon2Profile::new(131_072, 3, 4)),
        "E" => Some(Argon2Profile::new(262_144, 2, 1)),
        "F" => Some(Argon2Profile::new(262_144, 2, 4)),
        _ => None,
    }
}

fn main() {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let profile_name = arguments.next();
    if arguments.next().is_some() {
        eprintln!("usage: i02_argon2_benchmark <A|B|C|D|E|F>");
        std::process::exit(2);
    }
    let Some(profile_name) = profile_name else {
        eprintln!("usage: i02_argon2_benchmark <A|B|C|D|E|F>");
        std::process::exit(2);
    };
    let Some(profile) = profile_named(&profile_name) else {
        eprintln!("unknown benchmark profile");
        std::process::exit(2);
    };
    let result = match benchmark_argon2_profile(profile) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("benchmark_failed={}", error.code());
            std::process::exit(1);
        }
    };
    println!(
        "profile={profile_name},memory_kib={},time_cost={},parallelism={},warmups={},samples={},p50_ms={:.3},p95_ms={:.3},max_ms={:.3}",
        result.profile.memory_kib,
        result.profile.time_cost,
        result.profile.parallelism,
        result.warmups,
        result.samples,
        result.median.as_secs_f64() * 1_000.0,
        result.p95.as_secs_f64() * 1_000.0,
        result.maximum.as_secs_f64() * 1_000.0,
    );
}
