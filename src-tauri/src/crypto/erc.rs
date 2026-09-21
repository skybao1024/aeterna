use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use zeroize::Zeroizing;

use super::{
    ERC_FORMAT_VERSION,
    primitives::{CryptoError, CryptoResult},
    secret::ErcEntropy,
};

const ERC_HRP: &str = "aerc";
const ERC_PAYLOAD_LENGTH: usize = 17;

pub fn generate_erc() -> CryptoResult<ErcEntropy> {
    ErcEntropy::generate()
}

pub fn encode_erc(erc: &ErcEntropy) -> CryptoResult<String> {
    let mut payload = Zeroizing::new([0_u8; ERC_PAYLOAD_LENGTH]);
    payload[0] = ERC_FORMAT_VERSION;
    payload[1..].copy_from_slice(erc.expose());
    let hrp = Hrp::parse(ERC_HRP).map_err(|_| CryptoError::InvalidFormat)?;
    bech32::encode::<Bech32m>(hrp, &payload[..]).map_err(|_| CryptoError::InvalidFormat)
}

pub fn decode_erc(input: &str) -> CryptoResult<ErcEntropy> {
    if input.is_empty()
        || input.bytes().any(|byte| byte.is_ascii_whitespace())
        || input != input.to_ascii_lowercase()
    {
        return Err(CryptoError::InvalidFormat);
    }
    let checked =
        CheckedHrpstring::new::<Bech32m>(input).map_err(|_| CryptoError::InvalidFormat)?;
    let hrp = checked.hrp();
    let payload = Zeroizing::new(checked.byte_iter().collect::<Vec<_>>());
    if hrp.as_str() != ERC_HRP
        || payload.len() != ERC_PAYLOAD_LENGTH
        || payload[0] != ERC_FORMAT_VERSION
    {
        return Err(CryptoError::InvalidFormat);
    }
    let entropy: [u8; 16] = payload[1..]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat)?;
    Ok(ErcEntropy::from_bytes(entropy))
}

pub fn format_erc_for_display(erc: &ErcEntropy) -> CryptoResult<String> {
    let canonical = Zeroizing::new(encode_erc(erc)?.to_ascii_uppercase());
    let mut output = String::with_capacity(canonical.len() + canonical.len() / 4);
    for (index, character) in canonical.chars().enumerate() {
        if index > 0 && index.is_multiple_of(4) {
            output.push(' ');
        }
        output.push(character);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erc_round_trip_and_display_are_canonical() {
        let erc = ErcEntropy::from_bytes([0x42; 16]);
        let encoded = encode_erc(&erc);
        let encoded = match encoded {
            Ok(value) => value,
            Err(_) => panic!("synthetic ERC should encode"),
        };
        assert!(encoded.starts_with("aerc1"));
        assert!(encoded.bytes().all(|byte| !byte.is_ascii_uppercase()));
        assert!(matches!(decode_erc(&encoded), Ok(value) if value.expose() == erc.expose()));
        let display = format_erc_for_display(&erc);
        assert!(
            matches!(display, Ok(value) if value.bytes().all(|byte| byte == b' ' || !byte.is_ascii_lowercase()))
        );
    }

    #[test]
    fn erc_rejects_checksum_mutation_transposition_and_noncanonical_forms() {
        let erc = ErcEntropy::from_bytes([0x24; 16]);
        let encoded = match encode_erc(&erc) {
            Ok(value) => value,
            Err(_) => panic!("synthetic ERC should encode"),
        };
        let mut mutation = encoded.clone().into_bytes();
        let last = mutation.len() - 1;
        mutation[last] = if mutation[last] == b'q' { b'p' } else { b'q' };
        let mutation = String::from_utf8(mutation).unwrap_or_default();
        assert!(decode_erc(&mutation).is_err());

        let mut transposed = encoded.clone().into_bytes();
        transposed.swap(8, 9);
        let transposed = String::from_utf8(transposed).unwrap_or_default();
        assert!(decode_erc(&transposed).is_err());
        assert!(decode_erc(&encoded.to_ascii_uppercase()).is_err());
        assert!(decode_erc(&format!("{} ", encoded)).is_err());
        assert!(decode_erc(&encoded[..encoded.len() - 1]).is_err());
        assert!(decode_erc(&format!("{encoded}q")).is_err());
        assert!(decode_erc(&encoded.replace("aerc1", "xerc1")).is_err());

        let mut unknown_payload = [0_u8; ERC_PAYLOAD_LENGTH];
        unknown_payload[0] = 2;
        let hrp = Hrp::parse(ERC_HRP);
        let unknown = match hrp {
            Ok(hrp) => bech32::encode::<Bech32m>(hrp, &unknown_payload),
            Err(_) => panic!("constant HRP should be valid"),
        };
        assert!(matches!(unknown, Ok(value) if decode_erc(&value).is_err()));

        let mut valid_payload = [0_u8; ERC_PAYLOAD_LENGTH];
        valid_payload[0] = ERC_FORMAT_VERSION;
        let bech32_only = match Hrp::parse(ERC_HRP) {
            Ok(hrp) => bech32::encode::<bech32::Bech32>(hrp, &valid_payload),
            Err(_) => panic!("constant HRP should be valid"),
        };
        assert!(matches!(bech32_only, Ok(value) if decode_erc(&value).is_err()));
    }

    #[test]
    fn generated_erc_values_are_unique_in_a_bounded_sample() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let erc = generate_erc();
            let erc = match erc {
                Ok(value) => value,
                Err(_) => panic!("OS randomness should be available"),
            };
            assert!(seen.insert(*erc.expose()));
        }
    }
}
