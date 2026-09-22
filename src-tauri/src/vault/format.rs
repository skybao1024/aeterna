use sha2::{Digest, Sha256};

use crate::crypto::{MasterWrapper, RecoveryWrapper};

use super::{VaultError, VaultResult};

pub const APPLICATION_ID: i32 = 0x4145_5452;
pub const CONTAINER_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u32 = 1;
pub const CRYPTO_VERSION: u16 = 1;
pub const RECORD_FRAME_VERSION: u16 = 1;
pub const AES_256_GCM_ID: u8 = 1;
pub const GENERIC_RECORD_PURPOSE: u8 = 1;
pub const MAX_PLAINTEXT_LENGTH: usize = 1_048_576;
pub const MAX_FRAME_LENGTH: usize = 1_048_622;
pub const MIN_FRAME_LENGTH: usize = 46;
pub const VAULT_MAGIC: [u8; 12] = *b"AETERNA-VLT\0";

const HEADER_DOMAIN: &[u8; 14] = b"AETERNA-HEADER";
pub(super) const HEADER_AAD_VERSION: u8 = 1;
const WRAPPER_DOMAIN: &[u8; 19] = b"AETERNA-WRAPPERS-V1";
const RECORD_MAGIC: [u8; 8] = *b"AETRREC\0";
const RECORD_DOMAIN: &[u8; 14] = b"AETERNA-RECORD";
pub(super) const RECORD_AAD_VERSION: u8 = 1;
const FRAME_PREFIX_LENGTH: usize = 30;
const GCM_TAG_LENGTH: usize = 16;

pub(super) struct HeaderRow {
    pub magic: [u8; 12],
    pub container_version: u16,
    pub schema_version: u32,
    pub crypto_version: u16,
    pub vault_id: [u8; 16],
    pub device_id: [u8; 16],
    pub auth_nonce: [u8; 12],
    pub auth_tag: [u8; 16],
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

pub(super) struct MasterRow {
    pub revision: u64,
    pub wrapper: MasterWrapper,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

pub(super) struct RecoveryRow {
    pub recovery_id: [u8; 16],
    pub device_id: [u8; 16],
    pub wrapper: RecoveryWrapper,
    pub created_at_ms: u64,
}

pub(super) struct DecodedFrame<'a> {
    pub nonce: [u8; 12],
    pub ciphertext_and_tag: &'a [u8],
    pub plaintext_length: usize,
}

pub(super) fn wrapper_digest(
    vault_id: [u8; 16],
    master: &MasterRow,
    recovery: &RecoveryRow,
) -> VaultResult<[u8; 32]> {
    let mut encoded = [0_u8; 259];
    encoded[0..19].copy_from_slice(WRAPPER_DOMAIN);
    encoded[19..35].copy_from_slice(&vault_id);
    encoded[35..43].copy_from_slice(&master.revision.to_be_bytes());
    encoded[43..45].copy_from_slice(&master.wrapper.format_version.to_be_bytes());
    encoded[45] = master.wrapper.aead_algorithm;
    encoded[46] = master.wrapper.purpose;
    encoded[47] = master.wrapper.kdf_algorithm;
    encoded[48] = master.wrapper.kdf_version;
    encoded[49..53].copy_from_slice(&master.wrapper.profile.memory_kib.to_be_bytes());
    encoded[53..57].copy_from_slice(&master.wrapper.profile.time_cost.to_be_bytes());
    encoded[57..61].copy_from_slice(&master.wrapper.profile.parallelism.to_be_bytes());
    encoded[61..63].copy_from_slice(&master.wrapper.profile.output_length.to_be_bytes());
    encoded[63..79].copy_from_slice(&master.wrapper.salt);
    encoded[79..91].copy_from_slice(&master.wrapper.nonce);
    copy_exact(&mut encoded[91..139], &master.wrapper.ciphertext_and_tag)?;
    encoded[139..147].copy_from_slice(&master.created_at_ms.to_be_bytes());
    encoded[147..155].copy_from_slice(&master.updated_at_ms.to_be_bytes());
    encoded[155..171].copy_from_slice(&recovery.recovery_id);
    encoded[171..187].copy_from_slice(&recovery.device_id);
    encoded[187..189].copy_from_slice(&recovery.wrapper.format_version.to_be_bytes());
    encoded[189] = recovery.wrapper.aead_algorithm;
    encoded[190] = recovery.wrapper.purpose;
    encoded[191..203].copy_from_slice(&recovery.wrapper.nonce);
    copy_exact(&mut encoded[203..251], &recovery.wrapper.ciphertext_and_tag)?;
    encoded[251..259].copy_from_slice(&recovery.created_at_ms.to_be_bytes());
    Ok(Sha256::digest(encoded).into())
}

pub(super) fn header_aad(header: &HeaderRow, wrapper_digest: [u8; 32]) -> [u8; 115] {
    let mut encoded = [0_u8; 115];
    encoded[0..14].copy_from_slice(HEADER_DOMAIN);
    encoded[14] = HEADER_AAD_VERSION;
    encoded[15..27].copy_from_slice(&header.magic);
    encoded[27..29].copy_from_slice(&header.container_version.to_be_bytes());
    encoded[29..33].copy_from_slice(&header.schema_version.to_be_bytes());
    encoded[33..35].copy_from_slice(&header.crypto_version.to_be_bytes());
    encoded[35..51].copy_from_slice(&header.vault_id);
    encoded[51..67].copy_from_slice(&header.device_id);
    encoded[67..75].copy_from_slice(&header.created_at_ms.to_be_bytes());
    encoded[75..83].copy_from_slice(&header.updated_at_ms.to_be_bytes());
    encoded[83..115].copy_from_slice(&wrapper_digest);
    encoded
}

pub(super) fn record_aad(
    vault_id: [u8; 16],
    record_id: [u8; 16],
    generation: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
    plaintext_length: usize,
) -> VaultResult<[u8; 83]> {
    let plaintext_length = u32::try_from(plaintext_length).map_err(|_| VaultError::InvalidInput)?;
    if plaintext_length as usize > MAX_PLAINTEXT_LENGTH || generation == 0 {
        return Err(VaultError::InvalidInput);
    }
    let mut encoded = [0_u8; 83];
    encoded[0..14].copy_from_slice(RECORD_DOMAIN);
    encoded[14] = RECORD_AAD_VERSION;
    encoded[15..17].copy_from_slice(&CONTAINER_VERSION.to_be_bytes());
    encoded[17..19].copy_from_slice(&RECORD_FRAME_VERSION.to_be_bytes());
    encoded[19..21].copy_from_slice(&CRYPTO_VERSION.to_be_bytes());
    encoded[21] = AES_256_GCM_ID;
    encoded[22] = GENERIC_RECORD_PURPOSE;
    encoded[23..39].copy_from_slice(&vault_id);
    encoded[39..55].copy_from_slice(&record_id);
    encoded[55..63].copy_from_slice(&generation.to_be_bytes());
    encoded[63..71].copy_from_slice(&created_at_ms.to_be_bytes());
    encoded[71..79].copy_from_slice(&updated_at_ms.to_be_bytes());
    encoded[79..83].copy_from_slice(&plaintext_length.to_be_bytes());
    Ok(encoded)
}

pub(super) fn encode_frame(nonce: [u8; 12], ciphertext_and_tag: &[u8]) -> VaultResult<Vec<u8>> {
    if ciphertext_and_tag.len() < GCM_TAG_LENGTH
        || ciphertext_and_tag.len() > MAX_PLAINTEXT_LENGTH + GCM_TAG_LENGTH
    {
        return Err(VaultError::InvalidInput);
    }
    let encrypted_length =
        u32::try_from(ciphertext_and_tag.len()).map_err(|_| VaultError::InvalidInput)?;
    let mut frame = Vec::with_capacity(FRAME_PREFIX_LENGTH + ciphertext_and_tag.len());
    frame.extend_from_slice(&RECORD_MAGIC);
    frame.extend_from_slice(&RECORD_FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&CRYPTO_VERSION.to_be_bytes());
    frame.push(AES_256_GCM_ID);
    frame.push(GENERIC_RECORD_PURPOSE);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&encrypted_length.to_be_bytes());
    frame.extend_from_slice(ciphertext_and_tag);
    Ok(frame)
}

pub(super) fn decode_frame(frame: &[u8]) -> VaultResult<DecodedFrame<'_>> {
    if !(MIN_FRAME_LENGTH..=MAX_FRAME_LENGTH).contains(&frame.len()) {
        return Err(VaultError::InvalidFormat);
    }
    if frame[0..8] != RECORD_MAGIC
        || read_u16(&frame[8..10])? != RECORD_FRAME_VERSION
        || read_u16(&frame[10..12])? != CRYPTO_VERSION
        || frame[12] != AES_256_GCM_ID
        || frame[13] != GENERIC_RECORD_PURPOSE
    {
        return Err(VaultError::UnsupportedVersion);
    }
    let nonce = read_array(&frame[14..26])?;
    let encrypted_length =
        usize::try_from(read_u32(&frame[26..30])?).map_err(|_| VaultError::InvalidFormat)?;
    if !(GCM_TAG_LENGTH..=MAX_PLAINTEXT_LENGTH + GCM_TAG_LENGTH).contains(&encrypted_length)
        || frame.len() != FRAME_PREFIX_LENGTH + encrypted_length
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(DecodedFrame {
        nonce,
        ciphertext_and_tag: &frame[FRAME_PREFIX_LENGTH..],
        plaintext_length: encrypted_length - GCM_TAG_LENGTH,
    })
}

pub(super) fn read_array<const LENGTH: usize>(bytes: &[u8]) -> VaultResult<[u8; LENGTH]> {
    bytes.try_into().map_err(|_| VaultError::InvalidFormat)
}

fn read_u16(bytes: &[u8]) -> VaultResult<u16> {
    read_array(bytes).map(u16::from_be_bytes)
}

fn read_u32(bytes: &[u8]) -> VaultResult<u32> {
    read_array(bytes).map(u32::from_be_bytes)
}

fn copy_exact(output: &mut [u8], input: &[u8]) -> VaultResult<()> {
    if output.len() != input.len() {
        return Err(VaultError::InvalidFormat);
    }
    output.copy_from_slice(input);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_aad_has_the_approved_offsets() {
        let aad = record_aad([0x11; 16], [0x22; 16], 3, 4, 5, 6);
        let aad = match aad {
            Ok(value) => value,
            Err(_) => panic!("canonical metadata is valid"),
        };
        assert_eq!(&aad[0..14], b"AETERNA-RECORD");
        assert_eq!(aad[14], 1);
        assert_eq!(&aad[23..39], &[0x11; 16]);
        assert_eq!(&aad[39..55], &[0x22; 16]);
        assert_eq!(&aad[55..63], &3_u64.to_be_bytes());
        assert_eq!(&aad[79..83], &6_u32.to_be_bytes());
    }

    #[test]
    fn frame_round_trip_and_all_length_boundaries_are_exact() {
        for plaintext_length in [0, MAX_PLAINTEXT_LENGTH] {
            let encrypted = vec![0xa5; plaintext_length + GCM_TAG_LENGTH];
            let frame = encode_frame([0x33; 12], &encrypted);
            let frame = match frame {
                Ok(value) => value,
                Err(_) => panic!("boundary frame is valid"),
            };
            let decoded = decode_frame(&frame);
            assert!(
                matches!(decoded, Ok(value) if value.nonce == [0x33; 12] && value.plaintext_length == plaintext_length)
            );
        }
        assert!(encode_frame([0; 12], &[0; GCM_TAG_LENGTH - 1]).is_err());
        assert!(
            encode_frame([0; 12], &vec![0; MAX_PLAINTEXT_LENGTH + GCM_TAG_LENGTH + 1]).is_err()
        );
    }

    #[test]
    fn frame_rejects_tamper_truncation_extension_and_unknown_versions() {
        let frame = encode_frame([7; 12], &[9; GCM_TAG_LENGTH]);
        let frame = match frame {
            Ok(value) => value,
            Err(_) => panic!("synthetic frame is valid"),
        };
        for index in [0, 8, 10, 12, 13] {
            let mut tampered = frame.clone();
            tampered[index] ^= 1;
            assert!(decode_frame(&tampered).is_err());
        }
        let mut truncated = frame.clone();
        truncated.pop();
        assert!(decode_frame(&truncated).is_err());
        let mut extended = frame;
        extended.push(0);
        assert!(decode_frame(&extended).is_err());
    }
}
