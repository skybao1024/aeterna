use std::collections::HashSet;

use zeroize::Zeroizing;

use super::{
    DecryptedRecord, MAX_PLAINTEXT_LENGTH, RecordId, RecordVersion, UnlockedVault, VaultError,
    VaultResult,
};

const ITEM_MAGIC: [u8; 8] = *b"AETRITM\0";
const ITEM_PAYLOAD_VERSION: u16 = 1;
const ITEM_FLAGS: u8 = 0;
const ITEM_HEADER_LENGTH: usize = 30;
const ATTACHMENT_HEADER_LENGTH: usize = 24;
const ATTACHMENT_ID_ATTEMPTS: usize = 16;

pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_CATEGORY_BYTES: usize = 128;
pub const MAX_CONTACT_EXPLANATION_BYTES: usize = 8_192;
pub const MAX_BODY_BYTES: usize = 131_072;
pub const MAX_ATTACHMENT_COUNT: usize = 8;
pub const MAX_FILENAME_BYTES: usize = 255;
pub const MAX_MEDIA_TYPE_BYTES: usize = 127;
pub const MAX_ATTACHMENT_BYTES: usize = 786_432;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    Note,
    Instruction,
}

impl ItemKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Instruction => "instruction",
        }
    }

    const fn encoded(self) -> u8 {
        match self {
            Self::Note => 1,
            Self::Instruction => 2,
        }
    }

    fn decode(value: u8) -> VaultResult<Self> {
        match value {
            1 => Ok(Self::Note),
            2 => Ok(Self::Instruction),
            _ => Err(VaultError::ItemUnsupportedVersion),
        }
    }
}

pub struct ItemDraft {
    pub kind: ItemKind,
    pub title: Zeroizing<String>,
    pub category: Zeroizing<String>,
    pub contact_explanation: Zeroizing<String>,
    pub body: Zeroizing<String>,
}

impl ItemDraft {
    pub fn new(
        kind: ItemKind,
        title: String,
        category: String,
        contact_explanation: String,
        body: String,
    ) -> VaultResult<Self> {
        let draft = Self {
            kind,
            title: Zeroizing::new(title),
            category: Zeroizing::new(category),
            contact_explanation: Zeroizing::new(contact_explanation),
            body: Zeroizing::new(body),
        };
        validate_fields(
            draft.kind,
            &draft.title,
            &draft.category,
            &draft.contact_explanation,
            &draft.body,
            VaultError::InvalidInput,
        )?;
        Ok(draft)
    }
}

impl core::fmt::Debug for ItemDraft {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ItemDraft")
            .field("kind", &self.kind)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AttachmentId([u8; 16]);

impl AttachmentId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Debug for AttachmentId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AttachmentId([REDACTED])")
    }
}

pub struct VaultAttachment {
    pub id: AttachmentId,
    pub filename: Zeroizing<String>,
    pub media_type: Zeroizing<String>,
    content: Zeroizing<Vec<u8>>,
}

impl VaultAttachment {
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

impl core::fmt::Debug for VaultAttachment {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VaultAttachment")
            .field("id", &self.id)
            .field("metadata", &"[REDACTED]")
            .field("content", &"[REDACTED]")
            .finish()
    }
}

pub struct VaultItem {
    pub id: RecordId,
    pub revision: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub kind: ItemKind,
    pub title: Zeroizing<String>,
    pub category: Zeroizing<String>,
    pub contact_explanation: Zeroizing<String>,
    pub body: Zeroizing<String>,
    pub attachments: Vec<VaultAttachment>,
}

impl core::fmt::Debug for VaultItem {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VaultItem")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .field("kind", &self.kind)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

pub struct ItemSummary {
    pub id: RecordId,
    pub revision: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub kind: ItemKind,
    pub title: Zeroizing<String>,
    pub category: Zeroizing<String>,
    pub attachment_count: usize,
}

impl core::fmt::Debug for ItemSummary {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ItemSummary")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .field("kind", &self.kind)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

impl UnlockedVault {
    pub fn create_item(&self, draft: ItemDraft) -> VaultResult<VaultItem> {
        let item = VaultItem {
            id: RecordId::from_bytes([0; 16]),
            revision: 1,
            created_at_ms: 0,
            updated_at_ms: 0,
            kind: draft.kind,
            title: draft.title,
            category: draft.category,
            contact_explanation: draft.contact_explanation,
            body: draft.body,
            attachments: Vec::new(),
        };
        let encoded = encode_item(&item)?;
        let version = self.create_record(&encoded)?;
        Ok(with_version(item, version))
    }

    pub fn list_items(&self) -> VaultResult<Vec<ItemSummary>> {
        self.map_records(|record| {
            let item = item_from_record(record)?;
            Ok(ItemSummary {
                id: item.id,
                revision: item.revision,
                created_at_ms: item.created_at_ms,
                updated_at_ms: item.updated_at_ms,
                kind: item.kind,
                title: item.title,
                category: item.category,
                attachment_count: item.attachments.len(),
            })
        })
    }

    pub fn get_item(&self, id: RecordId) -> VaultResult<VaultItem> {
        self.read_record(id).and_then(item_from_record)
    }

    pub fn update_item(
        &self,
        id: RecordId,
        expected_revision: u64,
        draft: ItemDraft,
    ) -> VaultResult<VaultItem> {
        let mut item = self.get_item(id)?;
        ensure_revision(&item, expected_revision)?;
        item.kind = draft.kind;
        item.title = draft.title;
        item.category = draft.category;
        item.contact_explanation = draft.contact_explanation;
        item.body = draft.body;
        let encoded = encode_item(&item)?;
        let version = self.update_record(id, expected_revision, &encoded)?;
        Ok(with_version(item, version))
    }

    pub fn add_attachment(
        &self,
        id: RecordId,
        expected_revision: u64,
        filename: String,
        media_type: String,
        content: Vec<u8>,
    ) -> VaultResult<VaultItem> {
        validate_attachment_input(
            &filename,
            &media_type,
            content.len(),
            VaultError::InvalidInput,
        )?;
        let mut item = self.get_item(id)?;
        ensure_revision(&item, expected_revision)?;
        if item.attachments.len() >= MAX_ATTACHMENT_COUNT {
            return Err(VaultError::InvalidInput);
        }
        let attachment_id = self.unique_attachment_id(&item)?;
        item.attachments.push(VaultAttachment {
            id: attachment_id,
            filename: Zeroizing::new(filename),
            media_type: Zeroizing::new(media_type),
            content: Zeroizing::new(content),
        });
        let encoded = encode_item(&item)?;
        let version = self.update_record(id, expected_revision, &encoded)?;
        Ok(with_version(item, version))
    }

    pub fn replace_attachment(
        &self,
        id: RecordId,
        expected_revision: u64,
        attachment_id: AttachmentId,
        filename: String,
        media_type: String,
        content: Vec<u8>,
    ) -> VaultResult<VaultItem> {
        validate_attachment_input(
            &filename,
            &media_type,
            content.len(),
            VaultError::InvalidInput,
        )?;
        let mut item = self.get_item(id)?;
        ensure_revision(&item, expected_revision)?;
        let attachment = item
            .attachments
            .iter_mut()
            .find(|value| value.id == attachment_id)
            .ok_or(VaultError::AttachmentNotFound)?;
        attachment.filename = Zeroizing::new(filename);
        attachment.media_type = Zeroizing::new(media_type);
        attachment.content = Zeroizing::new(content);
        let encoded = encode_item(&item)?;
        let version = self.update_record(id, expected_revision, &encoded)?;
        Ok(with_version(item, version))
    }

    pub fn read_attachment(
        &self,
        id: RecordId,
        expected_revision: u64,
        attachment_id: AttachmentId,
    ) -> VaultResult<Zeroizing<Vec<u8>>> {
        let item = self.get_item(id)?;
        ensure_revision(&item, expected_revision)?;
        let attachment = item
            .attachments
            .iter()
            .find(|value| value.id == attachment_id)
            .ok_or(VaultError::AttachmentNotFound)?;
        Ok(Zeroizing::new(attachment.content().to_vec()))
    }

    pub fn remove_attachment(
        &self,
        id: RecordId,
        expected_revision: u64,
        attachment_id: AttachmentId,
    ) -> VaultResult<VaultItem> {
        let mut item = self.get_item(id)?;
        ensure_revision(&item, expected_revision)?;
        let index = item
            .attachments
            .iter()
            .position(|value| value.id == attachment_id)
            .ok_or(VaultError::AttachmentNotFound)?;
        item.attachments.remove(index);
        let encoded = encode_item(&item)?;
        let version = self.update_record(id, expected_revision, &encoded)?;
        Ok(with_version(item, version))
    }

    pub fn delete_item(&self, id: RecordId, expected_revision: u64) -> VaultResult<()> {
        self.delete_record(id, expected_revision)
    }

    fn unique_attachment_id(&self, item: &VaultItem) -> VaultResult<AttachmentId> {
        for _ in 0..ATTACHMENT_ID_ATTEMPTS {
            let candidate = AttachmentId(self.random_identifier()?);
            if item.attachments.iter().all(|value| value.id != candidate) {
                return Ok(candidate);
            }
        }
        Err(VaultError::RandomnessUnavailable)
    }
}

fn with_version(mut item: VaultItem, version: RecordVersion) -> VaultItem {
    item.id = version.id;
    item.revision = version.generation;
    item.created_at_ms = version.created_at_ms;
    item.updated_at_ms = version.updated_at_ms;
    item
}

fn item_from_record(record: DecryptedRecord) -> VaultResult<VaultItem> {
    let decoded = decode_item(record.plaintext())?;
    Ok(VaultItem {
        id: record.id,
        revision: record.generation,
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
        kind: decoded.kind,
        title: decoded.title,
        category: decoded.category,
        contact_explanation: decoded.contact_explanation,
        body: decoded.body,
        attachments: decoded.attachments,
    })
}

fn ensure_revision(item: &VaultItem, expected_revision: u64) -> VaultResult<()> {
    if expected_revision == 0 {
        return Err(VaultError::InvalidInput);
    }
    if item.revision != expected_revision {
        return Err(VaultError::Conflict);
    }
    Ok(())
}

fn encode_item(item: &VaultItem) -> VaultResult<Zeroizing<Vec<u8>>> {
    validate_fields(
        item.kind,
        &item.title,
        &item.category,
        &item.contact_explanation,
        &item.body,
        VaultError::InvalidInput,
    )?;
    if item.attachments.len() > MAX_ATTACHMENT_COUNT {
        return Err(VaultError::InvalidInput);
    }

    let mut identifiers = HashSet::with_capacity(item.attachments.len());
    let mut total_attachment_bytes = 0_usize;
    let mut encoded_length = ITEM_HEADER_LENGTH
        .checked_add(item.title.len())
        .and_then(|value| value.checked_add(item.category.len()))
        .and_then(|value| value.checked_add(item.contact_explanation.len()))
        .and_then(|value| value.checked_add(item.body.len()))
        .ok_or(VaultError::AttachmentTooLarge)?;
    for attachment in &item.attachments {
        if !identifiers.insert(attachment.id) {
            return Err(VaultError::InvalidInput);
        }
        validate_attachment_input(
            &attachment.filename,
            &attachment.media_type,
            attachment.content.len(),
            VaultError::InvalidInput,
        )?;
        total_attachment_bytes = total_attachment_bytes
            .checked_add(attachment.content.len())
            .ok_or(VaultError::AttachmentTooLarge)?;
        encoded_length = encoded_length
            .checked_add(ATTACHMENT_HEADER_LENGTH)
            .and_then(|value| value.checked_add(attachment.filename.len()))
            .and_then(|value| value.checked_add(attachment.media_type.len()))
            .and_then(|value| value.checked_add(attachment.content.len()))
            .ok_or(VaultError::AttachmentTooLarge)?;
    }
    if total_attachment_bytes > MAX_ATTACHMENT_BYTES || encoded_length > MAX_PLAINTEXT_LENGTH {
        return Err(VaultError::AttachmentTooLarge);
    }

    let attachment_count =
        u16::try_from(item.attachments.len()).map_err(|_| VaultError::InvalidInput)?;
    let mut output = Zeroizing::new(Vec::with_capacity(encoded_length));
    output.extend_from_slice(&ITEM_MAGIC);
    output.extend_from_slice(&ITEM_PAYLOAD_VERSION.to_be_bytes());
    output.push(item.kind.encoded());
    output.push(ITEM_FLAGS);
    output.extend_from_slice(&attachment_count.to_be_bytes());
    push_u32_length(&mut output, item.title.len())?;
    push_u32_length(&mut output, item.category.len())?;
    push_u32_length(&mut output, item.contact_explanation.len())?;
    push_u32_length(&mut output, item.body.len())?;
    output.extend_from_slice(item.title.as_bytes());
    output.extend_from_slice(item.category.as_bytes());
    output.extend_from_slice(item.contact_explanation.as_bytes());
    output.extend_from_slice(item.body.as_bytes());
    for attachment in &item.attachments {
        output.extend_from_slice(&attachment.id.0);
        push_u16_length(&mut output, attachment.filename.len())?;
        push_u16_length(&mut output, attachment.media_type.len())?;
        push_u32_length(&mut output, attachment.content.len())?;
        output.extend_from_slice(attachment.filename.as_bytes());
        output.extend_from_slice(attachment.media_type.as_bytes());
        output.extend_from_slice(&attachment.content);
    }
    if output.len() != encoded_length {
        return Err(VaultError::Internal);
    }
    Ok(output)
}

fn decode_item(bytes: &[u8]) -> VaultResult<DecodedItem> {
    if bytes.len() < ITEM_HEADER_LENGTH {
        return Err(VaultError::ItemInvalidFormat);
    }
    if bytes[0..8] != ITEM_MAGIC
        || read_u16(&bytes[8..10])? != ITEM_PAYLOAD_VERSION
        || bytes[11] != ITEM_FLAGS
    {
        return Err(VaultError::ItemUnsupportedVersion);
    }
    let kind = ItemKind::decode(bytes[10])?;
    let attachment_count = usize::from(read_u16(&bytes[12..14])?);
    if attachment_count > MAX_ATTACHMENT_COUNT {
        return Err(VaultError::ItemInvalidFormat);
    }
    let title_length = read_bounded_u32(&bytes[14..18], MAX_TITLE_BYTES)?;
    let category_length = read_bounded_u32(&bytes[18..22], MAX_CATEGORY_BYTES)?;
    let contact_length = read_bounded_u32(&bytes[22..26], MAX_CONTACT_EXPLANATION_BYTES)?;
    let body_length = read_bounded_u32(&bytes[26..30], MAX_BODY_BYTES)?;
    let mut decoder = Decoder::new(bytes, ITEM_HEADER_LENGTH);
    let title = decoder.take_string(title_length)?;
    let category = decoder.take_string(category_length)?;
    let contact_explanation = decoder.take_string(contact_length)?;
    let body = decoder.take_string(body_length)?;
    validate_fields(
        kind,
        &title,
        &category,
        &contact_explanation,
        &body,
        VaultError::ItemInvalidFormat,
    )?;

    let mut identifiers = HashSet::with_capacity(attachment_count);
    let mut attachments = Vec::with_capacity(attachment_count);
    let mut total_attachment_bytes = 0_usize;
    for _ in 0..attachment_count {
        let id = AttachmentId(decoder.take_array()?);
        if !identifiers.insert(id) {
            return Err(VaultError::ItemInvalidFormat);
        }
        let filename_length = usize::from(decoder.take_u16()?);
        let media_type_length = usize::from(decoder.take_u16()?);
        let content_length =
            usize::try_from(decoder.take_u32()?).map_err(|_| VaultError::ItemInvalidFormat)?;
        if filename_length > MAX_FILENAME_BYTES
            || media_type_length > MAX_MEDIA_TYPE_BYTES
            || content_length > MAX_ATTACHMENT_BYTES
        {
            return Err(VaultError::ItemInvalidFormat);
        }
        total_attachment_bytes = total_attachment_bytes
            .checked_add(content_length)
            .ok_or(VaultError::ItemInvalidFormat)?;
        if total_attachment_bytes > MAX_ATTACHMENT_BYTES {
            return Err(VaultError::ItemInvalidFormat);
        }
        let filename = decoder.take_string(filename_length)?;
        let media_type = decoder.take_string(media_type_length)?;
        validate_attachment_input(
            &filename,
            &media_type,
            content_length,
            VaultError::ItemInvalidFormat,
        )?;
        let content = Zeroizing::new(decoder.take(content_length)?.to_vec());
        attachments.push(VaultAttachment {
            id,
            filename,
            media_type,
            content,
        });
    }
    if !decoder.is_finished() {
        return Err(VaultError::ItemInvalidFormat);
    }
    Ok(DecodedItem {
        kind,
        title,
        category,
        contact_explanation,
        body,
        attachments,
    })
}

struct DecodedItem {
    kind: ItemKind,
    title: Zeroizing<String>,
    category: Zeroizing<String>,
    contact_explanation: Zeroizing<String>,
    body: Zeroizing<String>,
    attachments: Vec<VaultAttachment>,
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self { bytes, offset }
    }

    fn take(&mut self, length: usize) -> VaultResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(VaultError::ItemInvalidFormat)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(VaultError::ItemInvalidFormat)?;
        self.offset = end;
        Ok(value)
    }

    fn take_array<const LENGTH: usize>(&mut self) -> VaultResult<[u8; LENGTH]> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| VaultError::ItemInvalidFormat)
    }

    fn take_u16(&mut self) -> VaultResult<u16> {
        self.take_array().map(u16::from_be_bytes)
    }

    fn take_u32(&mut self) -> VaultResult<u32> {
        self.take_array().map(u32::from_be_bytes)
    }

    fn take_string(&mut self, length: usize) -> VaultResult<Zeroizing<String>> {
        let value =
            core::str::from_utf8(self.take(length)?).map_err(|_| VaultError::ItemInvalidFormat)?;
        Ok(Zeroizing::new(value.to_owned()))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn validate_fields(
    kind: ItemKind,
    title: &str,
    category: &str,
    contact_explanation: &str,
    body: &str,
    error: VaultError,
) -> VaultResult<()> {
    if title.is_empty()
        || title.len() > MAX_TITLE_BYTES
        || title.trim().is_empty()
        || has_disallowed_single_line_character(title)
        || category.len() > MAX_CATEGORY_BYTES
        || has_disallowed_single_line_character(category)
        || contact_explanation.len() > MAX_CONTACT_EXPLANATION_BYTES
        || has_disallowed_multiline_character(contact_explanation)
        || body.len() > MAX_BODY_BYTES
        || has_disallowed_multiline_character(body)
        || (kind == ItemKind::Note && !contact_explanation.is_empty())
    {
        return Err(error);
    }
    Ok(())
}

pub(crate) fn validate_attachment_input(
    filename: &str,
    media_type: &str,
    content_length: usize,
    error: VaultError,
) -> VaultResult<()> {
    if filename.is_empty()
        || filename.len() > MAX_FILENAME_BYTES
        || filename.trim().is_empty()
        || filename
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
        || media_type.len() > MAX_MEDIA_TYPE_BYTES
        || !valid_media_type(media_type)
    {
        return Err(error);
    }
    if content_length > MAX_ATTACHMENT_BYTES {
        return Err(VaultError::AttachmentTooLarge);
    }
    Ok(())
}

fn has_disallowed_single_line_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn has_disallowed_multiline_character(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\t' | '\r' | '\n'))
}

fn valid_media_type(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut parts = value.split('/');
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || kind.is_empty() || subtype.is_empty() {
        return false;
    }
    kind.bytes().chain(subtype.bytes()).all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(
                byte,
                b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
            )
    })
}

fn read_u16(bytes: &[u8]) -> VaultResult<u16> {
    bytes
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| VaultError::ItemInvalidFormat)
}

fn read_bounded_u32(bytes: &[u8], maximum: usize) -> VaultResult<usize> {
    let value = bytes
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| VaultError::ItemInvalidFormat)?;
    let value = usize::try_from(value).map_err(|_| VaultError::ItemInvalidFormat)?;
    if value > maximum {
        return Err(VaultError::ItemInvalidFormat);
    }
    Ok(value)
}

fn push_u16_length(output: &mut Vec<u8>, length: usize) -> VaultResult<()> {
    let length = u16::try_from(length).map_err(|_| VaultError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn push_u32_length(output: &mut Vec<u8>, length: usize) -> VaultResult<()> {
    let length = u32::try_from(length).map_err(|_| VaultError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ItemKind) -> VaultItem {
        VaultItem {
            id: RecordId::from_bytes([1; 16]),
            revision: 1,
            created_at_ms: 2,
            updated_at_ms: 3,
            kind,
            title: Zeroizing::new("Synthetic title".to_owned()),
            category: Zeroizing::new("Synthetic category".to_owned()),
            contact_explanation: Zeroizing::new(if kind == ItemKind::Instruction {
                "Synthetic contact explanation".to_owned()
            } else {
                String::new()
            }),
            body: Zeroizing::new("Synthetic body\nline two".to_owned()),
            attachments: Vec::new(),
        }
    }

    #[test]
    fn canonical_note_and_instruction_round_trip() {
        for kind in [ItemKind::Note, ItemKind::Instruction] {
            let mut source = item(kind);
            source.attachments.push(VaultAttachment {
                id: AttachmentId([7; 16]),
                filename: Zeroizing::new("合成.txt".to_owned()),
                media_type: Zeroizing::new("text/plain".to_owned()),
                content: Zeroizing::new(b"synthetic attachment".to_vec()),
            });
            let encoded = match encode_item(&source) {
                Ok(value) => value,
                Err(error) => panic!("encoding failed: {error}"),
            };
            assert_eq!(&encoded[0..8], &ITEM_MAGIC);
            assert_eq!(&encoded[8..10], &1_u16.to_be_bytes());
            assert_eq!(encoded[10], kind.encoded());
            assert_eq!(encoded[11], 0);
            assert_eq!(&encoded[12..14], &1_u16.to_be_bytes());
            let decoded = match decode_item(&encoded) {
                Ok(value) => value,
                Err(error) => panic!("decoding failed: {error}"),
            };
            assert_eq!(decoded.kind, kind);
            assert_eq!(&*decoded.title, "Synthetic title");
            assert_eq!(decoded.attachments.len(), 1);
            assert_eq!(decoded.attachments[0].content(), b"synthetic attachment");
        }
    }

    #[test]
    fn minimal_note_has_exact_golden_encoding() {
        let mut source = item(ItemKind::Note);
        source.title = Zeroizing::new("A".to_owned());
        source.category = Zeroizing::new(String::new());
        source.body = Zeroizing::new(String::new());
        let encoded = match encode_item(&source) {
            Ok(value) => value,
            Err(error) => panic!("encoding failed: {error}"),
        };
        let expected = [
            b'A', b'E', b'T', b'R', b'I', b'T', b'M', 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, b'A',
        ];
        assert_eq!(&*encoded, &expected);
    }

    #[test]
    fn exact_attachment_boundary_and_worst_case_payload_fit() {
        let maximum = ITEM_HEADER_LENGTH
            + MAX_TITLE_BYTES
            + MAX_CATEGORY_BYTES
            + MAX_CONTACT_EXPLANATION_BYTES
            + MAX_BODY_BYTES
            + (MAX_ATTACHMENT_COUNT * ATTACHMENT_HEADER_LENGTH)
            + (MAX_ATTACHMENT_COUNT * MAX_FILENAME_BYTES)
            + (MAX_ATTACHMENT_COUNT * MAX_MEDIA_TYPE_BYTES)
            + MAX_ATTACHMENT_BYTES;
        assert_eq!(maximum, 929_358);
        assert_eq!(MAX_PLAINTEXT_LENGTH - maximum, 119_218);

        let mut maximum_source = item(ItemKind::Instruction);
        maximum_source.title = Zeroizing::new("t".repeat(MAX_TITLE_BYTES));
        maximum_source.category = Zeroizing::new("c".repeat(MAX_CATEGORY_BYTES));
        maximum_source.contact_explanation =
            Zeroizing::new("e".repeat(MAX_CONTACT_EXPLANATION_BYTES));
        maximum_source.body = Zeroizing::new("b".repeat(MAX_BODY_BYTES));
        let maximum_media_type = format!("a/{}", "z".repeat(MAX_MEDIA_TYPE_BYTES - 2));
        for index in 0..MAX_ATTACHMENT_COUNT {
            maximum_source.attachments.push(VaultAttachment {
                id: AttachmentId([u8::try_from(index + 1).unwrap_or(1); 16]),
                filename: Zeroizing::new("f".repeat(MAX_FILENAME_BYTES)),
                media_type: Zeroizing::new(maximum_media_type.clone()),
                content: Zeroizing::new(if index == 0 {
                    vec![0xa5; MAX_ATTACHMENT_BYTES]
                } else {
                    Vec::new()
                }),
            });
        }
        let maximum_encoded = match encode_item(&maximum_source) {
            Ok(value) => value,
            Err(error) => panic!("maximum encoding failed: {error}"),
        };
        assert_eq!(maximum_encoded.len(), maximum);

        let mut source = item(ItemKind::Note);
        source.attachments.push(VaultAttachment {
            id: AttachmentId([8; 16]),
            filename: Zeroizing::new("boundary.bin".to_owned()),
            media_type: Zeroizing::new("application/octet-stream".to_owned()),
            content: Zeroizing::new(vec![0xa5; MAX_ATTACHMENT_BYTES]),
        });
        assert!(encode_item(&source).is_ok());
        source.attachments[0].content = Zeroizing::new(vec![0xa5; MAX_ATTACHMENT_BYTES + 1]);
        assert_eq!(
            encode_item(&source).err(),
            Some(VaultError::AttachmentTooLarge)
        );
    }

    #[test]
    fn decoder_rejects_unknown_truncated_extended_and_invalid_utf8_payloads() {
        let encoded = match encode_item(&item(ItemKind::Note)) {
            Ok(value) => value,
            Err(error) => panic!("encoding failed: {error}"),
        };
        for index in [0, 8, 10, 11] {
            let mut tampered = encoded.to_vec();
            tampered[index] ^= 0xff;
            assert_eq!(
                decode_item(&tampered).err(),
                Some(VaultError::ItemUnsupportedVersion)
            );
        }
        assert_eq!(
            decode_item(&encoded[..encoded.len() - 1]).err(),
            Some(VaultError::ItemInvalidFormat)
        );
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert_eq!(
            decode_item(&extended).err(),
            Some(VaultError::ItemInvalidFormat)
        );
        let mut invalid_utf8 = encoded.to_vec();
        invalid_utf8[ITEM_HEADER_LENGTH] = 0xff;
        assert_eq!(
            decode_item(&invalid_utf8).err(),
            Some(VaultError::ItemInvalidFormat)
        );

        let mut impossible_title = encoded.to_vec();
        impossible_title[14..18].copy_from_slice(
            &u32::try_from(MAX_TITLE_BYTES + 1)
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        assert_eq!(
            decode_item(&impossible_title).err(),
            Some(VaultError::ItemInvalidFormat)
        );

        let mut impossible_count = encoded.to_vec();
        impossible_count[12..14].copy_from_slice(&9_u16.to_be_bytes());
        assert_eq!(
            decode_item(&impossible_count).err(),
            Some(VaultError::ItemInvalidFormat)
        );
    }

    #[test]
    fn decoder_rejects_duplicate_attachment_ids() {
        let mut source = item(ItemKind::Note);
        for identifier in [1_u8, 2] {
            source.attachments.push(VaultAttachment {
                id: AttachmentId([identifier; 16]),
                filename: Zeroizing::new("a".to_owned()),
                media_type: Zeroizing::new(String::new()),
                content: Zeroizing::new(Vec::new()),
            });
        }
        let mut encoded = match encode_item(&source) {
            Ok(value) => value.to_vec(),
            Err(error) => panic!("encoding failed: {error}"),
        };
        let fields_length = source.title.len()
            + source.category.len()
            + source.contact_explanation.len()
            + source.body.len();
        let first_attachment = ITEM_HEADER_LENGTH + fields_length;
        let second_attachment = first_attachment + ATTACHMENT_HEADER_LENGTH + 1;
        let first_id = encoded[first_attachment..first_attachment + 16].to_vec();
        encoded[second_attachment..second_attachment + 16].copy_from_slice(&first_id);
        assert_eq!(
            decode_item(&encoded).err(),
            Some(VaultError::ItemInvalidFormat)
        );
    }

    #[test]
    fn field_filename_and_media_type_rules_are_exact() {
        assert!(
            ItemDraft::new(
                ItemKind::Note,
                " ".to_owned(),
                String::new(),
                String::new(),
                String::new()
            )
            .is_err()
        );
        assert!(
            ItemDraft::new(
                ItemKind::Note,
                "Title".to_owned(),
                String::new(),
                "not allowed".to_owned(),
                String::new()
            )
            .is_err()
        );
        assert!(
            ItemDraft::new(
                ItemKind::Instruction,
                "标题".to_owned(),
                "类别".to_owned(),
                "联系说明".to_owned(),
                "正文".to_owned()
            )
            .is_ok()
        );
        assert!(validate_attachment_input("empty.bin", "", 0, VaultError::InvalidInput).is_ok());
        assert!(
            validate_attachment_input("same.txt", "text/plain", 1, VaultError::InvalidInput)
                .is_ok()
        );
        assert!(
            validate_attachment_input("../bad", "text/plain", 1, VaultError::InvalidInput).is_err()
        );
        assert!(
            validate_attachment_input("bad.bin", "Text/Plain", 1, VaultError::InvalidInput)
                .is_err()
        );
        assert!(
            validate_attachment_input(
                "bad.bin",
                "text/plain;charset=utf-8",
                1,
                VaultError::InvalidInput
            )
            .is_err()
        );
    }

    #[test]
    fn debug_output_redacts_all_user_content() {
        let draft = ItemDraft::new(
            ItemKind::Note,
            "sensitive title".to_owned(),
            String::new(),
            String::new(),
            "sensitive body".to_owned(),
        );
        let draft = match draft {
            Ok(value) => value,
            Err(error) => panic!("draft failed: {error}"),
        };
        let debug = format!("{draft:?}");
        assert!(!debug.contains("sensitive title"));
        assert!(!debug.contains("sensitive body"));
    }
}
