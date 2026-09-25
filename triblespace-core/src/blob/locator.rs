//! Opaque discovery names for bearer-addressed blobs.
//!
//! A content handle is also the capability to read its exact bytes. A locator
//! is only a one-way image of that handle: it can be disclosed for discovery
//! and reference summaries without disclosing the bearer capability itself.

/// Random 32-byte context key that separates locators from every other
/// BLAKE3 input. Generated from the OS random source on 2026-09-24.
///
/// `LOCATOR_CONTEXT || H` is exactly one 64-byte BLAKE3 block, so a locator
/// costs one compression. The previous `derive_key` string context cost two:
/// one for the context string and one for the handle.
pub const LOCATOR_CONTEXT: [u8; 32] =
    hex_literal::hex!("224DFBA2A0DE0FEC0A2073D78B8DCFEE91A037BC7749639A0D5E83DF307BA93A");

/// Derive an opaque discovery locator without disclosing the bearer handle.
///
/// `L = BLAKE3(LOCATOR_CONTEXT || H)`. Possession of this locator does not
/// authorize an exact blob read.
pub fn blob_locator(handle: [u8; 32]) -> [u8; 32] {
    let mut block = [0; 64];
    block[..32].copy_from_slice(&LOCATOR_CONTEXT);
    block[32..].copy_from_slice(&handle);
    *blake3::hash(&block).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_matches_its_known_answer() {
        // Computed independently with the reference blake3 crate as
        // blake3::hash(LOCATOR_CONTEXT || [1; 32]). The bytes are wire
        // format: every peer must derive the same DHT key.
        assert_eq!(
            blob_locator([1; 32]),
            hex_literal::hex!("501F0C513B16AB49D80B1C440F848C18A3DDE215F802026B8CEE5C71515CCC51")
        );
    }

    #[test]
    fn locator_is_not_the_handle() {
        for handle in [[0; 32], [1; 32], [255; 32]] {
            assert_ne!(blob_locator(handle), handle);
        }
    }
}
