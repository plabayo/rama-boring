//! ChaCha20 stream cipher (RFC 8439).
use crate::ffi;

/// Apply ChaCha20 in place. The key, nonce and block counter must not be reused.
/// Panics if processing the buffer would wrap the block counter.
pub fn apply(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buffer: &mut [u8]) {
    let blocks = buffer.len().div_ceil(64) as u64;
    assert!(
        blocks <= u64::from(u32::MAX) - u64::from(counter) + 1,
        "ChaCha20 block counter overflow"
    );
    unsafe {
        ffi::CRYPTO_chacha_20(
            buffer.as_mut_ptr(),
            buffer.as_ptr(),
            buffer.len(),
            key.as_ptr(),
            nonce.as_ptr(),
            counter,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_block_vector() {
        let key = std::array::from_fn(|i| i as u8);
        let nonce = hex::decode("000000090000004a00000000")
            .unwrap()
            .try_into()
            .unwrap();
        let mut block = [0; 64];
        apply(&key, &nonce, 1, &mut block);
        assert_eq!(hex::encode(block), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }

    #[test]
    #[should_panic(expected = "ChaCha20 block counter overflow")]
    fn counter_cannot_wrap() {
        apply(&[0; 32], &[0; 12], u32::MAX, &mut [0; 65]);
    }
}
