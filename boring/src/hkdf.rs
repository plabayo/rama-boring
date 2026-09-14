//! HKDF extraction and expansion (RFC 5869).
use crate::{cvt, error::ErrorStack, ffi, hash::MessageDigest};

/// Extract a pseudorandom key into a digest-sized output buffer.
pub fn extract(
    digest: MessageDigest,
    salt: &[u8],
    secret: &[u8],
    output: &mut [u8],
) -> Result<(), ErrorStack> {
    assert_eq!(
        output.len(),
        digest.size(),
        "HKDF extraction output must match the digest size"
    );
    let mut len = 0;
    unsafe {
        cvt(ffi::HKDF_extract(
            output.as_mut_ptr(),
            &mut len,
            digest.as_ptr(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        ))
        .map(|_| ())
    }
}

/// Expand a pseudorandom key, with at most 255 digest-sized blocks of output.
pub fn expand(
    digest: MessageDigest,
    secret: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), ErrorStack> {
    unsafe {
        cvt(ffi::HKDF_expand(
            output.as_mut_ptr(),
            output.len(),
            digest.as_ptr(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        ))
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_case_one_and_expansion_limit() {
        let mut prk = [0; 32];
        let salt: Vec<_> = (0..=12).collect();
        let info: Vec<_> = (0xf0..=0xf9).collect();
        extract(MessageDigest::sha256(), &salt, &[0x0b; 22], &mut prk).unwrap();
        assert_eq!(
            hex::encode(prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut output = [0; 42];
        expand(MessageDigest::sha256(), &prk, &info, &mut output).unwrap();
        assert_eq!(
            hex::encode(output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        expand(MessageDigest::sha256(), &prk, &info, &mut [0; 255 * 32]).unwrap();
        assert!(expand(MessageDigest::sha256(), &prk, &info, &mut [0; 255 * 32 + 1]).is_err());
    }
}
