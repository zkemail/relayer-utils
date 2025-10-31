/// Pads a string to the specified size with zero bytes
///
/// # Arguments
/// * `s` - The string to pad
/// * `target_len` - The target length in bytes
///
/// # Returns
/// A vector of bytes padded to target_len with zeros
///
/// # Behavior
/// - If the input string is shorter than `target_len`, it will be padded with zeros
/// - If the input string is exactly `target_len` bytes, it will be returned as-is
/// - If the input string exceeds `target_len`, it will be **silently truncated** to `target_len`
///
/// # Security Note
/// Callers must validate input length before calling this function to prevent truncation.
/// See `PaddedEmailAddr::from_email_addr()` for an example of proper validation.
pub fn pad_string(s: &str, target_len: usize) -> Vec<u8> {
    let mut padded = s.as_bytes().to_vec();
    padded.resize(target_len, 0);
    padded
}

/// Pads a byte slice to the specified size with zero bytes
///
/// # Arguments
/// * `data` - The bytes to pad
/// * `target_len` - The target length in bytes
///
/// # Returns
/// A vector of bytes padded to target_len with zeros
pub fn pad_bytes(data: &[u8], target_len: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.resize(target_len, 0);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_string() {
        let input = "hello";
        let padded = pad_string(input, 10);
        assert_eq!(padded.len(), 10);
        assert_eq!(&padded[0..5], b"hello");
        assert_eq!(&padded[5..10], &[0u8; 5]);
    }

    #[test]
    fn test_pad_bytes() {
        let input = vec![1, 2, 3];
        let padded = pad_bytes(&input, 6);
        assert_eq!(padded.len(), 6);
        assert_eq!(&padded[0..3], &[1, 2, 3]);
        assert_eq!(&padded[3..6], &[0, 0, 0]);
    }
}
