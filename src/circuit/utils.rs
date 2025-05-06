use anyhow::{anyhow, Result};
use regex::Regex;

/// Finds a selector string in cleaned content and maps it back to its original position.
///
/// # Arguments
/// * `clean_content` - The cleaned content as a slice of bytes (no QP soft line breaks).
/// * `selector` - The string to find in the cleaned content.
/// * `position_map` - A slice mapping cleaned indices to original indices.
///                    For each i, `position_map[i]` is the index in `original_body` where that cleaned byte originated.
///                    If `position_map[i]` is `usize::MAX`, that cleaned position has no corresponding original position.
///
/// # Returns
/// A tuple containing `(selector, original_index)`.
///
/// # Errors
/// Returns an error if the selector is not found in the cleaned content or if the position mapping fails.
pub fn find_selector_in_clean_content(
    clean_content: &[u8],
    selector: &str,
    position_map: &[usize],
) -> Result<(String, usize, usize)> {
    let clean_string = String::from_utf8_lossy(clean_content);
    let re = Regex::new(selector).unwrap();
    if let Some(m) = re.find(&clean_string) {
        let selector_start_index = m.start();
        let selector_end_index = m.end();
        // Map this cleaned index back to original
        if selector_start_index < position_map.len() && selector_end_index < position_map.len() {
            let original_start_index = position_map[selector_start_index];
            let original_end_index = position_map[selector_end_index];
            if original_start_index == usize::MAX || original_end_index == usize::MAX {
                return Err(anyhow!("Failed to map selector position to original body"));
            }
            Ok((
                selector.to_string(),
                original_start_index,
                original_end_index,
            ))
        } else {
            Err(anyhow!("Selector index out of range in position map"))
        }
    } else {
        Err(anyhow!(
            "SHA precompute selector \"{}\" not found in cleaned body",
            selector
        ))
    }
}

/// Gets the adjusted selector string that accounts for potential soft line breaks in QP encoding.
/// If the selector exists in the original body, returns it as-is. Otherwise, finds it in cleaned
/// content and maps it back to the original format, including any soft line breaks.
///
/// # Arguments
/// * `original_body` - The original body as a slice of bytes, possibly containing QP soft line breaks.
/// * `selector` - The string to find in the content.
/// * `clean_content` - The cleaned content with soft line breaks removed.
/// * `position_map` - The index mapping from cleaned content to original content.
///
/// # Returns
/// The adjusted selector string that matches the original body format.
///
/// # Errors
/// Returns an error if the selector cannot be found in either the original or cleaned content.
pub fn get_adjusted_selector(
    original_body: &[u8],
    selector: &str,
    clean_content: &[u8],
    position_map: &[usize],
) -> Result<String> {
    let original_str = String::from_utf8_lossy(original_body);

    // First, try finding the selector in the original body as-is
    if original_str.contains(selector) {
        return Ok(selector.to_string());
    }

    // If not found, we must find it in the cleaned content and map back to original
    let (_, original_start_index, original_end_index) =
        find_selector_in_clean_content(clean_content, selector, position_map)?;

    // Retrieve the substring from the original body that corresponds to the found selector
    let adjusted_slice = &original_body[original_start_index..original_end_index];

    // Convert back to a string. If invalid UTF-8, use lossy conversion.
    let adjusted_str = regex::escape(&String::from_utf8_lossy(adjusted_slice));
    Ok(adjusted_str.to_string())
}
