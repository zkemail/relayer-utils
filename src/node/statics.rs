//! Static utility function for working with the `tokio` runtime.

use neon::{context::Context, result::NeonResult};
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;

/// Retrieves a reference to a lazily-initialized, static `Runtime` instance.
///
/// This function uses `OnceCell` to ensure that the `Runtime` is initialized at most once.
/// Subsequent calls will return the previously initialized `Runtime`.
///
/// # Arguments
///
/// * `cx` - A mutable reference to the context, allowing interaction with the Neon runtime.
///
/// # Returns
///
/// A `NeonResult` containing a reference to the `Runtime` or an error if initialization fails.
pub(crate) fn runtime<'a, C: Context<'a>>(cx: &mut C) -> NeonResult<&'static Runtime> {
    static RUNTIME: OnceCell<Runtime> = OnceCell::new();

    // Attempt to get the `Runtime`, or initialize it if it hasn't been already.
    RUNTIME.get_or_try_init(|| Runtime::new().or_else(|err| cx.throw_error(err.to_string())))
}
