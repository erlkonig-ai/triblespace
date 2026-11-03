//! Byte identity and validity semantics of the prototype `ZTrible` row.
//! That the derives in `support/ztrible.rs` compile is itself the first check.

#[path = "support/ztrible.rs"]
mod ztrible;

use ztrible::{PackedId, ZTrible};

#[test]
fn ztrible_layout_is_64_bytes_align_1() {
    assert_eq!(core::mem::size_of::<ZTrible>(), 64);
    assert_eq!(core::mem::align_of::<ZTrible>(), 1);
    assert_eq!(core::mem::size_of::<PackedId>(), 16);
    assert_eq!(core::mem::align_of::<PackedId>(), 1);
}
