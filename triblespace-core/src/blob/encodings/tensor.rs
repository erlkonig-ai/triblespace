//! Self-describing typed tensor blob encoding.
//!
//! [`Array<T>`](super::array::Array) says "a flat run of T" and leaves shape to
//! triples that reference it. A `Tensor` carries its shape INSIDE the blob, so
//! moving one between machines moves its shape with it — a blob transfer rather
//! than a blob transfer plus a side-channel for dimensions.
//!
//! It carries NOTHING ELSE. No magic marker, no rank field. Both were in an
//! earlier version and both were redundant: the element type and rank come from
//! the attribute that points at the blob, and content addressing means a handle
//! names exact bytes, so a marker could only catch a corruption hashing already
//! rules out. A redundant tag is worse than none — it looks like a check while
//! verifying nothing the reference had not already settled.
//!
//! # What is in the type, and why the rest is not
//!
//! `Tensor<T, RANK>` puts the element format and the rank in the type, so its
//! blob-encoding id is derived per `(element, rank)` — a rank-2 `F32` tensor is
//! structurally a different encoding from a rank-2 `BF16` one, and a query for
//! the first cannot match the second.
//!
//! Exact dimensions are NOT in the type. Encoding them would need one Rust type
//! per distinct shape, and Rust does not admit `[usize; RANK]` as a
//! const-generic parameter anyway. They live in the header, validated on read.
//!
//! # Logical dims, derived length
//!
//! The header records LOGICAL dimensions and the payload length is computed
//! from them. That is what keeps a packed format honest: an NVFP4 tensor of
//! `[256, 4096, 4096]` says 4096, not the 2048 bytes-per-row its packing would
//! suggest. Checkpoints that store the packed shape need a second field
//! recording the real one — Inkling's `original_shape`, present on 78 tensors —
//! and every reader has to know to consult it. Here there is nothing to
//! consult, because the shape was never wrong.
//!
//! # Block-scaled formats are ONE element type
//!
//! NVFP4 is not "E2M1 elements plus a scale decision". `hf_quant_config.json`
//! calls the whole scheme `NVFP4`: E2M1 elements, a fixed block size, E4M3
//! block scales, one FP32 global scale. So it is a single [`TensorElement`]
//! that knows its own storage requirement, and the scales live inside the same
//! blob as the data they scale. As separate tensors bound by a naming
//! convention — `w13_weight`, `.scale`, `.scale2` — nothing makes the bundle
//! atomic and a reader holding only the first has bytes it cannot interpret.

use core::marker::PhantomData;

use anybytes::Bytes;

use crate::blob::{Blob, BlobEncoding, TryFromBlob};
use crate::macros::entity;
use crate::metadata::{self, MetaDescribe};
use crate::trible::Fragment;

/// Header width, chosen so the TENSOR that follows it is 256-byte aligned.
///
/// The alignment is a chain, and every link has to hold:
///
/// * a current generic-envelope pile record's data begins at
///   `record_start + 256`, and its span is measured in 256-byte blocks, so a
///   blob's first byte is 256-aligned in a current-format pile;
/// * this header is 256 wide, so the payload begins 256 bytes later;
/// * therefore the payload is 256-aligned in the file, which is what CUDA and
///   Metal want for a zero-copy storage-buffer binding.
///
/// A header sized to fit the dims would break the second link and put every
/// tensor's payload at a different alignment — saving a few dozen bytes and
/// costing the property the whole 256 story exists for. At rank 3, 232 of
/// these bytes are spare.
pub const TENSOR_HEADER_LEN: usize = 256;

/// Largest rank the header can hold: one `u64` dimension per 8 bytes.
///
/// The whole header is dimensions now that the magic and rank field are gone,
/// which is what makes this exactly 32 rather than 29.
pub const MAX_RANK: usize = TENSOR_HEADER_LEN / 8;

/// An element format, including what it costs to store.
///
/// Deliberately NOT modelled on [`ArrayElement`](super::array::ArrayElement),
/// which requires `type Native`. A 4-bit float has no native Rust type, and
/// demanding one would either exclude the formats this encoding exists to carry
/// or force them to masquerade as `u8` — which is the confusion being removed.
pub trait TensorElement: MetaDescribe + 'static {
    /// Bits per LOGICAL element: 32 for f32, 4 for NVFP4's E2M1.
    const BITS: usize;

    /// Payload bytes for `elems` logical elements, INCLUDING any scale planes
    /// the format defines. A format that is more than its elements accounts for
    /// itself here rather than making every caller remember.
    ///
    /// Returns `None` when the exact length cannot be represented by `usize`.
    /// Implementors must check their complete format-specific calculation;
    /// wrapping or saturation cannot establish a valid payload extent.
    fn payload_len(elems: usize) -> Option<usize>;
}

/// A tensor of `T` with `RANK` dimensions.
pub struct Tensor<T: TensorElement, const RANK: usize>(PhantomData<T>);

impl<T: TensorElement, const RANK: usize> BlobEncoding for Tensor<T, RANK> {}

impl<T: TensorElement, const RANK: usize> MetaDescribe for Tensor<T, RANK> {
    fn describe() -> Fragment {
        // Identity derives from these facts, and the facts ARE the annotation:
        // an attribute of this encoding is queryable by rank and by element
        // schema without a second mechanism recording them. That is why the
        // rank is written as a fact rather than only living in the type.
        let mut core = entity! {
            metadata::array_item_schema*: T::describe(),
            metadata::tensor_rank: RANK as i64,
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        };
        let id = core.root().expect("rooted");
        let id_ref = crate::id::ExclusiveId::force_ref(&id);
        core += entity! { id_ref @
            metadata::name: "tensor",
            metadata::description:
                "Typed tensor: fixed 256-byte header carrying logical \
                 dimensions, followed by the payload. Self-describing, so a \
                 handle is interpretable without accompanying facts.",
        };
        core
    }
}

/// A tensor blob that failed to decode.
#[derive(Debug, PartialEq, Eq)]
pub enum TensorError {
    /// Shorter than the fixed header.
    TooShort { len: usize },
    /// The payload is not the length the header's dims imply.
    LengthMismatch { expected: usize, found: usize },
    /// A rank the fixed header cannot hold.
    RankTooLarge { rank: usize },
    /// Logical element count or complete byte extent is not representable.
    ExtentOverflow,
}

impl core::fmt::Display for TensorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TensorError::TooShort { len } => {
                write!(
                    f,
                    "tensor blob is {len} bytes, shorter than its {TENSOR_HEADER_LEN}-byte header"
                )
            }
            TensorError::LengthMismatch { expected, found } => {
                write!(f, "tensor payload is {found} bytes, dims imply {expected}")
            }
            TensorError::RankTooLarge { rank } => {
                write!(
                    f,
                    "rank {rank} exceeds the {MAX_RANK} a fixed header can hold"
                )
            }
            TensorError::ExtentOverflow => {
                write!(f, "tensor element count or byte extent overflows")
            }
        }
    }
}

impl core::error::Error for TensorError {}

/// A decoded tensor: its logical shape, and its payload bytes.
#[derive(Debug)]
pub struct TensorView {
    dims: Vec<u64>,
    elems: usize,
    payload: Bytes,
}

impl TensorView {
    /// Logical dimensions, as written. Never the packed shape.
    pub fn dims(&self) -> &[u64] {
        &self.dims
    }

    /// Logical element count.
    pub fn elems(&self) -> usize {
        self.elems
    }

    /// Payload bytes, including any scale planes the element format defines.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// Validate geometry before either constructing or exposing a typed view.
fn tensor_extent<T: TensorElement>(dims: &[u64]) -> Result<(usize, usize), TensorError> {
    // An empty axis makes the whole tensor empty regardless of axis order.
    // Do this first: a preceding product may otherwise overflow before zero.
    // The empty product (rank zero) remains one scalar element.
    let elems = if dims.contains(&0) {
        0
    } else {
        dims.iter()
            .try_fold(1u64, |n, &dim| n.checked_mul(dim))
            .ok_or(TensorError::ExtentOverflow)?
    };
    let elems = usize::try_from(elems).map_err(|_| TensorError::ExtentOverflow)?;
    let expected = T::payload_len(elems).ok_or(TensorError::ExtentOverflow)?;
    TENSOR_HEADER_LEN
        .checked_add(expected)
        .ok_or(TensorError::ExtentOverflow)?;
    Ok((elems, expected))
}

/// Build a tensor blob from logical dims and a payload.
///
/// Fallible on purpose. The payload length is checked against what the dims and
/// element format imply, here, once — rather than trusted and discovered later
/// as a misread tensor, which produces plausible numbers instead of an error.
pub fn tensor_blob<T: TensorElement, const RANK: usize>(
    dims: [u64; RANK],
    payload: Bytes,
) -> Result<Blob<Tensor<T, RANK>>, TensorError> {
    if RANK > MAX_RANK {
        return Err(TensorError::RankTooLarge { rank: RANK });
    }
    let (_, expected) = tensor_extent::<T>(&dims)?;
    if payload.len() != expected {
        return Err(TensorError::LengthMismatch {
            expected,
            found: payload.len(),
        });
    }

    let mut bytes = Vec::with_capacity(TENSOR_HEADER_LEN + payload.len());
    for d in dims {
        bytes.extend_from_slice(&d.to_le_bytes());
    }
    debug_assert_eq!(bytes.len(), RANK * 8);
    bytes.resize(TENSOR_HEADER_LEN, 0);
    bytes.extend_from_slice(&payload);
    Ok(Blob::new(Bytes::from_source(bytes)))
}

impl<T: TensorElement, const RANK: usize> TryFromBlob<Tensor<T, RANK>> for TensorView {
    type Error = TensorError;

    fn try_from_blob(blob: Blob<Tensor<T, RANK>>) -> Result<Self, Self::Error> {
        let bytes = blob.bytes;
        if bytes.len() < TENSOR_HEADER_LEN {
            return Err(TensorError::TooShort { len: bytes.len() });
        }
        // Checked on the READ side too, not only where blobs are built. RANK is
        // a const generic a caller names freely, and the dim loop would
        // otherwise run off the fixed header and read payload bytes as
        // dimensions — a plausible-looking tensor rather than an error.
        if RANK > MAX_RANK {
            return Err(TensorError::RankTooLarge { rank: RANK });
        }
        let mut dims = Vec::with_capacity(RANK);
        for i in 0..RANK {
            let at = i * 8;
            dims.push(u64::from_le_bytes(
                bytes[at..at + 8].try_into().expect("8 bytes"),
            ));
        }
        let (elems, expected) = tensor_extent::<T>(&dims)?;
        let payload = bytes.slice(TENSOR_HEADER_LEN..);
        if payload.len() != expected {
            return Err(TensorError::LengthMismatch {
                expected,
                found: payload.len(),
            });
        }
        Ok(TensorView {
            dims,
            elems,
            payload,
        })
    }
}

/// Element formats.
pub mod elements {
    use super::TensorElement;
    use crate::macros::entity;
    use crate::metadata::{self, MetaDescribe};
    use crate::trible::Fragment;

    macro_rules! dense_element {
        ($marker:ident, $bits:expr, $id:expr, $doc:expr) => {
            #[doc = $doc]
            pub struct $marker;

            impl MetaDescribe for $marker {
                fn describe() -> Fragment {
                    let id = crate::id_hex!($id);
                    entity! { crate::id::ExclusiveId::force_ref(&id) @
                        metadata::name:        stringify!($marker),
                        metadata::description: $doc,
                    }
                }
            }

            impl TensorElement for $marker {
                const BITS: usize = $bits;

                fn payload_len(elems: usize) -> Option<usize> {
                    // Every dense format declared below uses whole bytes.
                    elems.checked_mul(Self::BITS / 8)
                }
            }
        };
    }

    dense_element!(
        F32,
        32,
        "92F4DB8D84519C8D6E212CB810FF40D4",
        "32-bit IEEE-754 float."
    );
    dense_element!(
        F64,
        64,
        "FA3AD8DEC844D5F409AB728269B7A3FE",
        "64-bit IEEE-754 float."
    );
    dense_element!(
        F16,
        16,
        "0E7E69818968BCD97A540DE30B9E605D",
        "16-bit IEEE-754 half float."
    );
    dense_element!(
        BF16,
        16,
        "8656DFBC50009089603533E4558D05C6",
        "16-bit bfloat."
    );
    dense_element!(
        U8,
        8,
        "D16AC7C02F25E4799F4D47EB1E51EF6E",
        "Unsigned 8-bit integer."
    );
    dense_element!(
        E4M3,
        8,
        "5453AA907D7EDF3A61B07E0DFBA53CFC",
        "8-bit float, 4-bit exponent, 3-bit mantissa."
    );

    /// NVFP4: E2M1 elements in blocks of 16 with E4M3 block scales and one
    /// FP32 global scale.
    ///
    /// One element type, not a composition, because the format fixes all three
    /// choices — `quant_algo: "NVFP4"` names the whole scheme. The scales are
    /// part of the payload for the same reason: a blob carrying elements
    /// without the scales that interpret them is bytes, not a tensor.
    pub struct NVFP4;

    /// Logical elements per block scale.
    pub const NVFP4_BLOCK: usize = 16;

    impl MetaDescribe for NVFP4 {
        fn describe() -> Fragment {
            let id = crate::id_hex!("7C1AD2F9BEEE5EEF42F168DCD2A10BC1");
            entity! { crate::id::ExclusiveId::force_ref(&id) @
                metadata::name: "NVFP4",
                metadata::description:
                    "NVFP4: E2M1 elements, blocks of 16, E4M3 block scales, \
                     one FP32 global scale. Scales travel in the payload.",
            }
        }
    }

    impl TensorElement for NVFP4 {
        const BITS: usize = 4;

        fn payload_len(elems: usize) -> Option<usize> {
            let packed = elems.div_ceil(2);
            let blocks = elems.div_ceil(NVFP4_BLOCK);
            packed.checked_add(blocks)?.checked_add(4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::elements::{BF16, F32, NVFP4, NVFP4_BLOCK};
    use super::*;

    fn payload(n: usize) -> Bytes {
        Bytes::from_source(vec![0u8; n])
    }

    /// The id is derived per (element, rank), so a query for one cannot match
    /// the other. This is the property the whole encoding exists for.
    #[test]
    fn element_and_rank_both_discriminate_the_encoding() {
        let f32_2 = <Tensor<F32, 2> as MetaDescribe>::id();
        let bf16_2 = <Tensor<BF16, 2> as MetaDescribe>::id();
        let f32_3 = <Tensor<F32, 3> as MetaDescribe>::id();
        assert_ne!(f32_2, bf16_2, "element type must discriminate");
        assert_ne!(f32_2, f32_3, "rank must discriminate");
        assert_eq!(
            f32_2,
            <Tensor<F32, 2> as MetaDescribe>::id(),
            "and be stable"
        );
    }

    #[test]
    fn dims_and_payload_survive_a_roundtrip() {
        let blob = tensor_blob::<F32, 2>([3, 4], payload(3 * 4 * 4)).expect("well formed");
        let view: TensorView = blob.try_from_blob().expect("decodes");
        assert_eq!(view.dims(), &[3, 4]);
        assert_eq!(view.elems(), 12);
        assert_eq!(view.payload().len(), 48);
    }

    /// THE packing property. An NVFP4 tensor states its LOGICAL last dim; the
    /// byte length is derived. A checkpoint storing the packed shape needs a
    /// second field to recover the truth — here there is nothing to recover.
    #[test]
    fn a_packed_tensor_states_its_logical_shape() {
        let elems = 4096usize;
        let expected = elems / 2 + elems / NVFP4_BLOCK + 4;
        let blob = tensor_blob::<NVFP4, 1>([elems as u64], payload(expected)).expect("well formed");
        let view: TensorView = blob.try_from_blob().expect("decodes");
        assert_eq!(
            view.dims(),
            &[4096],
            "logical, not the 2048 bytes it packs into"
        );
        assert_eq!(view.elems(), 4096);
        assert!(view.payload().len() < elems, "and it really is packed");
    }

    /// Scales are payload, not a separate blob bound by naming convention.
    #[test]
    fn nvfp4_payload_accounts_for_its_own_scales() {
        assert_eq!(
            NVFP4::payload_len(16),
            Some(8 + 1 + 4),
            "8 packed + 1 block scale + global"
        );
        assert_eq!(NVFP4::payload_len(32), Some(16 + 2 + 4));
        assert_eq!(
            F32::payload_len(32),
            Some(128),
            "a dense format is just its elements"
        );
    }

    /// Measured against Inkling-Small, whose 78 quantised tensors are each
    /// rank-3 `[256, 4096, 2048]` with `scale [256, 4096, 256]` and
    /// `scale2 [256]`. That is 256 INDEPENDENT expert tensors stacked, not one
    /// tensor with 256 global scales — data, scales and scale2 all slice
    /// cleanly on the outermost dimension. So one expert is a rank-2 NVFP4
    /// tensor with a single global scale, which is what this encoding models.
    ///
    /// Storing them per-expert is also what makes a checkpoint shareable: a
    /// node fetches the experts it holds rather than a 12 GiB slab it either
    /// has or does not.
    #[test]
    fn one_inkling_expert_is_a_rank_2_nvfp4_tensor() {
        let (rows, cols) = (4096usize, 4096usize);
        let elems = rows * cols;
        let packed = elems / 2;
        let block_scales = elems / NVFP4_BLOCK;
        assert_eq!(
            packed,
            4096 * 2048,
            "matches the checkpoint's packed last dim"
        );
        assert_eq!(
            block_scales,
            4096 * 256,
            "matches the scale tensor's last dim"
        );
        assert_eq!(
            NVFP4::payload_len(elems),
            Some(packed + block_scales + 4),
            "one expert carries one global scale"
        );
        let blob = tensor_blob::<NVFP4, 2>(
            [rows as u64, cols as u64],
            payload(NVFP4::payload_len(elems).expect("bounded expert extent")),
        )
        .expect("well formed");
        let view: TensorView = blob.try_from_blob().expect("decodes");
        assert_eq!(view.dims(), &[4096, 4096], "logical, not the packed 2048");
    }

    /// A payload that does not match the dims is refused where it is cheap to
    /// refuse. Accepted, it would read later as a differently-shaped tensor and
    /// produce plausible numbers rather than an error.
    #[test]
    fn a_payload_that_contradicts_the_dims_is_refused() {
        let err = tensor_blob::<F32, 2>([3, 4], payload(40)).expect_err("must refuse");
        assert_eq!(
            err,
            TensorError::LengthMismatch {
                expected: 48,
                found: 40
            }
        );
    }

    /// Reading a rank-2 blob as rank-3 is still caught, just by a different
    /// route now that no rank is stored: the third dimension reads out of the
    /// header's zero padding, so the dims imply an empty payload and the actual
    /// one contradicts it. The check that survives is the one over real data.
    #[test]
    fn reading_a_tensor_at_the_wrong_rank_is_refused() {
        let blob = tensor_blob::<F32, 2>([3, 4], payload(48)).expect("well formed");
        let wrong: Blob<Tensor<F32, 3>> = blob.transmute();
        let err = <TensorView as TryFromBlob<Tensor<F32, 3>>>::try_from_blob(wrong)
            .expect_err("must refuse");
        assert_eq!(
            err,
            TensorError::LengthMismatch {
                expected: 0,
                found: 48
            }
        );
    }

    /// The payload begins at a constant offset regardless of rank, so it keeps
    /// the 256 alignment a pile record already gives its data.
    /// The header is dimensions and nothing else, so every field is a u64 at an
    /// 8-aligned offset by construction and the capacity is exactly 256/8.
    #[test]
    fn the_header_is_nothing_but_dimensions() {
        assert_eq!(MAX_RANK, 32, "one u64 per 8 bytes of a 256-byte header");
        let blob = tensor_blob::<F32, 3>([2, 3, 4], payload(2 * 3 * 4 * 4)).expect("ok");
        for (i, expect) in [2u64, 3, 4].iter().enumerate() {
            let at = i * 8;
            let got = u64::from_le_bytes(blob.bytes[at..at + 8].try_into().unwrap());
            assert_eq!(got, *expect, "dim {i} sits at offset {at}");
        }
        assert!(
            blob.bytes[24..TENSOR_HEADER_LEN].iter().all(|b| *b == 0),
            "the rest is padding, not a marker"
        );
    }

    #[test]
    fn the_payload_offset_does_not_depend_on_rank() {
        assert_eq!(TENSOR_HEADER_LEN % 256, 0);
        let r1 = tensor_blob::<F32, 1>([2], payload(8)).expect("ok");
        let r4 = tensor_blob::<F32, 4>([1, 1, 1, 2], payload(8)).expect("ok");
        assert_eq!(r1.bytes.len(), r4.bytes.len(), "same payload, same total");
    }
}

#[cfg(test)]
mod shape_check_reach {
    use super::elements::{F32, F64};
    use super::*;

    fn payload(n: usize) -> Bytes {
        Bytes::from_source(vec![0u8; n])
    }

    /// The dims-imply-length check is one comparison covering a family of
    /// errors, because they all break the same invariant.
    #[test]
    fn one_check_catches_several_different_mistakes() {
        // a truncated payload
        assert!(tensor_blob::<F32, 2>([3, 4], payload(40)).is_err());
        // a payload sized for a wider element
        assert!(tensor_blob::<F32, 2>([3, 4], payload(96)).is_err());
        assert!(tensor_blob::<F64, 2>([3, 4], payload(48)).is_err());
        // reading with an extra dimension: it comes from the zero padding
        let blob = tensor_blob::<F32, 2>([3, 4], payload(48)).expect("ok");
        let wrong: Blob<Tensor<F32, 3>> = blob.transmute();
        assert!(<TensorView as TryFromBlob<Tensor<F32, 3>>>::try_from_blob(wrong).is_err());
        // and reading with a MISSING leading dimension
        let blob = tensor_blob::<F32, 3>([2, 3, 4], payload(96)).expect("ok");
        let wrong: Blob<Tensor<F32, 2>> = blob.transmute();
        assert!(<TensorView as TryFromBlob<Tensor<F32, 2>>>::try_from_blob(wrong).is_err());
    }

    /// The one case that passes, and it is not a hole: a trailing dimension of
    /// 1 read away leaves the identical elements in the identical order, so
    /// [3,4,1] and [3,4] describe the same tensor. The check declines to
    /// complain about a difference that is not one.
    #[test]
    fn a_trailing_unit_dimension_is_genuinely_the_same_tensor() {
        let blob = tensor_blob::<F32, 3>([3, 4, 1], payload(48)).expect("ok");
        let as_rank2: Blob<Tensor<F32, 2>> = blob.transmute();
        let view: TensorView =
            <TensorView as TryFromBlob<Tensor<F32, 2>>>::try_from_blob(as_rank2).expect("passes");
        assert_eq!(view.dims(), &[3, 4]);
        assert_eq!(view.elems(), 12, "same elements, same order");
    }
}

#[cfg(test)]
mod extent_tests {
    use super::elements::{BF16, F32, F64, NVFP4, U8};
    use super::*;

    // Deliberately bypass the fallible constructor to exercise the reader on
    // malformed wire bytes. All callers use at most a few payload bytes.
    fn raw_blob<T: TensorElement, const RANK: usize>(
        dims: [u64; RANK],
        payload_len: usize,
    ) -> Blob<Tensor<T, RANK>> {
        let mut bytes = vec![0u8; TENSOR_HEADER_LEN + payload_len];
        for (i, dim) in dims.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&dim.to_le_bytes());
        }
        Blob::new(Bytes::from_source(bytes))
    }

    // These two tests use only the pre-fix public API. On the old code the
    // product panics with overflow checks, or wraps to zero and accepts the
    // empty payload without overflow checks. Both are failures of this test.
    #[test]
    fn constructor_rejects_overflowing_logical_extent() {
        assert!(
            tensor_blob::<BF16, 3>([1u64 << 63, 2, 1], Bytes::from_source(Vec::<u8>::new()))
                .is_err()
        );
    }

    #[test]
    fn parser_rejects_overflowing_logical_extent() {
        let blob = raw_blob::<BF16, 3>([1u64 << 63, 2, 1], 0);
        assert!(TensorView::try_from_blob(blob).is_err());
    }

    #[test]
    fn zero_extent_is_independent_of_dimension_order() {
        for dims in [
            [u64::MAX, u64::MAX, 0],
            [u64::MAX, 0, u64::MAX],
            [0, u64::MAX, u64::MAX],
        ] {
            let blob = tensor_blob::<BF16, 3>(dims, Bytes::from_source(Vec::<u8>::new())).unwrap();
            let view = TensorView::try_from_blob(blob).unwrap();
            assert_eq!(view.dims(), &dims);
            assert_eq!(view.elems(), 0);
            assert!(view.payload().is_empty());
            assert!(TensorView::try_from_blob(raw_blob::<BF16, 3>(dims, 1)).is_err());
        }
    }

    #[test]
    fn rank_zero_is_one_scalar_element() {
        let dense = tensor_blob::<F32, 0>([], Bytes::from_source(vec![0u8; 4])).unwrap();
        let dense = TensorView::try_from_blob(dense).unwrap();
        assert!(dense.dims().is_empty());
        assert_eq!(dense.elems(), 1);
        assert_eq!(dense.payload().len(), 4);
        assert!(TensorView::try_from_blob(raw_blob::<F32, 0>([], 0)).is_err());
        let packed = tensor_blob::<NVFP4, 0>([], Bytes::from_source(vec![0u8; 6])).unwrap();
        let packed = TensorView::try_from_blob(packed).unwrap();
        assert_eq!(packed.elems(), 1);
        assert_eq!(packed.payload().len(), 6);
    }

    #[test]
    fn dense_payload_overflow_is_rejected_before_length_comparison() {
        let elems = usize::MAX / 8 + 1;
        assert_eq!(F64::payload_len(elems), None);
        assert_eq!(F64::payload_len(elems - 1), Some((elems - 1) * 8));
        let error = tensor_blob::<F64, 1>([elems as u64], Bytes::from_source(Vec::<u8>::new()))
            .unwrap_err();
        assert_eq!(error, TensorError::ExtentOverflow);
        let error = TensorView::try_from_blob(raw_blob::<F64, 1>([elems as u64], 0)).unwrap_err();
        assert_eq!(error, TensorError::ExtentOverflow);
    }

    #[test]
    fn header_plus_payload_extent_must_fit() {
        assert_eq!(U8::payload_len(usize::MAX), Some(usize::MAX));
        let error = tensor_blob::<U8, 1>([usize::MAX as u64], Bytes::from_source(Vec::<u8>::new()))
            .unwrap_err();
        assert_eq!(error, TensorError::ExtentOverflow);
        let error =
            TensorView::try_from_blob(raw_blob::<U8, 1>([usize::MAX as u64], 0)).unwrap_err();
        assert_eq!(error, TensorError::ExtentOverflow);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn logical_count_must_fit_usize() {
        let dims = [u64::from(u32::MAX) + 1];
        let error = tensor_blob::<BF16, 1>(dims, Bytes::from_source(Vec::<u8>::new())).unwrap_err();
        assert_eq!(error, TensorError::ExtentOverflow);
        let error = TensorView::try_from_blob(raw_blob::<BF16, 1>(dims, 0)).unwrap_err();
        assert_eq!(error, TensorError::ExtentOverflow);
    }

    #[test]
    fn packed_payloads_keep_partial_blocks_and_empty_global_scale() {
        for (elems, expected) in [(0, 4), (1, 6), (15, 13), (16, 13), (17, 15), (32, 22)] {
            assert_eq!(NVFP4::payload_len(elems), Some(expected));
            let blob =
                tensor_blob::<NVFP4, 1>([elems as u64], Bytes::from_source(vec![0u8; expected]))
                    .unwrap();
            let view = TensorView::try_from_blob(blob).unwrap();
            assert_eq!(view.elems(), elems);
            assert_eq!(view.payload().len(), expected);
            assert!(
                TensorView::try_from_blob(raw_blob::<NVFP4, 1>([elems as u64], expected + 1))
                    .is_err()
            );
        }
        // Its packed extent fits even when an intermediate "elems * 4" would
        // overflow. Do not reject a representable packed result for that.
        let expected = usize::MAX.div_ceil(2) + usize::MAX.div_ceil(16) + 4;
        assert_eq!(NVFP4::payload_len(usize::MAX), Some(expected));
    }

    #[test]
    fn typed_view_keeps_the_original_payload_backing() {
        let blob = raw_blob::<BF16, 2>([2, 3], 12);
        let ptr = blob.bytes[TENSOR_HEADER_LEN..].as_ptr();
        let view = TensorView::try_from_blob(blob).unwrap();
        assert_eq!(view.payload().as_ptr(), ptr);
        assert_eq!(view.elems(), 6);
    }
}
