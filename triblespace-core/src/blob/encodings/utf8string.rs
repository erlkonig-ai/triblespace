use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::TryFromBlob;
use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::Encodes;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;

use anybytes::view::ViewError;
use anybytes::View;

/// Arbitrary-length UTF-8 text stored as a blob.
///
/// The text encoding for attributes of every length — names, labels, tags,
/// documents, prompts, JSON payloads, logs, etc.
/// Reference it from tribles via a [`Handle<UTF8String>`](crate::inline::encodings::hash::Handle).
pub struct UTF8String {}

impl BlobEncoding for UTF8String {}

impl MetaDescribe for UTF8String {
    fn describe() -> Fragment {
        let id: Id = id_hex!("8B173C65B7DB601A11E8A190BD774A79");
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "utf8string",
                metadata::description: "UTF-8 text of any length, stored as a blob and referenced by a content-derived handle. The default representation for textual payloads: documents, prompts, JSON, logs, names, addresses.\n\nBecause handles are content-derived, handle equality is content equality — a handle is an exact-match lookup key with no length ceiling, and identical text is stored once.\n\nText that NAMES something the system should reason about is usually better modelled as an entity referenced by GenId, so facts can be attached to the concept and renaming touches one place. Reach for this when the value is genuinely prose.",
                metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl TryFromBlob<UTF8String> for View<str> {
    type Error = ViewError;

    fn try_from_blob(b: Blob<UTF8String>) -> Result<Self, Self::Error> {
        b.bytes.view()
    }
}

impl Encodes<View<str>> for UTF8String
where
    crate::inline::encodings::hash::Handle<UTF8String>: crate::inline::InlineEncoding,
{
    type Output = Blob<UTF8String>;
    fn encode(source: View<str>) -> Blob<UTF8String> {
        Blob::new(source.bytes())
    }
}

/// Borrowed text of any lifetime. The bytes are copied into the blob, which
/// costs one pass over text that is hashed in full anyway.
impl<'a> Encodes<&'a str> for UTF8String
where
    crate::inline::encodings::hash::Handle<UTF8String>: crate::inline::InlineEncoding,
{
    type Output = Blob<UTF8String>;
    fn encode(source: &'a str) -> Blob<UTF8String> {
        Blob::new(source.to_owned().into())
    }
}

impl<'a> Encodes<&'a String> for UTF8String
where
    crate::inline::encodings::hash::Handle<UTF8String>: crate::inline::InlineEncoding,
{
    type Output = Blob<UTF8String>;
    fn encode(source: &'a String) -> Blob<UTF8String> {
        Blob::new(source.clone().into())
    }
}

impl Encodes<String> for UTF8String
where
    crate::inline::encodings::hash::Handle<UTF8String>: crate::inline::InlineEncoding,
{
    type Output = Blob<UTF8String>;
    fn encode(source: String) -> Blob<UTF8String> {
        Blob::new(source.into())
    }
}

/// Text as the HANDLE of its blob, without keeping the blob. This is what lets
/// a query constrain a `Handle<UTF8String>` attribute with a plain string:
/// `pattern!(&set, [{ ?e @ attr: "text" }])` compares content addresses, the
/// same 32 bytes `entity!` writes for that text. A content address, not a
/// derived id: equal text is equal handle by construction.
impl<'a> Encodes<&'a str> for crate::inline::encodings::hash::Handle<UTF8String> {
    type Output = crate::inline::Inline<crate::inline::encodings::hash::Handle<UTF8String>>;
    fn encode(source: &'a str) -> Self::Output {
        <UTF8String as Encodes<&'a str>>::encode(source).get_handle()
    }
}

impl Encodes<String> for crate::inline::encodings::hash::Handle<UTF8String> {
    type Output = crate::inline::Inline<crate::inline::encodings::hash::Handle<UTF8String>>;
    fn encode(source: String) -> Self::Output {
        <UTF8String as Encodes<String>>::encode(source).get_handle()
    }
}

impl<'a> Encodes<&'a String> for crate::inline::encodings::hash::Handle<UTF8String> {
    type Output = crate::inline::Inline<crate::inline::encodings::hash::Handle<UTF8String>>;
    fn encode(source: &'a String) -> Self::Output {
        <UTF8String as Encodes<&'a String>>::encode(source).get_handle()
    }
}

#[cfg(test)]
mod tests {
    use anybytes::Bytes;
    use anybytes::View;

    use crate::blob::encodings::utf8string::UTF8String;
    use crate::blob::IntoBlob;

    use crate::inline::encodings::hash::Handle;
    use crate::inline::Inline;

    #[test]
    fn string_handle() {
        let s: View<str> = Bytes::from(String::from("hello world!")).view().unwrap();
        let h: Inline<Handle<UTF8String>> = s.clone().to_blob().get_handle();
        let h2: Inline<Handle<UTF8String>> = s.clone().to_blob().get_handle();

        assert!(h == h2);
    }
}
