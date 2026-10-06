//! The text a reader of content bytes sees, shared by the semantic mappings:
//! an HTML page without its markup, a PDF's text layer.

/// The most a PDF page's decompressed content may inflate to before it is
/// treated as hostile and skipped (lopdf's decompression-bomb guard).
const PDF_PAGE_CONTENT_LIMIT: usize = 64 * 1024 * 1024;

pub(crate) fn head(text: &str, bytes: usize) -> String {
    if text.len() <= bytes {
        return text.to_owned();
    }
    let mut end = bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

pub(crate) fn looks_like_html(text: &str) -> bool {
    let start = head(text, 512).to_ascii_lowercase();
    start.contains("<html") || start.contains("<!doctype html") || start.contains("<body")
}

/// The text of an HTML document: script and style blocks removed, tags
/// removed, the five common entities decoded, whitespace collapsed. A page
/// from the web archive is then what its reader saw, which is what a query
/// means by it.
pub(crate) fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    while i < html.len() {
        if lower[i..].starts_with("<script") || lower[i..].starts_with("<style") {
            let close = if lower[i..].starts_with("<script") {
                "</script>"
            } else {
                "</style>"
            };
            match lower[i..].find(close) {
                Some(offset) => i += offset + close.len(),
                None => break,
            }
            out.push(' ');
            continue;
        }
        if html[i..].starts_with('<') {
            match html[i..].find('>') {
                Some(offset) => i += offset + 1,
                None => break,
            }
            out.push(' ');
            continue;
        }
        let next = html[i..].find('<').map(|o| i + o).unwrap_or(html.len());
        out.push_str(&html[i..next]);
        i = next;
    }
    let decoded = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text layer of a PDF, every page in order; empty for a document that
/// has none, or that lopdf cannot read. A failure to read is the same answer
/// every time for the same bytes, so it is a classification, not an error.
pub(crate) fn pdf_text(bytes: &[u8]) -> String {
    let Ok(document) = lopdf::Document::load_mem(bytes) else {
        return String::new();
    };
    let pages: Vec<u32> = document.get_pages().keys().copied().collect();
    document
        .extract_text_with_limit(&pages, PDF_PAGE_CONTENT_LIMIT)
        .unwrap_or_default()
}
