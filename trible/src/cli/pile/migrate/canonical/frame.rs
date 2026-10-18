//! Private migration adapter for deployed3ca native kinds; never runtime dispatch.
//! Generic recovery framing is owned by public PileRecords. These checks bind
//! its reported kind/span to the old dense grammar and enforce zero padding.
use hex_literal::hex;

pub const COMMIT: [u8; 32] =
    hex!("A1322BB3F5214287C314D42AFCC1A97CB264FACD9A22B4938838BE78DB31AA59");
pub const MERGE: [u8; 32] =
    hex!("3C1B4C0D0A71AB17D079AC528576B6BD2E6A514E461E7F0C3D1EA4C8F0BC019E");
pub const DERIVE: [u8; 32] =
    hex!("F3D2FA3E40FC0A4CCBC84603CAF2D3446662DA194391208BA6B932564F919A96");
pub const MAP: [u8; 32] = hex!("32E0D7333FD2AD1F567AE9A030814F95CA8F7F4A87C0DEAA275FB9DD8FC5F408");

// Exact current passthrough allowlist, copied from core's physical kind definitions.
pub const WANT: [u8; 32] = hex!("82EE8C72E252AB403C431AA98C9E77C0EA89796A8111DFF8C252ABCDE6F87D6F");
pub const BRANCH: [u8; 32] =
    hex!("2BC0B9FE0EFDB0BC53654E17BB9D06E01259F36AF93EEE54AD5D557B12DF706D");
pub const TOMBSTONE: [u8; 32] =
    hex!("8D9F27E76D3620EEC29B781F841E9EF77F2607B40DC702FE3DAED007E9228CA5");

pub fn supported(kind: [u8; 32]) -> bool {
    matches!(kind, COMMIT | MERGE | DERIVE | MAP)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedKind,
    Length,
    KindMismatch,
    Count,
    Padding,
}

pub fn tagged(kind: [u8; 32], frame: &[u8]) -> Result<Vec<u8>, Error> {
    let tag = match kind {
        COMMIT => 1,
        MERGE => 8,
        DERIVE => 9,
        MAP => 10,
        _ => return Err(Error::UnsupportedKind),
    };
    if frame.len() < 256 {
        return Err(Error::Length);
    }
    if frame[32..64] != kind {
        return Err(Error::KindMismatch);
    }
    let dense_len = if tag == 8 {
        let count = u32::from_be_bytes(frame[252..256].try_into().unwrap()) as usize;
        if !(2..=16).contains(&count) {
            return Err(Error::Count);
        }
        192 + count * 32
    } else {
        192
    };
    let end = 64 + dense_len;
    if frame.len() != end.div_ceil(256) * 256 {
        return Err(Error::Length);
    }
    if frame[end..].iter().any(|&b| b != 0) {
        return Err(Error::Padding);
    }
    let mut bytes = Vec::with_capacity(1 + dense_len);
    bytes.push(tag);
    bytes.extend_from_slice(&frame[64..end]);
    Ok(bytes)
}
