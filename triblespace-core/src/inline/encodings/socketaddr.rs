use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::Encodes;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::TryFromInline;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;

/// Error raised when a value does not match the [`SocketAddress`] encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSocketAddress;

/// Inline encoding for a socket address: an IP address and a port.
///
/// Bytes 0..16 hold the IPv6 address, an IPv4 address in its IPv4-mapped
/// form; bytes 16..18 hold the port and bytes 18..22 the IPv6 scope id, both
/// big-endian; the last ten bytes are zero. An IPv4-mapped address without a
/// scope reads back as IPv4. The IPv6 flow label is not kept.
pub struct SocketAddress;

impl MetaDescribe for SocketAddress {
    fn describe() -> Fragment {
        let id: Id = id_hex!("03C71A039027879514FB845C7D0C6B28");
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "socketaddr",
                metadata::description: "Socket address: an IP address and a port. Bytes 0..16 hold the IPv6 address, an IPv4 address in its IPv4-mapped form; bytes 16..18 hold the port and bytes 18..22 the IPv6 scope id, both big-endian; the last ten bytes are zero.\n\nUse for where an endpoint listens, for example the addresses a daemon is bound to. An IPv4-mapped address without a scope reads back as IPv4, and the IPv6 flow label is not kept.",
                metadata::tag: metadata::KIND_INLINE_ENCODING,
        }
    }
}

impl InlineEncoding for SocketAddress {
    type ValidationError = InvalidSocketAddress;
    type Encoding = Self;

    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        SocketAddr::try_from_inline(&value)?;
        Ok(value)
    }
}

impl Encodes<SocketAddr> for SocketAddress {
    type Output = Inline<SocketAddress>;

    fn encode(source: SocketAddr) -> Inline<SocketAddress> {
        let (ip, scope) = match source {
            SocketAddr::V4(v4) => (v4.ip().to_ipv6_mapped(), 0),
            SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
        };
        let mut raw = [0; 32];
        raw[..16].copy_from_slice(&ip.octets());
        raw[16..18].copy_from_slice(&source.port().to_be_bytes());
        raw[18..22].copy_from_slice(&scope.to_be_bytes());
        Inline::new(raw)
    }
}

impl TryFromInline<'_, SocketAddress> for SocketAddr {
    type Error = InvalidSocketAddress;

    fn try_from_inline(value: &Inline<SocketAddress>) -> Result<Self, Self::Error> {
        let raw = &value.raw;
        if raw[22..].iter().any(|byte| *byte != 0) {
            return Err(InvalidSocketAddress);
        }
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[..16]).unwrap());
        let port = u16::from_be_bytes([raw[16], raw[17]]);
        let scope = u32::from_be_bytes(raw[18..22].try_into().unwrap());
        Ok(match ip.to_ipv4_mapped() {
            Some(v4) if scope == 0 => SocketAddr::new(IpAddr::V4(v4), port),
            _ => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline::IntoInline;

    #[test]
    fn socket_addresses_round_trip() {
        for address in [
            "127.0.0.1:7001",
            "0.0.0.0:0",
            "[::1]:7002",
            "[2001:db8::7]:65535",
            "[fe80::1%3]:443",
        ] {
            let address: SocketAddr = address.parse().unwrap();
            let value: Inline<SocketAddress> = address.to_inline();
            assert_eq!(SocketAddr::try_from_inline(&value), Ok(address));
            assert!(SocketAddress::validate(value).is_ok());
        }
    }

    #[test]
    fn trailing_bytes_are_not_a_socket_address() {
        let address: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let mut value: Inline<SocketAddress> = address.to_inline();
        value.raw[31] = 1;
        assert_eq!(
            SocketAddr::try_from_inline(&value),
            Err(InvalidSocketAddress)
        );
        assert!(SocketAddress::validate(value).is_err());
    }
}
