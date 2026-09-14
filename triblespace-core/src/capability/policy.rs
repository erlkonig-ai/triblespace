//! Descriptor-local admission policies over capability definitions.
//!
//! A resource links its finite policy vocabulary through ordinary binding
//! entities. Every binding names one immutable capability definition and an
//! open or independently rooted quorum interpretation. Consumers query the
//! bound definition's invocation actions to select policy roots; proof grant
//! handles need not equal this binding. Delegation rights and application
//! restrictions live in grant definitions, never inline in proof records.

use std::error::Error;
use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::capability::{is_valid_capability_principal, CapabilityHandle};
use crate::id::{id_hex, Id};
use crate::inline::encodings::ed25519::ED25519PublicKey;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::iu256::U256;
use crate::metadata;
use crate::prelude::{attributes, entity, exists, find, pattern};
use crate::trible::{Fragment, TribleSet};

attributes! {
    /// One descriptor-local capability policy binding.
    ///
    /// Anchor minted with installed `trible genid` on 2026-09-06:
    /// `D6065F21923709C72144866C05F74B46`.
    "D6065F21923709C72144866C05F74B46" as pub resource_policy: GenId;
    /// Exact immutable SimpleArchive capability definition governed by a binding.
    ///
    /// Anchor minted with installed `trible genid` on 2026-09-06:
    /// `2949050AA6092F5689EA7EAA52700CE9`.
    "2949050AA6092F5689EA7EAA52700CE9" as pub capability_handle: Handle<SimpleArchive>;
    /// A governed resource descriptor referenced by ordinary collection facts.
    /// Anchor minted with `trible genid` on 2026-09-14:
    /// `5059416BAF824B364FF52F56A0D1CF9F`.
    "5059416BAF824B364FF52F56A0D1CF9F" as pub resource_handle: Handle<SimpleArchive>;
    /// Immutable declaration of the collection whose READ audience may repair
    /// this resource's proofs. It does not inherit any collection authority or
    /// require mutable collection facts naming the resource.
    /// Anchor minted with `trible genid` on 2026-09-14:
    /// `62E951EC3ABB7F9B7F123BB7DE2F9F99`.
    "62E951EC3ABB7F9B7F123BB7DE2F9F99" as pub resource_collection: Handle<SimpleArchive>;
    /// One distinct canonical Ed25519 trust root of this binding.
    /// Anchor minted on 2026-08-30; unchanged encoding and identity.
    "E9AC4E4749FD219705E9533B02AAA405" as pub admission_policy_root: ED25519PublicKey;
    /// Number of distinct roots required to invoke this exact capability.
    /// Anchor minted on 2026-08-30; unchanged encoding and identity.
    "AF874E4D44C3A6565754D3EE8EDE48B5" as pub admission_invoke_threshold: U256;
    /// Legacy identity-bearing field, not a delegation authorization rule.
    /// Anchor minted on 2026-08-30; unchanged encoding and identity.
    "1300EF404FE61D26FC091B0CEC1C41EC" as pub admission_delegate_threshold: U256;
}

/// An admission policy requiring no proof.
///
/// Minted with `trible genid` on 2026-08-30.
pub const KIND_ADMISSION_POLICY_OPEN: Id = id_hex!("77983C388E5109F9D55106A28D1C18FA");

/// A threshold policy over a canonical nonempty root set.
///
/// Minted with `trible genid` on 2026-08-30.
pub const KIND_ADMISSION_POLICY_QUORUM: Id = id_hex!("DC81E78C55E759F71AFFA645A02C44C5");

/// Invalid quorum geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionPolicyError {
    /// A quorum has no roots.
    EmptyRoots,
    /// A root is not a unique, usable Ed25519 principal encoding.
    InvalidRoot { key: [u8; 32] },
    /// A threshold is zero or exceeds the number of distinct roots.
    InvalidThreshold {
        /// Which threshold failed.
        field: &'static str,
        /// Supplied threshold.
        threshold: u32,
        /// Number of distinct policy roots.
        roots: usize,
    },
}

impl fmt::Display for AdmissionPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRoots => formatter.write_str("an admission quorum needs at least one root"),
            Self::InvalidRoot { .. } => {
                formatter.write_str("an admission root must be a canonical, non-weak Ed25519 key")
            }
            Self::InvalidThreshold {
                field,
                threshold,
                roots,
            } => write!(
                formatter,
                "{field} threshold {threshold} is outside 1..={roots}",
            ),
        }
    }
}

impl Error for AdmissionPolicyError {}

/// Immutable authorization law for one action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionPolicy {
    /// Every principal is admitted without evidence.
    Open,
    /// Distinct roots jointly support invocation.
    ///
    /// The encoded policy may also retain a legacy delegation threshold as
    /// identity-bearing descriptor data. Delegation authority itself is now
    /// carried only by the signed mode on each self-contained proof prefix.
    Quorum(ValidatedQuorum),
}

/// Canonical, structurally valid quorum geometry.
///
/// The fields are deliberately private: sorting, deduplication, and the
/// threshold bounds are invariants of the value rather than checks every
/// consumer must remember to repeat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedQuorum {
    roots: Vec<VerifyingKey>,
    invoke_threshold: u32,
    delegate_threshold: Option<u32>,
}

impl ValidatedQuorum {
    /// Distinct roots in canonical public-key order.
    pub fn roots(&self) -> &[VerifyingKey] {
        &self.roots
    }

    /// Number of distinct roots required to invoke the action.
    pub const fn invoke_threshold(&self) -> u32 {
        self.invoke_threshold
    }

    /// Legacy identity-bearing delegation threshold.
    ///
    /// This value is round-tripped because it participates in existing
    /// descriptor handles. It is not consulted by capability admission;
    /// signed proof-prefix modes govern delegation.
    pub const fn delegate_threshold(&self) -> Option<u32> {
        self.delegate_threshold
    }
}

impl AdmissionPolicy {
    /// Canonical threshold policy over the distinct supplied roots.
    pub fn quorum(
        roots: impl IntoIterator<Item = VerifyingKey>,
        invoke_threshold: u32,
        delegate_threshold: Option<u32>,
    ) -> Result<Self, AdmissionPolicyError> {
        let mut roots: Vec<_> = roots.into_iter().collect();
        if let Some(root) = roots
            .iter()
            .find(|root| !is_valid_capability_principal(root))
        {
            return Err(AdmissionPolicyError::InvalidRoot {
                key: root.to_bytes(),
            });
        }
        roots.sort_unstable_by_key(VerifyingKey::to_bytes);
        roots.dedup_by_key(|key| key.to_bytes());
        if roots.is_empty() {
            return Err(AdmissionPolicyError::EmptyRoots);
        }
        validate_threshold("invoke", invoke_threshold, roots.len())?;
        if let Some(threshold) = delegate_threshold {
            validate_threshold("delegate", threshold, roots.len())?;
        }
        Ok(Self::Quorum(ValidatedQuorum {
            roots,
            invoke_threshold,
            delegate_threshold,
        }))
    }

    /// One-root policy whose legacy delegation-threshold field is absent.
    ///
    /// This constructor does not constrain proof delegation. The independently
    /// signed grant definitions state which actions their recipients may delegate.
    pub fn direct(root: VerifyingKey) -> Self {
        Self::quorum([root], 1, None).expect("one-root direct policy is valid")
    }

    /// One-root policy retaining the legacy delegation-threshold value `1`.
    ///
    /// This remains available solely to reproduce existing descriptor
    /// identities. Proof-prefix definitions, not this field, govern delegation.
    pub fn delegable(root: VerifyingKey) -> Self {
        Self::quorum([root], 1, Some(1)).expect("one-root delegable policy is valid")
    }

    /// Canonical self-contained policy fragment.
    pub fn fragment(&self) -> Fragment {
        match self {
            Self::Open => {
                let kind = KIND_ADMISSION_POLICY_OPEN;
                entity! { _ @ metadata::tag: kind }
            }
            Self::Quorum(quorum) => {
                let kind = KIND_ADMISSION_POLICY_QUORUM;
                entity! { _ @
                    metadata::tag: kind,
                    admission_policy_root*: quorum.roots.iter().copied(),
                    admission_invoke_threshold: quorum.invoke_threshold,
                    admission_delegate_threshold?: quorum.delegate_threshold,
                }
            }
        }
    }

    /// Construct one binding entity without loading its definition.
    ///
    /// The caller which publishes a new definition also carries its blob in
    /// the descriptor Fragment. Binding presence alone never interprets it.
    pub fn binding(&self, capability: CapabilityHandle) -> Fragment {
        match self {
            Self::Open => entity! {
                capability_handle: capability,
                metadata::tag: KIND_ADMISSION_POLICY_OPEN,
            },
            Self::Quorum(quorum) => entity! {
                capability_handle: capability,
                metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
                admission_policy_root*: quorum.roots.iter().copied(),
                admission_invoke_threshold: quorum.invoke_threshold,
                admission_delegate_threshold?: quorum.delegate_threshold,
            },
        }
    }

    /// Distinct canonical roots, or `None` for open admission.
    pub fn roots(&self) -> Option<&[VerifyingKey]> {
        match self {
            Self::Open => None,
            Self::Quorum(quorum) => Some(quorum.roots()),
        }
    }

    /// Invocation threshold, or `None` for open admission.
    pub const fn invoke_threshold(&self) -> Option<u32> {
        match self {
            Self::Open => None,
            Self::Quorum(quorum) => Some(quorum.invoke_threshold()),
        }
    }

    /// Legacy identity-bearing delegation threshold.
    ///
    /// Capability admission ignores this value; it remains observable so a
    /// decoded descriptor can be reproduced byte-for-byte.
    pub const fn delegate_threshold(&self) -> Option<u32> {
        match self {
            Self::Open => None,
            Self::Quorum(quorum) => quorum.delegate_threshold(),
        }
    }
}

fn validate_threshold(
    field: &'static str,
    threshold: u32,
    roots: usize,
) -> Result<(), AdmissionPolicyError> {
    if threshold == 0 || threshold as usize > roots {
        return Err(AdmissionPolicyError::InvalidThreshold {
            field,
            threshold,
            roots,
        });
    }
    Ok(())
}

/// Query supported capability-policy interpretations linked by one resource entity.
///
/// Entity ids are opaque. Extra facts, unknown policy kinds, malformed values,
/// and unsupported quorum geometry contribute no interpretation; absence is
/// never Open. Every threshold alternative is evaluated over its own binding's
/// root set. `capability` restricts the query to one exact definition handle,
/// without loading that definition or acquiring any blob.
pub fn resource_policies<'a>(
    facts: &'a TribleSet,
    resource: Id,
    capability: Option<CapabilityHandle>,
) -> impl Iterator<Item = (CapabilityHandle, AdmissionPolicy)> + 'a {
    let bindings: Box<dyn Iterator<Item = (Id, CapabilityHandle)> + 'a> = match capability {
        Some(capability) => Box::new(
            find!(
                binding: Id,
                pattern!(facts, [
                    { resource @ resource_policy: ?binding },
                    { ?binding @ capability_handle: capability },
                ])
            )
            .map(move |binding| (binding, capability)),
        ),
        None => Box::new(find!(
            (binding: Id, capability: CapabilityHandle),
            pattern!(facts, [
                { resource @ resource_policy: ?binding },
                { ?binding @ capability_handle: ?capability },
            ])
        )),
    };
    bindings.flat_map(move |(binding, capability)| {
        let open = exists!(pattern!(facts, [{
            binding @ metadata::tag: KIND_ADMISSION_POLICY_OPEN,
        }]))
        .then_some((capability, AdmissionPolicy::Open));
        let roots: Vec<_> = find!(
            root: VerifyingKey,
            pattern!(facts, [{ binding @ admission_policy_root: ?root }])
        )
        .filter(is_valid_capability_principal)
        .collect();
        let quorums = find!(
            invoke: u32,
            pattern!(facts, [{ binding @
                metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
                admission_invoke_threshold: ?invoke,
            }])
        )
        .filter_map(move |invoke| {
            AdmissionPolicy::quorum(roots.iter().copied(), invoke, None)
                .ok()
                .map(|policy| (capability, policy))
        });
        open.into_iter().chain(quorums)
    })
}
#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key(byte: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[byte; 32]).verifying_key()
    }

    #[test]
    fn quorum_roots_are_a_canonical_set() {
        let a = AdmissionPolicy::quorum([key(2), key(1), key(2)], 1, Some(1)).unwrap();
        let b = AdmissionPolicy::quorum([key(1), key(2)], 1, Some(1)).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.fragment(), b.fragment());
    }

    #[test]
    fn invalid_thresholds_are_rejected() {
        assert!(AdmissionPolicy::quorum([], 1, None).is_err());
        assert!(AdmissionPolicy::quorum([key(1)], 0, None).is_err());
        assert!(AdmissionPolicy::quorum([key(1)], 1, Some(2)).is_err());

        let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
        assert_eq!(
            AdmissionPolicy::quorum([weak], 1, None),
            Err(AdmissionPolicyError::InvalidRoot { key: [0; 32] })
        );
    }

    #[test]
    fn policies_keep_capabilities_roots_and_resource_entities_joined() {
        let resource = crate::id::rngid();
        let other_resource = crate::id::rngid();
        let binding = crate::id::rngid();
        let first = CapabilityHandle::new([0; 32]);
        let second = CapabilityHandle::new([2; 32]);
        let unknown = CapabilityHandle::new([3; 32]);
        let facts = entity! { &resource @
            resource_policy*: entity! { &binding @
                capability_handle: first,
                metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
                admission_policy_root: key(1),
                admission_invoke_threshold*: [0_u32, 1_u32, 2_u32],
                metadata::name: "opaque binding entity",
            },
            resource_policy*: AdmissionPolicy::direct(key(2)).binding(second),
        } + entity! { &other_resource @
            resource_policy*: AdmissionPolicy::Open.binding(unknown),
        };
        assert_eq!(
            resource_policies(facts.facts(), resource.id, Some(first)).collect::<Vec<_>>(),
            vec![(first, AdmissionPolicy::direct(key(1)))]
        );
        assert_eq!(
            resource_policies(facts.facts(), resource.id, Some(second)).collect::<Vec<_>>(),
            vec![(second, AdmissionPolicy::direct(key(2)))]
        );
        assert_eq!(
            resource_policies(facts.facts(), resource.id, None).count(),
            2
        );
        assert_eq!(
            resource_policies(facts.facts(), resource.id, Some(unknown)).count(),
            0
        );
    }

    #[test]
    fn unknown_policy_kind_does_not_hide_supported_handle_interpretations() {
        let resource = crate::id::rngid();
        let unknown_kind = crate::id::rngid();
        let capability = CapabilityHandle::new([4; 32]);
        let facts = entity! { &resource @
            resource_policy*: entity! {
                capability_handle: capability,
                metadata::tag: unknown_kind.id,
            } + AdmissionPolicy::direct(key(4)).binding(capability)
              + AdmissionPolicy::Open.binding(capability),
        };
        let policies: Vec<_> = resource_policies(facts.facts(), resource.id, Some(capability))
            .map(|(_, policy)| policy)
            .collect();
        assert_eq!(policies.len(), 2);
        assert!(policies.contains(&AdmissionPolicy::direct(key(4))));
        assert!(policies.contains(&AdmissionPolicy::Open));
    }
}
