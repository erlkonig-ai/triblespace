//! What lattice v3 does with each mapping algorithm this binary knows.
//!
//! A derived collection names one mapping algorithm in its descriptor. Under
//! lattice v3 that mapping is either attached (an index maintained on the
//! frontier nodes of its parent, which never replicates and holds no DERIVE
//! records), deleted, or still derived (a collection of DERIVE leaves that
//! replicates because not every reader can compute it). The migration filter
//! (`trible pile migrate SRC lattice-v3`) leaves behind the DERIVE records of
//! collections whose mappings are all attached or deleted, and keeps the rest.
//! An algorithm missing from this table is unrecognised, and its records are
//! kept: open world, the conservative direction.
//!
//! Every id below is either the crate constant itself or a literal copied
//! from the source that defines it, never typed. A literal is used where the
//! constant is out of reach: the search crate is an optional dependency, the
//! archive-block BM25 mapping lives in the faculties repository, and the
//! ReferenceSummary module is deleted. `literals_match_their_definitions`
//! pins every literal whose definition this build can reach.

use triblespace_core::blob::encodings::entity_id_set::GENID_ATTRIBUTE_VALUES_MAPPING_V1;
use triblespace_core::collection::latest::LATEST_STATES_MAPPING_V1;
use triblespace_core::collection::lww_register::REGISTER_COORDINATES_MAPPING_V1;
use triblespace_core::collection::succinctarchive_union::{
    RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE, RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE,
    RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE, RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE,
    SIMPLE_TO_SUCCINCT_MAPPING_V1,
};
use triblespace_core::id::Id;
use triblespace_core::id_hex;
use triblespace_paths::REGULAR_PATH_MAPPING_V1;

/// What becomes of a derived collection's DERIVE records under lattice v3.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum V3Fate {
    /// The mapping becomes attached: its DERIVE records are left behind.
    Attached,
    /// The mapping is deleted: its DERIVE records are left behind.
    Deleted,
    /// The mapping stays derived: its DERIVE records are kept.
    Derived,
}

impl V3Fate {
    /// Whether a collection naming only mappings of this fate leaves its
    /// DERIVE records behind.
    pub(crate) fn leaves_derives_behind(self) -> bool {
        matches!(self, Self::Attached | Self::Deleted)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Deleted => "deleted",
            Self::Derived => "derived",
        }
    }
}

/// One classified mapping algorithm, with where its id comes from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct V3Mapping {
    pub(crate) id: Id,
    pub(crate) name: &'static str,
    pub(crate) fate: V3Fate,
    pub(crate) source: &'static str,
}

/// `TEXT_ATTRIBUTE_TO_BM25`, copied from triblespace-search/src/text_bm25.rs
/// (introduced in 0ceb79b7).
const TEXT_ATTRIBUTE_TO_BM25: Id = id_hex!("221CC84DDF0A61477A26BCE6ABD879D1");
/// `ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1`, copied from faculties
/// src/archive_bm25.rs (introduced in faculties 71317cae). Faculty-owned: no
/// build of this binary can reach the constant.
const ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1: Id = id_hex!("4EC6991611EF484A37FBD95F6E108FC6");
/// `REFERENCE_SUMMARY_MAPPING_V2`, copied from
/// triblespace-core/src/collection/reference_summary.rs as it stood before
/// e948ca53 deleted it (introduced in f18c3b7c).
const REFERENCE_SUMMARY_MAPPING_V2: Id = id_hex!("C0F7F9B5A68660407FDBFD8CF4D6E1AD");
/// `REFERENCE_SUMMARY_MAPPING_V1`, copied from the same file as it stood
/// from 36be9bbe until f18c3b7c replaced it; that file's last version says no
/// populated version 1 collection existed.
const REFERENCE_SUMMARY_MAPPING_V1: Id = id_hex!("A8C939AA55A7EC07C12FFCDA1FAA5785");
/// `NOMIC_ATTRIBUTES_TO_NVFP4`, copied from triblespace-search/src/semantic.rs
/// (current since f0c6157b).
const NOMIC_ATTRIBUTES_TO_NVFP4: Id = id_hex!("523C31F03F049CA26A0E847CAAFC08F7");
/// Earlier values of `NOMIC_ATTRIBUTES_TO_NVFP4`, copied from the lines
/// f0c6157b, be175f5c and 9c82f23f replaced in the same file.
const NOMIC_ATTRIBUTES_TO_NVFP4_BEFORE_F0C6157B: Id = id_hex!("2B69128192930EE0782CCA03B97677F5");
const NOMIC_ATTRIBUTES_TO_NVFP4_BEFORE_BE175F5C: Id = id_hex!("021EE2F74220BDAE30CC35FB08FC9427");
const NOMIC_ATTRIBUTES_TO_NVFP4_BEFORE_9C82F23F: Id = id_hex!("B94732E5DA22EFE9A4961BE906F5C500");
/// `EMBEDDING_ATTRIBUTE_TO_NVFP4`, copied from triblespace-search/src/nvfp4.rs
/// (current since a1927bd0).
const EMBEDDING_ATTRIBUTE_TO_NVFP4: Id = id_hex!("7B8668FD3857AD86B5AB24F5DD1BC1F9");
/// The earlier value of `EMBEDDING_ATTRIBUTE_TO_NVFP4`, copied from the line
/// a1927bd0 replaced (introduced in 12491c99).
const EMBEDDING_ATTRIBUTE_TO_NVFP4_BEFORE_A1927BD0: Id =
    id_hex!("E8732C5918436416D071C0BAEF4F883F");

/// Every mapping algorithm lattice v3 classifies.
///
/// The attached list follows the build brief (decisions 4 and 12, spec
/// resolution 7): Succinct, Rank9, the LWW register, latest states,
/// EntityIdSet, both BM25 mappings and PathSummary become attached;
/// ReferenceSummary is deleted; the semantic index and the stored-vector
/// NVFP4 set stay derived. It is frozen against that list, not against the
/// attached implementations themselves, which land separately.
pub(crate) const V3_MAPPINGS: &[V3Mapping] = &[
    V3Mapping {
        id: SIMPLE_TO_SUCCINCT_MAPPING_V1,
        name: "SIMPLE_TO_SUCCINCT_MAPPING_V1",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::succinctarchive_union",
    },
    V3Mapping {
        id: RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE,
        name: "RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::succinctarchive_union",
    },
    V3Mapping {
        id: RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE,
        name: "RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::succinctarchive_union",
    },
    V3Mapping {
        id: RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE,
        name: "RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::succinctarchive_union",
    },
    V3Mapping {
        id: RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE,
        name: "RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::succinctarchive_union",
    },
    V3Mapping {
        id: GENID_ATTRIBUTE_VALUES_MAPPING_V1,
        name: "GENID_ATTRIBUTE_VALUES_MAPPING_V1",
        fate: V3Fate::Attached,
        source: "triblespace-core blob::encodings::entity_id_set",
    },
    V3Mapping {
        id: LATEST_STATES_MAPPING_V1,
        name: "LATEST_STATES_MAPPING_V1",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::latest",
    },
    V3Mapping {
        id: REGISTER_COORDINATES_MAPPING_V1,
        name: "REGISTER_COORDINATES_MAPPING_V1",
        fate: V3Fate::Attached,
        source: "triblespace-core collection::lww_register",
    },
    V3Mapping {
        id: REGULAR_PATH_MAPPING_V1,
        name: "REGULAR_PATH_MAPPING_V1",
        fate: V3Fate::Attached,
        source: "triblespace-paths path_summary_union",
    },
    V3Mapping {
        id: TEXT_ATTRIBUTE_TO_BM25,
        name: "TEXT_ATTRIBUTE_TO_BM25",
        fate: V3Fate::Attached,
        source: "triblespace-search text_bm25 (literal)",
    },
    V3Mapping {
        id: ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1,
        name: "ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1",
        fate: V3Fate::Attached,
        source: "faculties archive_bm25 (literal)",
    },
    V3Mapping {
        id: REFERENCE_SUMMARY_MAPPING_V2,
        name: "REFERENCE_SUMMARY_MAPPING_V2",
        fate: V3Fate::Deleted,
        source: "triblespace-core collection::reference_summary, deleted (literal)",
    },
    V3Mapping {
        id: REFERENCE_SUMMARY_MAPPING_V1,
        name: "REFERENCE_SUMMARY_MAPPING_V1",
        fate: V3Fate::Deleted,
        source: "triblespace-core collection::reference_summary, retired (literal)",
    },
    V3Mapping {
        id: NOMIC_ATTRIBUTES_TO_NVFP4,
        name: "NOMIC_ATTRIBUTES_TO_NVFP4",
        fate: V3Fate::Derived,
        source: "triblespace-search semantic (literal)",
    },
    V3Mapping {
        id: NOMIC_ATTRIBUTES_TO_NVFP4_BEFORE_F0C6157B,
        name: "NOMIC_ATTRIBUTES_TO_NVFP4 (before f0c6157b)",
        fate: V3Fate::Derived,
        source: "triblespace-search semantic, retired (literal)",
    },
    V3Mapping {
        id: NOMIC_ATTRIBUTES_TO_NVFP4_BEFORE_BE175F5C,
        name: "NOMIC_ATTRIBUTES_TO_NVFP4 (before be175f5c)",
        fate: V3Fate::Derived,
        source: "triblespace-search semantic, retired (literal)",
    },
    V3Mapping {
        id: NOMIC_ATTRIBUTES_TO_NVFP4_BEFORE_9C82F23F,
        name: "NOMIC_ATTRIBUTES_TO_NVFP4 (before 9c82f23f)",
        fate: V3Fate::Derived,
        source: "triblespace-search semantic, retired (literal)",
    },
    V3Mapping {
        id: EMBEDDING_ATTRIBUTE_TO_NVFP4,
        name: "EMBEDDING_ATTRIBUTE_TO_NVFP4",
        fate: V3Fate::Derived,
        source: "triblespace-search nvfp4 (literal)",
    },
    V3Mapping {
        id: EMBEDDING_ATTRIBUTE_TO_NVFP4_BEFORE_A1927BD0,
        name: "EMBEDDING_ATTRIBUTE_TO_NVFP4 (before a1927bd0)",
        fate: V3Fate::Derived,
        source: "triblespace-search nvfp4, retired (literal)",
    },
];

/// The classification of one mapping algorithm, if lattice v3 knows it.
pub(crate) fn v3_mapping(id: Id) -> Option<&'static V3Mapping> {
    V3_MAPPINGS.iter().find(|mapping| mapping.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_classified_id_is_distinct() {
        let ids: BTreeSet<Id> = V3_MAPPINGS.iter().map(|mapping| mapping.id).collect();
        assert_eq!(ids.len(), V3_MAPPINGS.len());
    }

    /// Every algorithm the listing names is classified, under the name the
    /// listing gives it, so a mapping added there cannot go unclassified.
    #[test]
    fn every_algorithm_the_listing_names_is_classified() {
        let mut named = 0;
        for mapping in V3_MAPPINGS {
            if let Some(name) = super::super::mapping_algorithm_name(mapping.id) {
                named += 1;
                assert_eq!(mapping.name, name, "{:X}", mapping.id);
            }
        }
        // Nine core and paths mappings, plus the three search mappings when
        // this build has the search feature.
        let search = if cfg!(feature = "search") { 3 } else { 0 };
        assert_eq!(named, 9 + search);
    }

    #[test]
    fn the_fates_follow_the_build_brief() {
        let fate = |id| v3_mapping(id).map(|mapping| mapping.fate);
        for attached in [
            SIMPLE_TO_SUCCINCT_MAPPING_V1,
            RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE,
            RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE,
            RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE,
            RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE,
            GENID_ATTRIBUTE_VALUES_MAPPING_V1,
            LATEST_STATES_MAPPING_V1,
            REGISTER_COORDINATES_MAPPING_V1,
            REGULAR_PATH_MAPPING_V1,
            TEXT_ATTRIBUTE_TO_BM25,
            ARCHIVE_BLOCK_TEXT_BM25_MAPPING_V1,
        ] {
            assert_eq!(fate(attached), Some(V3Fate::Attached), "{attached:X}");
        }
        for deleted in [REFERENCE_SUMMARY_MAPPING_V2, REFERENCE_SUMMARY_MAPPING_V1] {
            assert_eq!(fate(deleted), Some(V3Fate::Deleted), "{deleted:X}");
        }
        for derived in [NOMIC_ATTRIBUTES_TO_NVFP4, EMBEDDING_ATTRIBUTE_TO_NVFP4] {
            assert_eq!(fate(derived), Some(V3Fate::Derived), "{derived:X}");
        }
    }

    /// The literals equal the constants they were copied from, wherever this
    /// build can reach the constant.
    #[cfg(feature = "search")]
    #[test]
    fn literals_match_their_definitions() {
        assert_eq!(
            TEXT_ATTRIBUTE_TO_BM25,
            triblespace_search::text_bm25::TEXT_ATTRIBUTE_TO_BM25
        );
        assert_eq!(
            NOMIC_ATTRIBUTES_TO_NVFP4,
            triblespace_search::semantic::NOMIC_ATTRIBUTES_TO_NVFP4
        );
        assert_eq!(
            EMBEDDING_ATTRIBUTE_TO_NVFP4,
            triblespace_search::nvfp4::EMBEDDING_ATTRIBUTE_TO_NVFP4
        );
    }
}
