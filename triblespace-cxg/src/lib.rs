//! Construction grammar over json_tree units.
//!
//! A [`Grammar`] is a set of [`Construction`]s. Each construction has a
//! category, an anchor (a query over the anchor occurrence's entity) and
//! constituents: one-step paths to the anchor's members, each classified once
//! as a bound value, a child of some category, or a drop with a reason.
//!
//! [`Grammar::cover`] accepts a unit only if exactly one total cover exists:
//! every occurrence of the tree unfolded from the unit's root is accounted for
//! by exactly one construction instance. Otherwise it reports the occurrences
//! it could not account for, or could account for in more than one way, and
//! produces no image.
//!
//! Constructions are context-free over trees. An anchor sees only its own
//! entity and the category its parent demands, and it is a predicate, so a
//! construction gives at most one analysis of an entity. The number of covers
//! of an occurrence therefore depends on (entity, category) alone. json_tree
//! shares identical subtrees under one entity, so that number is computed once
//! per pair and counted at every path the subtree occupies. Context belongs to
//! queries over the emitted image, never to an anchor.
//!
//! The engine never dispatches on a node's kind. An occurrence's members are
//! whatever object fields and array entries it has, and a construction must
//! claim all of them. Kinds matter only to the anchors that ask for them.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

use anybytes::View;
use ethnum::U256;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::id::Id;
use triblespace_core::import::json_tree;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::prelude::*;
use triblespace_core::repo::BlobStoreGet;
use triblespace_core::trible::{Fragment, TribleSet};

/// A grammatical category, demanded by a parent constituent and supplied by
/// constructions. A category may carry context its parent decided (a
/// compiler's record conditions, say), and constructions are found by its
/// [`Category::family`], so one construction serves every context of its
/// family and reads the context through its anchor.
pub trait Category: Clone + Eq + Hash + fmt::Debug {
    type Family: Clone + Eq + Hash + fmt::Debug;
    fn family(&self) -> Self::Family;
}

/// A plain name is its own family.
impl Category for &'static str {
    type Family = &'static str;
    fn family(&self) -> &'static str {
        self
    }
}

type Name = Inline<Handle<UTF8String>>;

/// How many total covers an occurrence has under a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Count {
    Zero,
    One,
    Many,
}

impl Count {
    fn add(self, other: Count) -> Count {
        match (self, other) {
            (Count::Zero, x) | (x, Count::Zero) => x,
            _ => Count::Many,
        }
    }

    fn mul(self, other: Count) -> Count {
        match (self, other) {
            (Count::Zero, _) | (_, Count::Zero) => Count::Zero,
            (Count::One, Count::One) => Count::One,
            _ => Count::Many,
        }
    }
}

/// A one-step path from an anchor to its members.
#[derive(Clone, Debug)]
pub enum Step {
    /// The object member with this name.
    Field(&'static str),
    /// The array entry at this index.
    Index(usize),
    /// Every array entry.
    Each,
    /// Every object member, whatever its name: an object whose member
    /// names are ids rather than a fixed vocabulary.
    EachField,
}

/// A child category computed from the anchor's entity and the category the
/// anchor was asked for: how context a parent decides reaches its children.
pub type Within<C> = Arc<dyn Fn(&TribleSet, Id, &C) -> C + Send + Sync>;

/// What a constituent does with the members it claims.
#[derive(Clone)]
pub enum Role<C> {
    /// The member's whole subtree is consumed and bound.
    Value,
    /// The member must be covered by a construction of this category.
    Child(C),
    /// The member must be covered by a construction of the category this
    /// computes.
    Within(Within<C>),
    /// The member is consumed and emits nothing, for the stated reason.
    Drop(&'static str),
}

impl<C: fmt::Debug> fmt::Debug for Role<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Value => write!(f, "Value"),
            Role::Child(c) => write!(f, "Child({c:?})"),
            Role::Within(_) => write!(f, "Within(..)"),
            Role::Drop(reason) => write!(f, "Drop({reason:?})"),
        }
    }
}

impl<C: Clone> Role<C> {
    /// The category a child must be covered as, when this role has one.
    fn child(&self, facts: &TribleSet, anchor: Id, category: &C) -> Option<C> {
        match self {
            Role::Child(c) => Some(c.clone()),
            Role::Within(f) => Some(f(facts, anchor, category)),
            Role::Value | Role::Drop(_) => None,
        }
    }
}

/// One constituent of a construction.
#[derive(Clone, Debug)]
pub struct Constituent<C> {
    pub step: Step,
    pub role: Role<C>,
    /// A `Field` or `Index` step claims nothing when the member is absent.
    /// `Each` and `EachField` are always optional.
    pub optional: bool,
}

impl<C> Constituent<C> {
    pub fn new(step: Step, role: Role<C>) -> Self {
        Constituent {
            step,
            role,
            optional: false,
        }
    }

    pub fn optional(step: Step, role: Role<C>) -> Self {
        Constituent {
            step,
            role,
            optional: true,
        }
    }
}

/// A query over the anchor occurrence's entity, given the category it is
/// asked for.
pub type Anchor<C> = Box<dyn Fn(&TribleSet, Id, &C) -> bool + Send + Sync>;
pub type Emit<C> = Box<dyn Fn(&Instance<C>) -> Fragment + Send + Sync>;

/// A construction: family, anchor, constituents and emit.
pub struct Construction<C: Category> {
    pub name: &'static str,
    pub category: C::Family,
    pub anchor: Anchor<C>,
    pub constituents: Vec<Constituent<C>>,
    /// Builds the construction's image from an instance. The returned
    /// fragment must have exactly one root: the parent refers to it.
    pub emit: Emit<C>,
}

/// An accepted construction instance, as handed to its emit.
pub struct Instance<'a, C> {
    pub facts: &'a TribleSet,
    pub anchor: Id,
    /// The category the instance covers, with whatever context it carries.
    pub category: &'a C,
    parts: &'a [Vec<Part>],
}

#[derive(Clone, Debug)]
struct Part {
    step: PathStep,
    value: Id,
    child: Option<Id>,
}

impl<C> Instance<'_, C> {
    /// The value entities claimed by constituent `k`, in member order.
    pub fn values(&self, k: usize) -> impl Iterator<Item = Id> + '_ {
        self.parts[k].iter().map(|p| p.value)
    }

    /// The emitted roots of constituent `k`'s children, in member order.
    pub fn children(&self, k: usize) -> impl Iterator<Item = Id> + '_ {
        self.parts[k].iter().filter_map(|p| p.child)
    }

    /// The array indices of constituent `k`'s members, in member order.
    pub fn indices(&self, k: usize) -> impl Iterator<Item = U256> + '_ {
        self.parts[k].iter().filter_map(|p| match p.step {
            PathStep::Index(i) => Some(i),
            PathStep::Field(_) => None,
        })
    }
}

/// One step of an occurrence's path from the unit's root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathStep {
    Field(Name),
    Index(U256),
}

#[derive(Clone, Debug)]
struct Member {
    step: PathStep,
    value: Id,
}

/// Why a unit has no single cover, located by path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding<C> {
    pub path: String,
    pub category: C,
    pub problem: Problem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// No construction of the category has an anchor that matches.
    NoConstruction,
    /// A matching construction requires a member the occurrence lacks.
    Missing {
        construction: &'static str,
        step: String,
    },
    /// A matching construction leaves these members unclaimed.
    Unclaimed {
        construction: &'static str,
        members: Vec<String>,
    },
    /// More than one construction covers the occurrence.
    Ambiguous { constructions: Vec<&'static str> },
    /// The occurrence contains itself. Content-derived ids cannot do this,
    /// but a buggy writer or merge can.
    Cycle,
    /// The construction's emit returned a fragment without a single root.
    Unrooted { construction: &'static str },
}

impl<C: fmt::Debug> fmt::Display for Finding<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} as {:?}: {:?}", self.path, self.category, self.problem)
    }
}

/// A grammar whose constructions passed the static checks.
pub struct Grammar<C: Category> {
    constructions: Vec<Construction<C>>,
    by_category: HashMap<C::Family, Vec<usize>>,
    field_names: HashMap<&'static str, Name>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrammarError {
    /// Two constituents of one construction can claim the same member.
    Overlap { construction: &'static str },
}

impl<C: Category> Grammar<C> {
    pub fn new(constructions: Vec<Construction<C>>) -> Result<Self, GrammarError> {
        let mut by_category: HashMap<C::Family, Vec<usize>> = HashMap::new();
        let mut field_names = HashMap::new();
        for (i, c) in constructions.iter().enumerate() {
            let mut fields = HashSet::new();
            let mut indices = HashSet::new();
            let mut each = false;
            let mut each_field = false;
            for con in &c.constituents {
                let fresh = match con.step {
                    Step::Field(name) => {
                        let blob: Blob<UTF8String> = name.to_blob();
                        field_names.insert(name, blob.get_handle());
                        fields.insert(name)
                    }
                    Step::Index(index) => indices.insert(index),
                    Step::Each => !std::mem::replace(&mut each, true),
                    Step::EachField => !std::mem::replace(&mut each_field, true),
                };
                if !fresh || (each && !indices.is_empty()) || (each_field && !fields.is_empty()) {
                    return Err(GrammarError::Overlap {
                        construction: c.name,
                    });
                }
            }
            by_category.entry(c.category.clone()).or_default().push(i);
        }
        Ok(Grammar {
            constructions,
            by_category,
            field_names,
        })
    }

    /// The number of covers of `root` as `category`, without emitting.
    pub fn count(&self, facts: &TribleSet, root: Id, category: &C) -> Count {
        Run::new(self, facts).count(root, category)
    }

    /// The image of the unit's single total cover, or every finding that
    /// explains why there is none.
    pub fn cover<B: BlobStoreGet>(
        &self,
        facts: &TribleSet,
        blobs: &B,
        root: Id,
        category: &C,
    ) -> Result<Fragment, Vec<Finding<C>>> {
        let mut run = Run::new(self, facts);
        if run.count(root, category) == Count::One {
            let mut image = Fragment::empty();
            match run.emit(root, category, &mut image) {
                Ok(_) => return Ok(image),
                Err(problem) => {
                    return Err(vec![Finding {
                        path: String::from("/"),
                        category: category.clone(),
                        problem,
                    }])
                }
            }
        }
        let mut findings = Vec::new();
        run.diagnose(root, category, &mut Vec::new(), blobs, &mut findings);
        Err(findings)
    }
}

enum Fit {
    Applies(Vec<Vec<Part>>),
    Missing(usize),
    Unclaimed(Vec<PathStep>),
}

struct Run<'g, 'u, C: Category> {
    grammar: &'g Grammar<C>,
    facts: &'u TribleSet,
    counts: HashMap<(Id, C), Count>,
    open: HashSet<(Id, C)>,
    emitted: HashMap<(Id, C), Id>,
}

impl<'g, 'u, C: Category> Run<'g, 'u, C> {
    fn new(grammar: &'g Grammar<C>, facts: &'u TribleSet) -> Self {
        Run {
            grammar,
            facts,
            counts: HashMap::new(),
            open: HashSet::new(),
            emitted: HashMap::new(),
        }
    }

    fn members(&self, e: Id) -> Vec<Member> {
        let facts = self.facts;
        let mut members: Vec<Member> = find!(
            (name: Name, value: Id),
            pattern!(facts, [
                { e @ json_tree::object_field: _?field },
                { _?field @ json_tree::field_name: ?name, json_tree::field_value: ?value },
            ])
        )
        .map(|(name, value)| Member {
            step: PathStep::Field(name),
            value,
        })
        .chain(
            find!(
                (index: U256, value: Id),
                pattern!(facts, [{ _?entry @
                    json_tree::array_parent: e,
                    json_tree::array_index: ?index,
                    json_tree::array_value: ?value,
                }])
            )
            .map(|(index, value)| Member {
                step: PathStep::Index(index),
                value,
            }),
        )
        .collect();
        members.sort_by(|a, b| (a.step, a.value).cmp(&(b.step, b.value)));
        members
    }

    fn claims(&self, step: &Step, member: &PathStep) -> bool {
        match (step, member) {
            (Step::Field(name), PathStep::Field(handle)) => self.grammar.field_names[name] == *handle,
            (Step::Index(i), PathStep::Index(index)) => U256::from(*i as u64) == *index,
            (Step::Each, PathStep::Index(_)) => true,
            (Step::EachField, PathStep::Field(_)) => true,
            _ => false,
        }
    }

    fn fit(&self, c: &Construction<C>, members: &[Member]) -> Fit {
        let mut parts = vec![Vec::new(); c.constituents.len()];
        let mut claimed = vec![false; members.len()];
        for (k, con) in c.constituents.iter().enumerate() {
            for (m, member) in members.iter().enumerate() {
                if self.claims(&con.step, &member.step) {
                    parts[k].push(Part {
                        step: member.step,
                        value: member.value,
                        child: None,
                    });
                    claimed[m] = true;
                }
            }
            let optional = con.optional || matches!(con.step, Step::Each | Step::EachField);
            if parts[k].is_empty() && !optional {
                return Fit::Missing(k);
            }
        }
        let unclaimed: Vec<PathStep> = members
            .iter()
            .zip(&claimed)
            .filter(|(_, claimed)| !**claimed)
            .map(|(member, _)| member.step)
            .collect();
        if unclaimed.is_empty() {
            Fit::Applies(parts)
        } else {
            Fit::Unclaimed(unclaimed)
        }
    }

    /// The instance count of construction `c` at `e`, when it applies.
    fn instance(
        &mut self,
        c: &Construction<C>,
        e: Id,
        category: &C,
        members: &[Member],
    ) -> Option<(Count, Vec<Vec<Part>>)> {
        if !(c.anchor)(self.facts, e, category) {
            return None;
        }
        let Fit::Applies(parts) = self.fit(c, members) else {
            return Some((Count::Zero, Vec::new()));
        };
        let mut n = Count::One;
        for (k, con) in c.constituents.iter().enumerate() {
            if let Some(child) = con.role.child(self.facts, e, category) {
                for part in &parts[k] {
                    n = n.mul(self.count(part.value, &child));
                }
            }
        }
        Some((n, parts))
    }

    fn count(&mut self, e: Id, category: &C) -> Count {
        if let Some(n) = self.counts.get(&(e, category.clone())) {
            return *n;
        }
        if !self.open.insert((e, category.clone())) {
            return Count::Zero;
        }
        let grammar = self.grammar;
        let members = self.members(e);
        let mut total = Count::Zero;
        for &i in grammar.by_category.get(&category.family()).into_iter().flatten() {
            if let Some((n, _)) = self.instance(&grammar.constructions[i], e, category, &members) {
                total = total.add(n);
            }
        }
        self.open.remove(&(e, category.clone()));
        self.counts.insert((e, category.clone()), total);
        total
    }

    /// Emits the single cover of `e` as `category` into `image`. Only called
    /// where the count is `One`, so exactly one instance has count `One`.
    fn emit(&mut self, e: Id, category: &C, image: &mut Fragment) -> Result<Id, Problem> {
        if let Some(root) = self.emitted.get(&(e, category.clone())) {
            return Ok(*root);
        }
        let grammar = self.grammar;
        let members = self.members(e);
        let mut chosen = None;
        for &i in grammar.by_category.get(&category.family()).into_iter().flatten() {
            let c = &grammar.constructions[i];
            if let Some((Count::One, parts)) = self.instance(c, e, category, &members) {
                chosen = Some((c, parts));
                break;
            }
        }
        let (c, mut parts) = chosen.expect("a count of One has exactly one instance of count One");
        for (k, con) in c.constituents.iter().enumerate() {
            if let Some(child) = con.role.child(self.facts, e, category) {
                for part in &mut parts[k] {
                    part.child = Some(self.emit(part.value, &child, image)?);
                }
            }
        }
        let fragment = (c.emit)(&Instance {
            facts: self.facts,
            anchor: e,
            category,
            parts: &parts,
        });
        let root = fragment
            .root()
            .ok_or(Problem::Unrooted { construction: c.name })?;
        *image += fragment;
        self.emitted.insert((e, category.clone()), root);
        Ok(root)
    }

    fn diagnose<B: BlobStoreGet>(
        &mut self,
        e: Id,
        category: &C,
        path: &mut Vec<PathStep>,
        blobs: &B,
        findings: &mut Vec<Finding<C>>,
    ) {
        let here = |problem: Problem, path: &[PathStep]| Finding {
            path: render_path(path, blobs),
            category: category.clone(),
            problem,
        };
        let target = self.count(e, category);
        let grammar = self.grammar;
        let members = self.members(e);
        let mut candidates = Vec::new();
        for &i in grammar.by_category.get(&category.family()).into_iter().flatten() {
            let c = &grammar.constructions[i];
            if (c.anchor)(self.facts, e, category) {
                candidates.push(c);
            }
        }
        if candidates.is_empty() {
            findings.push(here(Problem::NoConstruction, path));
            return;
        }
        if target == Count::Many {
            // Only the constructions that do cover explain an ambiguity.
            candidates.retain(|c| matches!(self.instance(c, e, category, &members), Some((n, _)) if n != Count::Zero));
            if candidates.len() > 1 {
                let constructions = candidates.iter().map(|c| c.name).collect();
                findings.push(here(Problem::Ambiguous { constructions }, path));
                return;
            }
        }
        self.open.insert((e, category.clone()));
        for c in candidates {
            match self.fit(c, &members) {
                Fit::Missing(k) => findings.push(here(
                    Problem::Missing {
                        construction: c.name,
                        step: format!("{:?}", c.constituents[k].step),
                    },
                    path,
                )),
                Fit::Unclaimed(steps) => findings.push(here(
                    Problem::Unclaimed {
                        construction: c.name,
                        members: steps.iter().map(|s| render_step(s, blobs)).collect(),
                    },
                    path,
                )),
                Fit::Applies(parts) => {
                    for (k, con) in c.constituents.iter().enumerate() {
                        let Some(child) = con.role.child(self.facts, e, category) else {
                            continue;
                        };
                        for part in &parts[k] {
                            if self.open.contains(&(part.value, child.clone())) {
                                path.push(part.step);
                                findings.push(Finding {
                                    path: render_path(path, blobs),
                                    category: child.clone(),
                                    problem: Problem::Cycle,
                                });
                                path.pop();
                                continue;
                            }
                            if self.count(part.value, &child) != Count::One {
                                path.push(part.step);
                                self.diagnose(part.value, &child, path, blobs, findings);
                                path.pop();
                            }
                        }
                    }
                }
            }
        }
        self.open.remove(&(e, category.clone()));
    }
}

fn render_step<B: BlobStoreGet>(step: &PathStep, blobs: &B) -> String {
    match step {
        PathStep::Field(handle) => match blobs.get::<View<str>, UTF8String>(*handle) {
            Ok(name) => name.as_ref().to_owned(),
            Err(_) => String::from("<unresolved field name>"),
        },
        PathStep::Index(index) => index.to_string(),
    }
}

fn render_path<B: BlobStoreGet>(path: &[PathStep], blobs: &B) -> String {
    if path.is_empty() {
        return String::from("/");
    }
    path.iter().map(|s| format!("/{}", render_step(s, blobs))).collect()
}
