//! One routing descent, with callbacks before any semantic mutation.
//!
//! Unique paths update in place. Shared paths are read-only until absence is
//! established, then copy on unwind. Cloning every child before descending
//! would unnecessarily force COW even on a unique replay path; eagerly COWing
//! shared branches would invalidate snapshots on a duplicate or rejected value.

use super::*;

enum Position {
    Split { depth: usize, old: u8, new: u8 },
    Occupied,
    Child { depth: usize, edge: u8 },
}

impl<const K: usize, O: KeySchema<K>, V, H: PatchHash> Head<K, O, V, H> {
    fn insertion_position(&self, key: &[u8; K], start: usize) -> Position {
        let end = self.end_depth();
        let existing = self.childleaf_key();
        for depth in start..end {
            let i = O::TREE_TO_KEY[depth];
            if existing[i] != key[i] {
                return Position::Split { depth, old: existing[i], new: key[i] };
            }
        }
        if end == K {
            Position::Occupied
        } else {
            Position::Child { depth: end, edge: key[O::TREE_TO_KEY[end]] }
        }
    }

    pub(super) fn try_insert_with<E>(
        &mut self,
        key: &[u8; K],
        start: usize,
        vacant: impl FnOnce() -> V,
        occupied: impl FnOnce(&V) -> Result<(), E>,
    ) -> Result<bool, E> {
        let position = self.insertion_position(key, start);
        if matches!(self.body_ref(), BodyRef::Branch(branch) if !branch.is_unique()) {
            if let Some(inserted) = self.insert_shared_at(key, position, vacant, occupied)? {
                *self = inserted;
                return Ok(true);
            }
            return Ok(false);
        }
        match position {
            Position::Occupied => {
                occupied(self.leaf_entry().1)?;
                Ok(false)
            }
            Position::Split { depth, old, new } => {
                drop(occupied);
                let entry = Entry::with_value(key, vacant());
                let branch = Branch::new(depth, self.clone().with_key(old), entry.leaf().with_key(new));
                *self = Head::new(self.key(), branch);
                Ok(true)
            }
            Position::Child { depth, edge } => {
                let mut editor = BranchMut::from_head(self);
                if editor.child_table.table_get(edge).is_some() {
                    editor.try_update_child(edge, |child| {
                        child.try_insert_with(key, depth + 1, vacant, occupied)
                    })
                } else {
                    drop(occupied);
                    let entry = Entry::with_value(key, vacant());
                    editor.modify_child(edge, |_| Some(entry.leaf().with_key(edge)));
                    Ok(true)
                }
            }
        }
    }

    fn insert_shared_at<E>(
        &self,
        key: &[u8; K],
        position: Position,
        vacant: impl FnOnce() -> V,
        occupied: impl FnOnce(&V) -> Result<(), E>,
    ) -> Result<Option<Self>, E> {
        match position {
            Position::Occupied => {
                occupied(self.leaf_entry().1)?;
                Ok(None)
            }
            Position::Split { depth, old, new } => {
                drop(occupied);
                let entry = Entry::with_value(key, vacant());
                let branch = Branch::new(depth, self.clone().with_key(old), entry.leaf().with_key(new));
                Ok(Some(Head::new(self.key(), branch)))
            }
            Position::Child { depth, edge } => {
                let BodyRef::Branch(branch) = self.body_ref() else { unreachable!() };
                let inserted = if let Some(child) = branch.child_table.table_get(edge) {
                    let position = child.insertion_position(key, depth + 1);
                    let Some(inserted) = child.insert_shared_at(key, position, vacant, occupied)? else {
                        return Ok(None);
                    };
                    inserted
                } else {
                    drop(occupied);
                    Entry::with_value(key, vacant()).leaf().with_key(edge)
                };
                // No user callback remains. Copy only the actually shared path,
                // preserving untouched child Heads and the incoming edge byte.
                let mut result = self.clone();
                BranchMut::from_head(&mut result).modify_child(edge, |_| Some(inserted));
                Ok(Some(result))
            }
        }
    }
}
