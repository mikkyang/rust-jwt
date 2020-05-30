use std::ops::Index;

/// A store of keys that can be retrieved by key id.
pub trait Store {
    type Algorithm: ?Sized;

    fn get(&self, key_id: &str) -> Option<&Self::Algorithm>;
}

impl<T, A> Store for T
where
    for<'a> T: Index<&'a str, Output = A>,
{
    type Algorithm = A;

    fn get(&self, key_id: &str) -> Option<&A> {
        Some(&self[key_id])
    }
}
