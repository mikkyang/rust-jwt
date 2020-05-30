pub trait Store {
    type Algorithm: ?Sized;

    fn get(&self, key_id: &str) -> Option<&Self::Algorithm>;
}
