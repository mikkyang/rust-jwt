pub struct Unsigned;

pub struct Signed {
    pub token_string: String,
}

pub struct Verified;

pub struct BorrowedUnverified<'a> {
    pub header_str: &'a str,
    pub claims_str: &'a str,
    pub signature_str: &'a str,
}

pub struct Unverified {
    pub token_string: String,
}
