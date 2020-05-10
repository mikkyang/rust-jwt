#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="UPPERCASE")]
pub enum AlgorithmType {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
    Es512,
    Ps256,
    Ps384,
    Ps512,
    #[serde(rename="none")]
    None,
}
