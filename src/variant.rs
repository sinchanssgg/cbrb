//! Protocol variant selector.

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Variant {
    /// CRBB as specified in Algorithm 1: full VK in every ECHO/READY,
    /// exact Pedersen verification per share.
    Crbb,
    /// CRBB-H: digest-only ECHO/READY with REQ/REPLY retrieval,
    /// batched verification per share.
    CrbbH,
}

impl Variant {
    pub fn parse(s: &str) -> Self {
        match s {
            "crbb" => Variant::Crbb,
            "crbb-h" | "crbbh" | "h" => Variant::CrbbH,
            _ => panic!("unknown variant: {}", s),
        }
    }
}