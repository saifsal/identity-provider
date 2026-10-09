//! The JWS algorithms this project knows about.
//!
//! `none` is deliberately absent: it cannot be named, so no policy can allow it
//! (ADR 0001). Names are matched case-sensitively, so `none`, `NONE` and `eddsa`
//! are all simply unknown (ADR 0003, header rules).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    EdDSA,
    ES256,
    /// Verification only, to pass the RFC 7515 Appendix A.1 vector (ADR 0001).
    HS256,
}

impl Alg {
    /// The registered JOSE name.
    pub fn name(self) -> &'static str {
        match self {
            Alg::EdDSA => "EdDSA",
            Alg::ES256 => "ES256",
            Alg::HS256 => "HS256",
        }
    }

    /// Looks up an algorithm by its exact, case-sensitive name.
    pub fn from_name(name: &str) -> Option<Alg> {
        match name {
            "EdDSA" => Some(Alg::EdDSA),
            "ES256" => Some(Alg::ES256),
            "HS256" => Some(Alg::HS256),
            _ => None,
        }
    }
}

impl fmt::Display for Alg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for alg in [Alg::EdDSA, Alg::ES256, Alg::HS256] {
            assert_eq!(Alg::from_name(alg.name()), Some(alg));
            assert_eq!(alg.to_string(), alg.name());
        }
    }

    #[test]
    fn matching_is_exact() {
        for s in ["none", "NONE", "None", "eddsa", "EDDSA", "es256", "hs256", "RS256", "", " EdDSA", "EdDSA "] {
            assert_eq!(Alg::from_name(s), None, "{s:?}");
        }
    }
}
