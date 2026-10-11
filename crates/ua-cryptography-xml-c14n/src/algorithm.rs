/// A canonicalization method of XML-DSig, named by its `Algorithm` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Canonical XML 1.0 (W3C REC-xml-c14n-20010315), comments left out.
    Inclusive,
    /// Canonical XML 1.0 with comments.
    InclusiveWithComments,
    /// Exclusive XML Canonicalization 1.0 (W3C REC-xml-exc-c14n-20020718), comments left out.
    Exclusive,
    /// Exclusive XML Canonicalization 1.0 with comments.
    ExclusiveWithComments,
}

/// The URI of Canonical XML 1.0.
const INCLUSIVE_URI: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
/// The URI of Canonical XML 1.0 with comments.
const INCLUSIVE_WITH_COMMENTS_URI: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
/// The URI of Exclusive XML Canonicalization 1.0.
const EXCLUSIVE_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The URI of Exclusive XML Canonicalization 1.0 with comments.
const EXCLUSIVE_WITH_COMMENTS_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

impl Algorithm {
    /// The method a `ds:CanonicalizationMethod` or `ds:Transform` URI names, if it is one of the four.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            INCLUSIVE_URI => Some(Algorithm::Inclusive),
            INCLUSIVE_WITH_COMMENTS_URI => Some(Algorithm::InclusiveWithComments),
            EXCLUSIVE_URI => Some(Algorithm::Exclusive),
            EXCLUSIVE_WITH_COMMENTS_URI => Some(Algorithm::ExclusiveWithComments),
            _ => None,
        }
    }

    /// The `Algorithm` URI of the method.
    pub fn uri(self) -> &'static str {
        match self {
            Algorithm::Inclusive => INCLUSIVE_URI,
            Algorithm::InclusiveWithComments => INCLUSIVE_WITH_COMMENTS_URI,
            Algorithm::Exclusive => EXCLUSIVE_URI,
            Algorithm::ExclusiveWithComments => EXCLUSIVE_WITH_COMMENTS_URI,
        }
    }

    pub(crate) fn is_exclusive(self) -> bool {
        matches!(self, Algorithm::Exclusive | Algorithm::ExclusiveWithComments)
    }

    pub(crate) fn keeps_comments(self) -> bool {
        matches!(
            self,
            Algorithm::InclusiveWithComments | Algorithm::ExclusiveWithComments
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_is_found_by_its_uri() {
        for algorithm in [
            Algorithm::Inclusive,
            Algorithm::InclusiveWithComments,
            Algorithm::Exclusive,
            Algorithm::ExclusiveWithComments,
        ] {
            assert_eq!(Algorithm::from_uri(algorithm.uri()), Some(algorithm));
        }
        assert_eq!(Algorithm::from_uri("http://www.w3.org/2006/12/xml-c14n11"), None);
    }
}
