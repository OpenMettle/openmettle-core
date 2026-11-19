//! Operator-issued one-time home invitation code (ADR 0022).
use std::fmt;

/// Longest accepted input, measured before any normalization.
pub const MAX_INPUT_BYTES: usize = 64;
const PREFIX: &str = "omh1";

/// The 16 secret bytes of one invitation code. The create script prints the code once and the
/// database stores only its hash. This type has no `Display`, and `Debug` is redacted: the
/// bytes go only into the sealed login and the redemption function. Never log them.
#[derive(Clone)]
pub struct InvitationCode([u8; 16]);

impl InvitationCode {
    /// Syntax only: this does not show that any invitation has this code. Input is at most
    /// 64 ASCII bytes. ASCII spaces and `-` are removed and letters are lowercased. What
    /// remains is 32 hexadecimal digits, with or without the `omh1` prefix.
    pub fn parse(input: &str) -> Option<Self> {
        if input.len() > MAX_INPUT_BYTES || !input.is_ascii() {
            return None;
        }
        let compact: String = input
            .chars()
            .filter(|c| !matches!(c, ' ' | '-'))
            .map(|c| c.to_ascii_lowercase())
            .collect();
        let digits = compact.strip_prefix(PREFIX).unwrap_or(&compact);
        if digits.len() != 32 {
            return None;
        }
        let mut bytes = [0; 16];
        let (pairs, _) = digits.as_bytes().as_chunks::<2>();
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            let high = char::from(*high).to_digit(16)?;
            let low = char::from(*low).to_digit(16)?;
            *byte = (high * 16 + low) as u8;
        }
        Some(Self(bytes))
    }
    pub(crate) fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
    /// The code recovered from a sealed login (ADR 0009).
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}
impl fmt::Debug for InvitationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationCode(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = "omh1-0123-4567-89ab-cdef-fedc-ba98-7654-3210";
    const BYTES: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    #[test]
    fn accepted_forms_decode_to_the_same_sixteen_bytes() {
        let padded = format!(
            "{CANONICAL}{}",
            " ".repeat(MAX_INPUT_BYTES - CANONICAL.len())
        );
        assert_eq!(padded.len(), MAX_INPUT_BYTES);
        for input in [
            CANONICAL,
            "OMH1-0123-4567-89AB-CDEF-FEDC-BA98-7654-3210",
            "omh10123456789abcdeffedcba9876543210",
            "0123-4567-89ab-cdef-fedc-ba98-7654-3210",
            "0123456789ABCDEFfedcba9876543210",
            " omh1 0123 4567 89ab cdef fedc ba98 7654 3210 ",
            padded.as_str(),
        ] {
            let code = InvitationCode::parse(input).expect("accepted form");
            assert_eq!(code.bytes(), &BYTES);
        }
    }

    #[test]
    fn malformed_input_is_refused() {
        let hex = &CANONICAL.replace('-', "")["omh1".len()..];
        assert_eq!(hex.len(), 32);
        let long = format!(
            "{CANONICAL}{}",
            " ".repeat(MAX_INPUT_BYTES + 1 - CANONICAL.len())
        );
        assert_eq!(long.len(), MAX_INPUT_BYTES + 1);
        for input in [
            String::new(),
            "omh1".into(),
            hex[..31].into(),
            format!("{hex}0"),
            format!("omh1{}", &hex[..31]),
            format!("omh1{hex}0"),
            // Not hexadecimal, including a second prefix and another version's prefix.
            format!("{}g", &hex[..31]),
            format!("omh1omh1{}", &hex[..28]),
            format!("omh2{hex}"),
            format!("0x{}", &hex[..30]),
            // Separators other than the ASCII space and hyphen are not removed.
            CANONICAL.replace('-', "_"),
            CANONICAL.replace('-', "\t"),
            format!("{CANONICAL}\n"),
            // Not ASCII: a full-width digit and a non-breaking space.
            format!("{}\u{ff10}", &hex[..31]),
            CANONICAL.replace('-', "\u{a0}"),
            long,
        ] {
            assert!(
                InvitationCode::parse(&input).is_none(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let code = InvitationCode::parse(CANONICAL).unwrap();
        assert_eq!(format!("{code:?}"), "InvitationCode(..)");
        assert_eq!(format!("{:?}", Some(&code)), "Some(InvitationCode(..))");
    }
}
