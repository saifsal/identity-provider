//! A small, strict JSON parser (RFC 8259) for JOSE headers, claims and JWKS.
//!
//! Why hand-written: the verifier must reject duplicate member names (ADR 0003,
//! steps 4, 10 and 12), and `serde_json` accepts them by default. Two components
//! that disagree about duplicates can be exploited against each other, so the
//! rule has to be enforced while parsing, not afterwards.
//!
//! Strictness beyond the grammar:
//!
//! * duplicate member names are an error at every nesting level, compared after
//!   unescaping, so `"a"` and `"\u0061"` count as the same name;
//! * lone surrogate escapes are an error;
//! * nesting deeper than [`MAX_DEPTH`] is an error, so hostile input cannot
//!   exhaust the stack;
//! * the input must be valid UTF-8 and contain exactly one value, with nothing
//!   but JSON whitespace around it.
//!
//! Numbers are not converted to floating point. A number written as a plain
//! integer that fits in `i64` becomes [`Number::Int`]. Every other number,
//! including `1.0`, `1e3` and integers outside the `i64` range, becomes
//! [`Number::Other`] and keeps its source text. Callers that require an integer
//! (`exp`, `nbf`) therefore reject all of those forms.

use std::collections::HashSet;
use std::fmt;

/// Maximum nesting depth of arrays and objects.
pub const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Number {
    /// A number written as an integer literal that fits in `i64`.
    Int(i64),
    /// Any other valid JSON number, kept as written.
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    /// Members in source order. Names are unique, which the parser guarantees.
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The value as an integer, only for a number written as an integer literal
    /// that fits in `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(Number::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// The member called `name`, if this is an object that has one.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    InvalidUtf8,
    UnexpectedEnd,
    /// A byte that does not fit the grammar at this position, as a byte offset.
    Unexpected { index: usize },
    /// A bad escape sequence, a lone surrogate, or a raw control character in a
    /// string.
    InvalidString { index: usize },
    /// Content after the end of the top-level value.
    TrailingData { index: usize },
    DuplicateKey { name: String },
    TooDeep,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::InvalidUtf8 => write!(f, "input is not valid UTF-8"),
            JsonError::UnexpectedEnd => write!(f, "unexpected end of input"),
            JsonError::Unexpected { index } => write!(f, "unexpected byte at offset {index}"),
            JsonError::InvalidString { index } => write!(f, "invalid string at offset {index}"),
            JsonError::TrailingData { index } => {
                write!(f, "trailing data at offset {index}")
            }
            JsonError::DuplicateKey { name } => write!(f, "duplicate member name {name:?}"),
            JsonError::TooDeep => write!(f, "nesting deeper than {MAX_DEPTH}"),
        }
    }
}

impl std::error::Error for JsonError {}

/// Parses exactly one JSON value from `input`.
pub fn parse(input: &[u8]) -> Result<Value, JsonError> {
    let text = std::str::from_utf8(input).map_err(|_| JsonError::InvalidUtf8)?;
    let mut parser = Parser { text, pos: 0 };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != text.len() {
        return Err(JsonError::TrailingData { index: parser.pos });
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn unexpected(&self) -> JsonError {
        match self.peek() {
            Some(_) => JsonError::Unexpected { index: self.pos },
            None => JsonError::UnexpectedEnd,
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, JsonError> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            // Report the first byte that differs from the expected word.
            let rest = self.text.as_bytes()[self.pos..].iter();
            let matched = rest.zip(word.bytes()).take_while(|(a, b)| *a == b).count();
            self.pos += matched;
            Err(self.unexpected())
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.unexpected()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth >= MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.unexpected());
            }
            let name = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            if !seen.insert(name.clone()) {
                return Err(JsonError::DuplicateKey { name });
            }
            members.push((name, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth >= MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn digits(&mut self) -> Result<(), JsonError> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == start {
            Err(self.unexpected())
        } else {
            Ok(())
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            // A leading zero stands alone: "01" is not a number.
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits()?,
            _ => return Err(self.unexpected()),
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.pos += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.digits()?;
        }
        let lexeme = &self.text[start..self.pos];
        let number = match integral.then(|| lexeme.parse::<i64>()) {
            Some(Ok(n)) => Number::Int(n),
            _ => Number::Other(lexeme.to_string()),
        };
        Ok(Value::Number(number))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self
            .text
            .as_bytes()
            .get(self.pos..self.pos + 4)
            .ok_or(JsonError::UnexpectedEnd)?;
        let mut n = 0u32;
        for &b in digits {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(JsonError::InvalidString { index: self.pos }),
            };
            n = (n << 4) | u32::from(d);
            self.pos += 1;
        }
        Ok(n)
    }

    /// Parses a `\uXXXX` escape, including a following low surrogate when the
    /// first unit is a high surrogate. `self.pos` is just after the `u`.
    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let at = self.pos;
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !self.text[self.pos..].starts_with("\\u") {
                    return Err(JsonError::InvalidString { index: at });
                }
                self.pos += 2;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(JsonError::InvalidString { index: at });
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(JsonError::InvalidString { index: at }),
            other => other,
        };
        char::from_u32(code).ok_or(JsonError::InvalidString { index: at })
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        // Start of the current run of bytes that need no translation. Runs end
        // only at ASCII bytes, so slicing there is always on a char boundary.
        let mut run = self.pos;
        loop {
            let Some(b) = self.peek() else {
                return Err(JsonError::UnexpectedEnd);
            };
            match b {
                b'"' => {
                    out.push_str(&self.text[run..self.pos]);
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.text[run..self.pos]);
                    self.pos += 1;
                    let Some(esc) = self.peek() else {
                        return Err(JsonError::UnexpectedEnd);
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(JsonError::InvalidString { index: self.pos - 1 }),
                    }
                    run = self.pos;
                }
                0x00..=0x1F => return Err(JsonError::InvalidString { index: self.pos }),
                _ => self.pos += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Value, JsonError> {
        parse(s.as_bytes())
    }

    fn ok(s: &str) -> Value {
        p(s).unwrap_or_else(|e| panic!("{s:?} should parse, got {e}"))
    }

    fn int(n: i64) -> Value {
        Value::Number(Number::Int(n))
    }

    #[test]
    fn parses_scalars() {
        assert_eq!(ok("null"), Value::Null);
        assert_eq!(ok("true"), Value::Bool(true));
        assert_eq!(ok("false"), Value::Bool(false));
        assert_eq!(ok("0"), int(0));
        assert_eq!(ok("-0"), int(0));
        assert_eq!(ok("1700000000"), int(1_700_000_000));
        assert_eq!(ok("\"abc\""), Value::String("abc".into()));
        assert_eq!(ok("\"\""), Value::String(String::new()));
    }

    #[test]
    fn parses_the_rfc_7515_a1_header() {
        // RFC 7515 Appendix A.1.1 decoded header, including its CRLF and space.
        let v = ok("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
        assert_eq!(v.get("typ").and_then(Value::as_str), Some("JWT"));
        assert_eq!(v.get("alg").and_then(Value::as_str), Some("HS256"));
        assert_eq!(v.get("kid"), None);
    }

    #[test]
    fn parses_nested_structures_and_keeps_member_order() {
        let v = ok(r#"{"b":[1,2,{"c":null}],"a":{"x":true}}"#);
        let names: Vec<&str> = v.as_object().unwrap().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["b", "a"]);
        let arr = v.get("b").unwrap().as_array().unwrap();
        assert_eq!(arr[0], int(1));
        assert_eq!(arr[2].get("c"), Some(&Value::Null));
    }

    #[test]
    fn allows_json_whitespace_only() {
        assert_eq!(ok(" \t\r\n[ 1 , 2 ]\n"), Value::Array(vec![int(1), int(2)]));
        assert!(p("\u{000B}1").is_err());
        assert!(p("\u{00A0}1").is_err());
        assert!(p("\u{FEFF}1").is_err());
    }

    #[test]
    fn rejects_duplicate_keys_at_top_level() {
        assert_eq!(
            p(r#"{"alg":"EdDSA","alg":"none"}"#),
            Err(JsonError::DuplicateKey { name: "alg".into() })
        );
    }

    #[test]
    fn rejects_duplicate_keys_in_nested_objects() {
        assert_eq!(
            p(r#"{"a":{"b":1,"b":2}}"#),
            Err(JsonError::DuplicateKey { name: "b".into() })
        );
        assert_eq!(
            p(r#"[{"k":1,"k":1}]"#),
            Err(JsonError::DuplicateKey { name: "k".into() })
        );
    }

    #[test]
    fn same_name_in_different_objects_is_fine() {
        ok(r#"{"a":{"x":1},"b":{"x":2},"c":[{"x":3},{"x":4}]}"#);
    }

    #[test]
    fn duplicate_detection_works_after_unescaping() {
        assert_eq!(
            p(r#"{"a":1,"\u0061":2}"#),
            Err(JsonError::DuplicateKey { name: "a".into() })
        );
        assert_eq!(
            p(r#"{"a/b":1,"a\/b":2}"#),
            Err(JsonError::DuplicateKey { name: "a/b".into() })
        );
        // Different names that merely look similar are not duplicates.
        ok(r#"{"a":1,"A":2,"a ":3}"#);
    }

    #[test]
    fn decodes_escapes() {
        assert_eq!(
            ok(r#""\"\\\/\b\f\n\r\t""#),
            Value::String("\"\\/\u{8}\u{c}\n\r\t".into())
        );
        assert_eq!(ok(r#""\u00e9\u00E9""#), Value::String("éé".into()));
        assert_eq!(ok(r#""\u0000""#), Value::String("\0".into()));
    }

    #[test]
    fn passes_through_raw_utf8() {
        assert_eq!(ok("\"é€😀\""), Value::String("é€😀".into()));
        assert_eq!(ok("{\"é\":\"ü\"}").get("é").and_then(Value::as_str), Some("ü"));
    }

    #[test]
    fn combines_surrogate_pairs() {
        assert_eq!(ok(r#""\ud83d\ude00""#), Value::String("😀".into()));
        assert_eq!(ok(r#""\uD83D\uDE00""#), Value::String("😀".into()));
    }

    #[test]
    fn rejects_lone_and_misordered_surrogates() {
        for s in [
            r#""\ud83d""#,
            r#""\ud83dx""#,
            r#""\ud83d\u0041""#,
            r#""\ude00""#,
            r#""\ude00\ud83d""#,
        ] {
            assert!(
                matches!(p(s), Err(JsonError::InvalidString { .. })),
                "{s:?} gave {:?}",
                p(s)
            );
        }
    }

    #[test]
    fn rejects_bad_escapes_and_control_characters() {
        for s in [r#""\x41""#, r#""\u12G4""#, r#""\u12""#, "\"a\nb\"", "\"a\tb\"", "\"\u{1}\""] {
            assert!(p(s).is_err(), "{s:?} should be rejected");
        }
        assert!(matches!(p(r#""\q""#), Err(JsonError::InvalidString { .. })));
        assert!(matches!(p("\"a\nb\""), Err(JsonError::InvalidString { .. })));
    }

    #[test]
    fn rejects_unterminated_input() {
        for s in ["", " ", "{", "[", "\"abc", "{\"a\"", "{\"a\":", "{\"a\":1", "[1,", "tru"] {
            assert!(p(s).is_err(), "{s:?} should be rejected");
        }
        assert_eq!(p(""), Err(JsonError::UnexpectedEnd));
        assert_eq!(p("\"abc"), Err(JsonError::UnexpectedEnd));
    }

    #[test]
    fn rejects_grammar_violations() {
        for s in [
            "{,}", "[,]", "[1,]", r#"{"a":1,}"#, r#"{"a" 1}"#, r#"{a:1}"#, r#"{'a':1}"#, "[1 2]",
            r#"{"a":1 "b":2}"#, "nul", "True", "NULL", "undefined", "NaN", "Infinity", "// c\n1",
            "/* c */1", "[1]]", "{}}",
        ] {
            assert!(p(s).is_err(), "{s:?} should be rejected");
        }
    }

    #[test]
    fn rejects_multiple_top_level_values() {
        assert_eq!(p("1 2"), Err(JsonError::TrailingData { index: 2 }));
        assert_eq!(p("{} {}"), Err(JsonError::TrailingData { index: 3 }));
        assert!(p("{}x").is_err());
    }

    #[test]
    fn number_grammar_is_strict() {
        for s in [
            "01", "-01", "00", "+1", ".5", "1.", "-", "-.5", "1e", "1e+", "1.e3", "0x10", "1_000",
            "- 1", "--1",
        ] {
            assert!(p(s).is_err(), "{s:?} should be rejected");
        }
    }

    #[test]
    fn only_plain_integers_are_ints() {
        assert_eq!(ok("42").as_i64(), Some(42));
        assert_eq!(ok("-42").as_i64(), Some(-42));
        assert_eq!(ok("9223372036854775807").as_i64(), Some(i64::MAX));
        assert_eq!(ok("-9223372036854775808").as_i64(), Some(i64::MIN));
        for s in ["9223372036854775808", "1.0", "1.5", "1e3", "1E3", "1e-3", "-0.0", "10e0"] {
            assert_eq!(ok(s), Value::Number(Number::Other(s.into())), "{s:?}");
            assert_eq!(ok(s).as_i64(), None, "{s:?}");
        }
    }

    #[test]
    fn accessors_do_not_coerce_types() {
        assert_eq!(ok("\"1\"").as_i64(), None);
        assert_eq!(ok("1").as_str(), None);
        assert_eq!(ok("[]").as_object(), None);
        assert_eq!(ok("{}").as_array(), None);
        assert_eq!(ok("[1]").get("x"), None);
        assert_eq!(ok("true").as_i64(), None);
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(parse(b"\"\xff\""), Err(JsonError::InvalidUtf8));
        assert_eq!(parse(b"\"\xc3\""), Err(JsonError::InvalidUtf8));
        // Overlong encoding of '/'.
        assert_eq!(parse(b"\"\xc0\xaf\""), Err(JsonError::InvalidUtf8));
        // A UTF-8 encoded surrogate.
        assert_eq!(parse(b"\"\xed\xa0\x80\""), Err(JsonError::InvalidUtf8));
    }

    #[test]
    fn nesting_limit_is_exact() {
        let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(p(&nested(MAX_DEPTH)).is_ok());
        assert_eq!(p(&nested(MAX_DEPTH + 1)), Err(JsonError::TooDeep));

        let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
        assert!(p(&objects(MAX_DEPTH)).is_ok());
        assert_eq!(p(&objects(MAX_DEPTH + 1)), Err(JsonError::TooDeep));
    }

    #[test]
    fn deeply_nested_hostile_input_does_not_overflow_the_stack() {
        let deep = "[".repeat(1_000_000);
        assert_eq!(p(&deep), Err(JsonError::TooDeep));
    }

    #[test]
    fn handles_many_members_and_long_strings() {
        let body: Vec<String> = (0..2000).map(|i| format!("\"k{i}\":{i}")).collect();
        let v = ok(&format!("{{{}}}", body.join(",")));
        assert_eq!(v.as_object().unwrap().len(), 2000);
        assert_eq!(v.get("k1999").and_then(Value::as_i64), Some(1999));

        let long = "x".repeat(100_000);
        assert_eq!(ok(&format!("\"{long}\"")).as_str(), Some(long.as_str()));
    }
}
