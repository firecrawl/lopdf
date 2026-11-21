use super::Object;
use crate::Result;
use crate::parser::{ParserInput, comment, content_space, inline_image, operand, operator_bytes};
use crate::writer::Writer;
use nom::Err as NomErr;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct Operation {
    pub operator: String,
    pub operands: Vec<Object>,
}

impl Operation {
    pub fn new(operator: &str, operands: Vec<Object>) -> Operation {
        Operation {
            operator: operator.to_string(),
            operands,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Content<Operations: AsRef<[Operation]> = Vec<Operation>> {
    pub operations: Operations,
}

impl<Operations: AsRef<[Operation]>> Content<Operations> {
    /// Encode content operations.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut first_operation = true;
        for operation in self.operations.as_ref() {
            // Add new line after each operation except the last one.
            if first_operation {
                first_operation = false;
            } else {
                buffer.write_all(b"\n")?;
            }
            for operand in &operation.operands {
                Writer::write_object(&mut buffer, operand)?;
                buffer.write_all(b" ")?;
            }
            buffer.write_all(operation.operator.as_bytes())?;
        }
        Ok(buffer)
    }
}

/// Streaming reader over a content stream's operations.
///
/// Yields the same operations as `Content::decode` without materializing
/// them: one reused operation buffer serves the whole stream, so iteration
/// allocates only for operand payloads that own heap data (names, strings,
/// arrays, dictionaries). Operations with purely numeric operands iterate
/// allocation-free once the buffers are warm.
///
/// End-of-stream semantics mirror `Content::decode` exactly: the first
/// unparseable operation ends iteration and its partially parsed operands
/// are discarded. When the parse fails hard instead of merely ending (an
/// inline image whose recovery scan finds no `EI`, or operand nesting
/// beyond the supported depth), [`Self::poisoned`] returns true; whole-
/// stream decoding returns an error for those inputs, so callers that
/// reproduce its semantics must discard every operation yielded so far.
///
/// The accessors are meaningful only after an [`Self::advance`] call that
/// returned true.
pub struct ContentOperations<'a> {
    remaining: ParserInput<'a>,
    operator: String,
    operands: Vec<Object>,
    done: bool,
    poisoned: bool,
}

impl<'a> ContentOperations<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        // Whole-stream decoding skips leading content whitespace before the
        // first operation; content_space is take_while and cannot fail.
        let remaining = match content_space(data) {
            Ok((rest, ())) => rest,
            Err(_) => data,
        };
        ContentOperations {
            remaining,
            operator: String::new(),
            operands: Vec::new(),
            done: false,
            poisoned: false,
        }
    }

    /// Advance to the next operation. Returns false when the stream ends;
    /// check [`Self::poisoned`] to distinguish a clean end from a failed
    /// parse.
    pub fn advance(&mut self) -> bool {
        if self.done {
            return false;
        }
        // Comments between operations.
        while let Ok((rest, ())) = comment(self.remaining) {
            self.remaining = rest;
        }
        // The inline-image branch commits on exactly these two bytes (its
        // tag is followed by zero-width whitespace), and every failure past
        // the tag is a hard one: whole-stream decoding aborts there rather
        // than falling back to the operand branch.
        if self.remaining.starts_with(b"BI") {
            return match inline_image(self.remaining) {
                Ok((rest, (operands, operator))) => {
                    self.remaining = rest;
                    self.operator.clear();
                    self.operator.push_str(&operator);
                    self.operands.clear();
                    self.operands.extend(operands);
                    true
                }
                Err(_) => self.stop(true),
            };
        }
        self.operands.clear();
        loop {
            match operand(self.remaining) {
                Ok((rest, object)) => {
                    self.remaining = rest;
                    self.operands.push(object);
                }
                // The operand list ends where the operator (or garbage)
                // begins.
                Err(NomErr::Error(_)) => break,
                // Nesting-depth exhaustion aborts whole-stream decoding.
                Err(_) => return self.stop(true),
            }
        }
        match operator_bytes(self.remaining) {
            Ok((rest, op)) => {
                self.operator.clear();
                self.operator.push_str(op);
                self.remaining = match content_space(rest) {
                    Ok((rest, ())) => rest,
                    Err(_) => rest,
                };
                true
            }
            // No operator: whole-stream decoding stops here and discards
            // the partial operands.
            Err(NomErr::Error(_)) => self.stop(false),
            Err(_) => self.stop(true),
        }
    }

    /// The current operation's operator. Valid only after an `advance`
    /// that returned true.
    pub fn operator(&self) -> &str {
        &self.operator
    }

    /// The current operation's operands. Valid only after an `advance`
    /// that returned true.
    pub fn operands(&self) -> &[Object] {
        &self.operands
    }

    /// True when iteration ended because the stream failed to parse (the
    /// whole-stream decode returns an error for this input) rather than
    /// reaching a clean end.
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    fn stop(&mut self, poisoned: bool) -> bool {
        self.done = true;
        self.poisoned = poisoned;
        // Discarded partial state must not be observable afterwards.
        self.operator.clear();
        self.operands.clear();
        false
    }
}

#[cfg(test)]
mod streaming_equivalence_tests {
    use super::*;

    /// The reader must agree with `Content::decode` on every input: same
    /// operations when decoding succeeds, a poisoned end when it errors
    /// (in which case the yielded prefix is unspecified, matching the
    /// decoder's discard-everything behavior).
    fn assert_stream_matches_decode(data: &[u8]) {
        let mut reader = ContentOperations::new(data);
        let mut streamed: Vec<Operation> = Vec::new();
        while reader.advance() {
            streamed.push(Operation {
                operator: reader.operator().to_string(),
                operands: reader.operands().to_vec(),
            });
        }
        match Content::decode(data) {
            Ok(content) => {
                assert!(
                    !reader.poisoned(),
                    "decode succeeded but the reader ended poisoned: {:?}",
                    String::from_utf8_lossy(data)
                );
                assert_eq!(
                    content.operations.len(),
                    streamed.len(),
                    "operation count mismatch for {:?}",
                    String::from_utf8_lossy(data)
                );
                for (decoded, streamed) in content.operations.iter().zip(&streamed) {
                    assert_eq!(decoded.operator, streamed.operator);
                    assert_eq!(decoded.operands, streamed.operands);
                }
            }
            Err(_) => {
                assert!(
                    reader.poisoned(),
                    "decode failed but the reader ended clean: {:?}",
                    String::from_utf8_lossy(data)
                );
            }
        }
        // A retry after the end must stay inert.
        assert!(!reader.advance());
    }

    #[test]
    fn plain_operations() {
        assert_stream_matches_decode(b"1 2 m 3 4 l S");
        assert_stream_matches_decode(b"BT /F1 12 Tf (Hello) Tj ET");
        assert_stream_matches_decode(b"q 0.5 0 0 0.5 0 0 cm Q");
    }

    #[test]
    fn empty_and_whitespace_streams() {
        assert_stream_matches_decode(b"");
        assert_stream_matches_decode(b"   \t\r\n ");
        // \x0C and \0 are not content whitespace: zero operations today.
        assert_stream_matches_decode(b"\x0C q Q");
        assert_stream_matches_decode(b"\0 q Q");
    }

    #[test]
    fn comments() {
        assert_stream_matches_decode(b"% lead\nq Q");
        assert_stream_matches_decode(b"q\n% between\nQ");
        assert_stream_matches_decode(b"q Q\n% trailing\n");
        // Unterminated trailing comment (no eol).
        assert_stream_matches_decode(b"q Q % no newline");
        // Comment then an indented line: the indent is not consumed by
        // anything, so today's decoder drops the tail operations.
        assert_stream_matches_decode(b"q\n% c\n  1 2 m");
        // Comment between operands stops the stream identically.
        assert_stream_matches_decode(b"1 % c\n2 m");
    }

    #[test]
    fn operator_edges() {
        // Operator at end of input, no trailing byte.
        assert_stream_matches_decode(b"1 2 m");
        // Digits terminate an operator token: `d0` parses as operator `d`
        // and the 0 joins the next (never-completed) operation.
        assert_stream_matches_decode(b"1 2 d0");
        // Trailing garbage after a complete operation.
        assert_stream_matches_decode(b"q Q )");
        assert_stream_matches_decode(b"q Q 1 2");
    }

    #[test]
    fn inline_images() {
        // Valid 1x1 gray image, 1 byte of data.
        assert_stream_matches_decode(b"BI /W 1 /H 1 /BPC 8 /CS /DeviceGray ID x EI q Q");
        // Unparseable image dict with an ` EI ` window: recovery skips it.
        assert_stream_matches_decode(b"BI /Foo 1 ID zzz EI q Q");
        // BI after operands is a plain operator, not an image.
        assert_stream_matches_decode(b"/N BI /W 1 /H 1 ID xx EI ");
    }

    #[test]
    fn poisoned_streams() {
        // BI committed, dictionary unparseable, no EI window anywhere.
        assert_stream_matches_decode(b"q Q BIX");
        // Truncated inline image: data ends before any ` EI `.
        assert_stream_matches_decode(b"(Hello) Tj BI /W 8 /H 8 /BPC 8 /CS /DeviceGray ID xx");
        // Operand nesting beyond the supported depth.
        let mut deep = Vec::new();
        deep.extend(std::iter::repeat_n(b'[', 101));
        assert_stream_matches_decode(&deep);
    }

    #[test]
    fn nested_operands() {
        assert_stream_matches_decode(b"[(a) 1 (b) 2] TJ");
        assert_stream_matches_decode(b"<< /A [1 2 [3]] >> x");
    }
}
