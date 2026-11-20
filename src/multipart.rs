//! Streaming `multipart/form-data` parser for one artifact upload (RFC 7578 over the RFC 2046
//! §5.1 framing; ADR 0031). It is sans-I/O: the caller feeds body chunks of any size, down to
//! one byte, and receives the file part's bytes as they become certain. Memory is bounded by
//! the chunk plus a carry of at most one part header block or one delimiter, and the metadata
//! part, whatever the file size. The file's byte ceiling belongs to the storage sink.
//!
//! A form is exactly one `file` part, with an explicit `Content-Type` and an optional
//! `filename` kept as display metadata, and one `metadata` part of `application/json`, in
//! either order. Any other part, a repeated part, a part header other than
//! `Content-Disposition` and `Content-Type`, or a stream without its closing delimiter is
//! refused. Errors are fixed categories that never carry request bytes.
use crate::storage::valid_display_name;
use std::fmt;

/// Largest header block of one part, excluding its terminating blank line.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Largest `metadata` part body.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
/// Largest preamble before the first delimiter, and largest epilogue after the closing one.
pub const MAX_SKIPPED_BYTES: usize = 1024;
/// Stored media types are at most this long, as migration 4 requires.
const MAX_MEDIA_TYPE_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The request is not `multipart/form-data` with exactly one valid boundary.
    ContentType,
    /// Framing, part header syntax or `Content-Disposition` is malformed.
    Malformed,
    /// A part header block exceeds [`MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// A part is named neither `file` nor `metadata`.
    UnknownPart,
    /// A second `file` or `metadata` part.
    DuplicatePart,
    /// The form lacks its `file` or `metadata` part.
    MissingPart,
    /// A part's media type is missing, malformed or unsupported.
    MediaType,
    /// The file name is not an acceptable display name.
    DisplayName,
    /// The `metadata` part exceeds [`MAX_METADATA_BYTES`].
    MetadataTooLarge,
    /// The stream ended before the closing delimiter.
    Truncated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContentType => "request is not multipart/form-data with one valid boundary",
            Self::Malformed => "multipart body is malformed",
            Self::HeadersTooLarge => "multipart part headers are too large",
            Self::UnknownPart => "multipart part is not file or metadata",
            Self::DuplicatePart => "multipart part is repeated",
            Self::MissingPart => "multipart file or metadata part is missing",
            Self::MediaType => "multipart part media type is missing or unsupported",
            Self::DisplayName => "file name is not an acceptable display name",
            Self::MetadataTooLarge => "metadata part is too large",
            Self::Truncated => "multipart body ended before its closing delimiter",
        })
    }
}

/// The completed form, apart from the file bytes already handed out by [`Parser::feed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    /// The file part's media type: essence in lower case, then any parameters.
    pub media_type: String,
    /// The file name without any directory part, or `None` when absent or empty.
    pub display_name: Option<String>,
    /// The raw `metadata` part, at most [`MAX_METADATA_BYTES`]; the caller decodes it.
    pub metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    File,
    Metadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Discarding bytes before the first delimiter.
    Preamble,
    /// After a delimiter: `--` closes the form, CRLF opens a part.
    Delimiter,
    Headers,
    Body(Part),
    Epilogue,
}

pub struct Parser {
    /// `CRLF -- boundary`.
    delimiter: Vec<u8>,
    /// Unprocessed input: a partial header block or a possible delimiter prefix.
    carry: Vec<u8>,
    state: State,
    /// Preamble or epilogue bytes discarded so far.
    skipped: usize,
    file: Option<(String, Option<String>)>,
    metadata: Option<Vec<u8>>,
}

impl Parser {
    /// A parser for the request's `Content-Type` header value.
    pub fn new(content_type: &str) -> Result<Self, Error> {
        let (essence, params) = split_params(content_type).ok_or(Error::ContentType)?;
        let boundary = match params.as_slice() {
            [(name, value)] if name == "boundary" => value,
            _ => return Err(Error::ContentType),
        };
        // RFC 2046: 1 to 70 bchars, not ending in a space.
        let bchar = |b: u8| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b);
        if !essence.eq_ignore_ascii_case("multipart/form-data")
            || !(1..=70).contains(&boundary.len())
            || !boundary.bytes().all(bchar)
            || boundary.ends_with(' ')
        {
            return Err(Error::ContentType);
        }
        Ok(Self {
            delimiter: [b"\r\n--", boundary.as_bytes()].concat(),
            // A virtual CRLF lets a delimiter at the very start match like any other.
            carry: b"\r\n".to_vec(),
            state: State::Preamble,
            skipped: 0,
            file: None,
            metadata: None,
        })
    }

    /// Consumes `chunk` and returns the file bytes it completes, possibly none.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Error> {
        let mut input = std::mem::take(&mut self.carry);
        input.extend_from_slice(chunk);
        let mut file = Vec::new();
        let mut pos = 0;
        let keep = self.delimiter.len() - 1;
        loop {
            let rest = &input[pos..];
            match self.state {
                State::Preamble | State::Body(_) => {
                    let (taken, found) = match find(rest, &self.delimiter) {
                        Some(i) => (i, true),
                        // Hold back what could still begin a delimiter.
                        None => (rest.len().saturating_sub(keep), false),
                    };
                    match self.state {
                        State::Body(Part::File) => file.extend_from_slice(&rest[..taken]),
                        State::Body(Part::Metadata) => self.metadata_bytes(&rest[..taken])?,
                        _ => self.skip(taken)?,
                    }
                    if !found {
                        pos += taken;
                        break;
                    }
                    pos += taken + self.delimiter.len();
                    self.state = State::Delimiter;
                }
                State::Delimiter => {
                    if rest.len() < 2 {
                        break;
                    }
                    self.state = match &rest[..2] {
                        b"--" => State::Epilogue,
                        b"\r\n" => State::Headers,
                        _ => return Err(Error::Malformed),
                    };
                    self.skipped = 0;
                    pos += 2;
                }
                State::Headers => {
                    let end = if rest.starts_with(b"\r\n") {
                        Some((0, 2))
                    } else {
                        find(rest, b"\r\n\r\n").map(|i| (i, i + 4))
                    };
                    let Some((len, consumed)) = end else {
                        if rest.len() > MAX_HEADER_BYTES + 3 {
                            return Err(Error::HeadersTooLarge);
                        }
                        break;
                    };
                    if len > MAX_HEADER_BYTES {
                        return Err(Error::HeadersTooLarge);
                    }
                    self.state = State::Body(self.headers(&rest[..len])?);
                    pos += consumed;
                }
                State::Epilogue => {
                    self.skip(rest.len())?;
                    pos = input.len();
                    break;
                }
            }
        }
        input.drain(..pos);
        self.carry = input;
        Ok(file)
    }

    /// Ends the stream: the closing delimiter must have arrived and both parts been seen.
    pub fn finish(self) -> Result<Form, Error> {
        if self.state != State::Epilogue {
            return Err(Error::Truncated);
        }
        match (self.file, self.metadata) {
            (Some((media_type, display_name)), Some(metadata)) => Ok(Form {
                media_type,
                display_name,
                metadata,
            }),
            _ => Err(Error::MissingPart),
        }
    }

    fn skip(&mut self, count: usize) -> Result<(), Error> {
        self.skipped += count;
        if self.skipped > MAX_SKIPPED_BYTES {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn metadata_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let metadata = self.metadata.get_or_insert_with(Vec::new);
        if metadata.len() + bytes.len() > MAX_METADATA_BYTES {
            return Err(Error::MetadataTooLarge);
        }
        metadata.extend_from_slice(bytes);
        Ok(())
    }

    /// Parses one part's header block and records which part it opens.
    fn headers(&mut self, block: &[u8]) -> Result<Part, Error> {
        let block = std::str::from_utf8(block).map_err(|_| Error::Malformed)?;
        let (mut disposition, mut content_type) = (None, None);
        for line in block.split("\r\n") {
            let (name, value) = line.split_once(':').ok_or(Error::Malformed)?;
            // No obs-fold, empty name or control character other than HT in a value.
            if !name.bytes().all(tchar) || name.is_empty() || value.bytes().any(control) {
                return Err(Error::Malformed);
            }
            let slot = if name.eq_ignore_ascii_case("content-disposition") {
                &mut disposition
            } else if name.eq_ignore_ascii_case("content-type") {
                &mut content_type
            } else {
                return Err(Error::Malformed);
            };
            if slot.replace(value.trim_matches(ows)).is_some() {
                return Err(Error::Malformed);
            }
        }
        let (_, params) = split_params(disposition.ok_or(Error::Malformed)?)
            .filter(|(kind, _)| kind.eq_ignore_ascii_case("form-data"))
            .ok_or(Error::Malformed)?;
        let (mut name, mut filename) = (None, None);
        for (key, value) in params {
            match key.as_str() {
                "name" => name = Some(value),
                "filename" => filename = Some(value),
                _ => return Err(Error::Malformed),
            }
        }
        let part = match name.ok_or(Error::Malformed)?.as_str() {
            "file" => Part::File,
            "metadata" => Part::Metadata,
            _ => return Err(Error::UnknownPart),
        };
        let content_type = content_type.ok_or(Error::MediaType)?;
        match part {
            Part::File if self.file.is_some() => return Err(Error::DuplicatePart),
            Part::Metadata if self.metadata.is_some() => return Err(Error::DuplicatePart),
            Part::File => {
                self.file = Some((media_type(content_type)?, display_name(filename)?));
            }
            Part::Metadata => {
                json(content_type)?;
                self.metadata = Some(Vec::new());
            }
        }
        Ok(part)
    }
}

/// The file part's media type: `type/subtype` tokens other than a nested `multipart/*`, with
/// syntactically valid parameters. The essence and parameter names are lower-cased.
fn media_type(value: &str) -> Result<String, Error> {
    let (essence, params) = split_params(value).ok_or(Error::MediaType)?;
    let essence = essence.to_ascii_lowercase();
    let (kind, subtype) = essence.split_once('/').ok_or(Error::MediaType)?;
    if !token(kind) || !token(subtype) || kind == "multipart" {
        return Err(Error::MediaType);
    }
    let mut out = essence.clone();
    for (name, value) in params {
        out.push(';');
        out.push_str(&name);
        out.push('=');
        if token(&value) {
            out.push_str(&value);
        } else {
            out.push('"');
            for c in value.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
    }
    if out.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(Error::MediaType);
    }
    Ok(out)
}

/// The metadata part must be `application/json`, optionally declaring UTF-8.
fn json(value: &str) -> Result<(), Error> {
    let (essence, params) = split_params(value).ok_or(Error::MediaType)?;
    let utf8 = params
        .iter()
        .all(|(name, value)| name == "charset" && value.eq_ignore_ascii_case("utf-8"));
    if !essence.eq_ignore_ascii_case("application/json") || !utf8 {
        return Err(Error::MediaType);
    }
    Ok(())
}

/// RFC 7578 §4.2: a file name's directory part is ignored. Absent or empty means no name;
/// anything else must be a valid display name. It is never used as a path.
fn display_name(filename: Option<String>) -> Result<Option<String>, Error> {
    let Some(filename) = filename else {
        return Ok(None);
    };
    let base = filename.rsplit(['/', '\\']).next().unwrap_or_default();
    if base.is_empty() {
        return Ok(None);
    }
    if !valid_display_name(base) {
        return Err(Error::DisplayName);
    }
    Ok(Some(base.to_owned()))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(tchar)
}

fn control(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

fn ows(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Splits `head *( OWS ";" OWS name "=" ( token / quoted-string ) )`. Parameter names are
/// lower-cased; a repeated name, an empty parameter or a bad quoted string refuses the value.
fn split_params(value: &str) -> Option<(&str, Vec<(String, String)>)> {
    let bytes = value.as_bytes();
    let mut i = bytes.iter().position(|&b| b == b';').unwrap_or(bytes.len());
    let head = value[..i].trim_matches(ows);
    if head.is_empty() || head.contains('"') {
        return None;
    }
    let mut params: Vec<(String, String)> = Vec::new();
    let skip_ows = |i: &mut usize| {
        while bytes.get(*i).is_some_and(|&b| b == b' ' || b == b'\t') {
            *i += 1;
        }
    };
    while i < bytes.len() {
        i += 1; // the ';'
        skip_ows(&mut i);
        let start = i;
        while bytes.get(i).copied().is_some_and(tchar) {
            i += 1;
        }
        let name = value[start..i].to_ascii_lowercase();
        if name.is_empty() || bytes.get(i) != Some(&b'=') {
            return None;
        }
        i += 1;
        let parsed = if bytes.get(i) == Some(&b'"') {
            i += 1;
            let mut out = Vec::new();
            loop {
                match *bytes.get(i)? {
                    b'"' => break,
                    b'\\' => {
                        i += 1;
                        out.push(*bytes.get(i).filter(|&&b| !control(b))?);
                    }
                    b if control(b) => return None,
                    b => out.push(b),
                }
                i += 1;
            }
            i += 1;
            // Only ASCII bytes were dropped, so the rest is still UTF-8.
            String::from_utf8(out).ok()?
        } else {
            let start = i;
            while bytes.get(i).copied().is_some_and(tchar) {
                i += 1;
            }
            let token = &value[start..i];
            if token.is_empty() {
                return None;
            }
            token.to_owned()
        };
        if params.iter().any(|(existing, _)| *existing == name) {
            return None;
        }
        params.push((name, parsed));
        skip_ows(&mut i);
        if i < bytes.len() && bytes[i] != b';' {
            return None;
        }
    }
    Some((head, params))
}

#[cfg(test)]
mod tests;
