//! Synthetic forms fed at every chunk boundary; no I/O.
use super::*;

const BOUNDARY: &str = "synthetic-Boundary_0'()+,./:=?";
const CONTENT_TYPE: &str = "multipart/form-data; boundary=\"synthetic-Boundary_0'()+,./:=?\"";

fn file_part(headers: &str, body: &[u8]) -> Vec<u8> {
    [
        format!("--{BOUNDARY}\r\n{headers}\r\n\r\n").as_bytes(),
        body,
        b"\r\n",
    ]
    .concat()
}

fn file(body: &[u8]) -> Vec<u8> {
    file_part(
        "Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\n\
         Content-Type: Text/Plain; charset=utf-8",
        body,
    )
}

fn metadata(json: &str) -> Vec<u8> {
    file_part(
        "content-disposition: form-data; name=metadata\r\ncontent-type: application/json",
        json.as_bytes(),
    )
}

fn close() -> Vec<u8> {
    format!("--{BOUNDARY}--\r\n").into_bytes()
}

/// Feeds `body` in chunks of `size` bytes and returns the file bytes and the form.
fn parse_in(body: &[u8], size: usize) -> Result<(Vec<u8>, Form), Error> {
    let mut parser = Parser::new(CONTENT_TYPE)?;
    let mut out = Vec::new();
    for chunk in body.chunks(size) {
        out.extend(parser.feed(chunk)?);
    }
    Ok((out, parser.finish()?))
}

/// Every chunk size must agree with the single-chunk result.
fn parse(body: &[u8]) -> Result<(Vec<u8>, Form), Error> {
    let whole = parse_in(body, body.len().max(1));
    for size in [1, 2, 3, 5, 7, 13, 64, 4096] {
        assert_eq!(parse_in(body, size), whole, "chunk size {size}");
    }
    whole
}

#[test]
fn accepts_file_and_metadata_in_either_order_at_any_chunk_boundary() {
    // Content that contains near-delimiters, CRLFs and dashes must pass through unchanged.
    let content = format!("line\r\n--{}\r\n-- \r\nx--{BOUNDARY}\r", &BOUNDARY[..10]);
    let expected = Form {
        media_type: "text/plain;charset=utf-8".into(),
        display_name: Some("notes.txt".into()),
        metadata: br#"{"note":"synthetic"}"#.to_vec(),
    };
    for body in [
        [
            file(content.as_bytes()),
            metadata(r#"{"note":"synthetic"}"#),
            close(),
        ]
        .concat(),
        [
            metadata(r#"{"note":"synthetic"}"#),
            file(content.as_bytes()),
            close(),
        ]
        .concat(),
        // A preamble, and an epilogue after the closing delimiter, are ignored within bounds.
        [
            b"synthetic preamble\r\n".to_vec(),
            metadata(r#"{"note":"synthetic"}"#),
            file(content.as_bytes()),
            close(),
            b"epilogue".to_vec(),
        ]
        .concat(),
    ] {
        let (bytes, form) = parse(&body).unwrap();
        assert_eq!(bytes, content.as_bytes());
        assert_eq!(form, expected);
    }
    // Empty file and empty metadata parts are well-formed; policy belongs to the caller.
    let (bytes, form) = parse(&[metadata(""), file(b""), close()].concat()).unwrap();
    assert!(bytes.is_empty() && form.metadata.is_empty());
}

#[test]
fn file_names_are_display_metadata_only() {
    let named = |disposition: &str| {
        let body = [
            file_part(
                &format!("Content-Disposition: {disposition}\r\nContent-Type: application/pdf"),
                b"%PDF",
            ),
            metadata("{}"),
            close(),
        ]
        .concat();
        parse(&body).map(|(_, form)| form.display_name)
    };
    for (disposition, expected) in [
        (r#"form-data; name="file""#, None),
        (r#"form-data; name="file"; filename="""#, None),
        (r#"form-data; name="file"; filename="dir/""#, None),
        (
            r#"form-data; name="file"; filename="../../etc/passwd""#,
            Some("passwd"),
        ),
        (
            r#"form-data; name="file"; filename="C:\\Users\\x\\Report.pdf""#,
            Some("Report.pdf"),
        ),
        (
            r#"form-data; name="file"; filename="R\"quoted\" été.pdf""#,
            Some("R\"quoted\" été.pdf"),
        ),
        (
            "form-data; filename=plain.pdf; name=file",
            Some("plain.pdf"),
        ),
    ] {
        assert_eq!(
            named(disposition),
            Ok(expected.map(str::to_owned)),
            "{disposition}"
        );
    }
    let long = format!(r#"form-data; name="file"; filename="{}""#, "é".repeat(256));
    for disposition in [
        r#"form-data; name="file"; filename=" leading.pdf""#,
        r#"form-data; name="file"; filename="trailing.pdf ""#,
        "form-data; name=\"file\"; filename=\"tab\u{85}.pdf\"",
        long.as_str(),
    ] {
        assert_eq!(named(disposition), Err(Error::DisplayName), "{disposition}");
    }
    let ok = format!(r#"form-data; name="file"; filename="{}""#, "é".repeat(255));
    assert!(named(&ok).is_ok());
}

#[test]
fn refuses_missing_duplicate_and_unknown_parts() {
    for (body, error) in [
        ([file(b"x"), close()].concat(), Error::MissingPart),
        ([metadata("{}"), close()].concat(), Error::MissingPart),
        (close(), Error::MissingPart),
        (
            [file(b"x"), metadata("{}"), file(b"y"), close()].concat(),
            Error::DuplicatePart,
        ),
        (
            [metadata("{}"), file(b"x"), metadata("{}"), close()].concat(),
            Error::DuplicatePart,
        ),
        (
            [
                file_part(
                    "Content-Disposition: form-data; name=\"other\"\r\nContent-Type: text/plain",
                    b"x",
                ),
                file(b"x"),
                metadata("{}"),
                close(),
            ]
            .concat(),
            Error::UnknownPart,
        ),
    ] {
        assert_eq!(parse(&body).err(), Some(error));
    }
}

#[test]
fn refuses_missing_and_unsupported_media_types() {
    let with =
        |headers: &str| parse(&[file_part(headers, b"x"), metadata("{}"), close()].concat()).err();
    let disposition = "Content-Disposition: form-data; name=\"file\"";
    for content_type in [
        None,
        Some("text"),
        Some("text/"),
        Some("/plain"),
        Some("multipart/mixed; boundary=x"),
        Some("text/plain; charset"),
        Some("text/plain; charset=\"unterminated"),
        Some("text/pl ain"),
    ] {
        let headers = match content_type {
            Some(value) => format!("{disposition}\r\nContent-Type: {value}"),
            None => disposition.to_owned(),
        };
        assert_eq!(with(&headers), Some(Error::MediaType), "{content_type:?}");
    }
    let long = format!(
        "{disposition}\r\nContent-Type: text/plain; p=\"{}\"",
        "a".repeat(250)
    );
    assert_eq!(with(&long), Some(Error::MediaType));
    let metadata_as = |value: &str| {
        let part = file_part(
            &format!("Content-Disposition: form-data; name=\"metadata\"\r\nContent-Type: {value}"),
            b"{}",
        );
        parse(&[file(b"x"), part, close()].concat()).err()
    };
    for value in [
        "text/plain",
        "application/json; charset=latin1",
        "application/jsonx",
    ] {
        assert_eq!(metadata_as(value), Some(Error::MediaType), "{value}");
    }
    assert_eq!(metadata_as("Application/JSON; Charset=UTF-8"), None);
    let missing = file_part("Content-Disposition: form-data; name=\"metadata\"", b"{}");
    assert_eq!(
        parse(&[file(b"x"), missing, close()].concat()).err(),
        Some(Error::MediaType)
    );
}

#[test]
fn refuses_malformed_headers_and_framing() {
    let headers =
        |headers: &str| parse(&[file_part(headers, b"x"), metadata("{}"), close()].concat()).err();
    for bad in [
        "",
        "Content-Disposition form-data; name=\"file\"",
        "Content-Disposition: attachment; name=\"file\"\r\nContent-Type: text/plain",
        "Content-Disposition: form-data\r\nContent-Type: text/plain",
        "Content-Disposition: form-data; name=\"file\"; filename*=UTF-8''x\r\nContent-Type: text/plain",
        "Content-Disposition: form-data; name=\"file\"; name=\"file\"\r\nContent-Type: text/plain",
        "Content-Disposition: form-data; name=\"file\"\r\nContent-Type: text/plain\r\nContent-Type: text/plain",
        "Content-Disposition: form-data; name=\"file\"\r\nContent-Type: text/plain\r\nX-Extra: 1",
        "Content-Disposition: form-data; name=\"file\"\r\n Content-Type: text/plain",
        "Content-Disposition: form-data; name=\"file\"\r\nContent-Transfer-Encoding: base64",
        "Content-Disposition: form-data; name=\"file\";\r\nContent-Type: text/plain",
        "Content-Disposition: form-data; name=\"fi\rle\"\r\nContent-Type: text/plain",
    ] {
        assert_eq!(headers(bad), Some(Error::Malformed), "{bad:?}");
    }
    // Non-UTF-8 header bytes.
    let mut part = file(b"x");
    part[BOUNDARY.len() + 6] = 0xff;
    assert_eq!(
        parse(&[part, metadata("{}"), close()].concat()).err(),
        Some(Error::Malformed)
    );
    // A delimiter followed by neither CRLF nor "--".
    let bad = format!("--{BOUNDARY}X\r\n").into_bytes();
    assert_eq!(parse(&bad).err(), Some(Error::Malformed));
    // Preamble and epilogue are bounded.
    let preamble = [vec![b'p'; MAX_SKIPPED_BYTES + 1], file(b"x")].concat();
    assert_eq!(parse(&preamble).err(), Some(Error::Malformed));
    let epilogue = [
        file(b"x"),
        metadata("{}"),
        close(),
        vec![b'e'; MAX_SKIPPED_BYTES + 1],
    ]
    .concat();
    assert_eq!(parse(&epilogue).err(), Some(Error::Malformed));
}

#[test]
fn refuses_truncated_streams() {
    let complete = [file(b"payload"), metadata("{}"), close()].concat();
    // Every strict prefix, including one missing only the final "--", is truncated or
    // incomplete; none is accepted.
    let closing = complete.len() - "--\r\n".len();
    for end in 0..closing {
        let result = parse_in(&complete[..end], 1);
        assert!(
            matches!(
                result,
                Err(Error::Truncated | Error::MissingPart | Error::Malformed)
            ),
            "prefix {end}: {result:?}"
        );
    }
    assert_eq!(
        parse_in(&complete[..closing], 1).err(),
        Some(Error::Truncated)
    );
    assert!(parse(&complete).is_ok());
    // An empty body.
    assert_eq!(parse_in(b"", 1).err(), Some(Error::Truncated));
}

#[test]
fn bounds_headers_and_metadata() {
    let padding = format!("X: {}", "a".repeat(MAX_HEADER_BYTES));
    let big = format!("Content-Disposition: form-data; name=\"file\"\r\n{padding}");
    assert_eq!(
        parse(&[file_part(&big, b"x"), metadata("{}"), close()].concat()).err(),
        Some(Error::HeadersTooLarge)
    );
    // An unterminated header block is refused once it exceeds the bound, before the end.
    let mut parser = Parser::new(CONTENT_TYPE).unwrap();
    parser
        .feed(format!("--{BOUNDARY}\r\nContent-Type: ").as_bytes())
        .unwrap();
    let flood = vec![b'a'; MAX_HEADER_BYTES];
    assert_eq!(parser.feed(&flood).err(), Some(Error::HeadersTooLarge));

    let json = format!("\"{}\"", "m".repeat(MAX_METADATA_BYTES - 2));
    assert!(parse_in(&[file(b"x"), metadata(&json), close()].concat(), 4096).is_ok());
    let json = format!("\"{}\"", "m".repeat(MAX_METADATA_BYTES - 1));
    assert_eq!(
        parse_in(&[file(b"x"), metadata(&json), close()].concat(), 4096).err(),
        Some(Error::MetadataTooLarge)
    );
}

#[test]
fn file_bytes_stream_with_a_bounded_carry() {
    let mut parser = Parser::new(CONTENT_TYPE).unwrap();
    let head = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    assert!(parser.feed(head.as_bytes()).unwrap().is_empty());
    let mut total = 0;
    for _ in 0..256 {
        total += parser.feed(&[7u8; 4096]).unwrap().len();
        assert!(parser.carry.len() < parser.delimiter.len());
    }
    // Everything except a possible delimiter prefix has been handed out.
    assert_eq!(total, 256 * 4096 - (parser.delimiter.len() - 1));
}

#[test]
fn content_type_needs_one_valid_boundary() {
    for value in [
        "multipart/form-data; boundary=abc",
        "Multipart/Form-Data;boundary=\"a b\"",
        &format!("multipart/form-data; boundary={}", "b".repeat(70)),
    ] {
        assert!(Parser::new(value).is_ok(), "{value}");
    }
    for value in [
        "",
        "multipart/form-data",
        "multipart/mixed; boundary=abc",
        "application/json",
        "multipart/form-data; boundary=",
        "multipart/form-data; boundary=\"\"",
        "multipart/form-data; boundary=\"ends \"",
        "multipart/form-data; boundary=a; boundary=b",
        "multipart/form-data; boundary=abc; charset=utf-8",
        "multipart/form-data; boundary=\"a;b\"",
        &format!("multipart/form-data; boundary={}", "b".repeat(71)),
    ] {
        assert_eq!(
            Parser::new(value).err(),
            Some(Error::ContentType),
            "{value}"
        );
    }
}

#[test]
fn errors_are_fixed_categories() {
    for error in [
        Error::ContentType,
        Error::Malformed,
        Error::HeadersTooLarge,
        Error::UnknownPart,
        Error::DuplicatePart,
        Error::MissingPart,
        Error::MediaType,
        Error::DisplayName,
        Error::MetadataTooLarge,
        Error::Truncated,
    ] {
        let text = error.to_string();
        assert!(!text.is_empty() && !text.contains(BOUNDARY));
    }
}
