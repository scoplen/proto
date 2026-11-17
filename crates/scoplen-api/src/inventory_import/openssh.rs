// SPDX-License-Identifier: Apache-2.0
//! Pure, deliberately bounded D-153 preparation; never executes OpenSSH configuration.

use std::{fmt, net::IpAddr};

use scoplen_model::MAX_TEXT_BYTES;
use serde::Serialize;
use uuid::Uuid;

use super::{InventoryImportFields, InventoryImportRow, MAX_INVENTORY_IMPORT_ROWS, validate_cell};
use crate::inventory::InventoryType;

/// Complete explicitly selected source bound, including an optional leading BOM.
pub const MAX_INVENTORY_OPENSSH_BYTES: usize = 1_048_576;

/// Fixed source-free file failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryOpenSshErrorKind {
    /// Original source exceeds one MiB.
    RawTooLarge,
    /// Original source is not UTF-8.
    InvalidUtf8,
    /// Invalid physical line, keyword, quoting, argument count or selector.
    InvalidSyntax,
    /// Include or Match appears anywhere in the source.
    UnsupportedScope,
    /// No positive literal Host operand was supplied.
    NoCandidates,
    /// More than one hundred distinct literal aliases, including blocked candidates.
    TooManyCandidates,
}

/// Content-free file diagnostic; a file failure exposes no selectable candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryOpenSshError {
    /// Fixed failure class.
    pub kind: InventoryOpenSshErrorKind,
    /// Optional one-based physical source line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

impl fmt::Display for InventoryOpenSshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inventory OpenSSH {:?}", self.kind)
    }
}

impl std::error::Error for InventoryOpenSshError {}

impl InventoryOpenSshError {
    /// Serialize only the fixed diagnostic fields for the thin browser adapter.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"kind\":\"invalid_syntax\"}".into())
    }
}

/// Fixed source-free candidate failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryOpenSshDiagnosticKind {
    /// An applicable directive is outside the supported profile.
    UnsupportedOption,
    /// An applicable supported option uses an unsupported value.
    UnsupportedValue,
    /// An existing D-151/K-1 field or complete-pair constraint failed.
    InvalidField,
    /// No explicit applicable User was supplied, after all other checks.
    MissingUsername,
}

/// Known typed field; never an untrusted keyword or label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryOpenSshField {
    /// Original literal alias.
    Name,
    /// Copied or expanded `HostName`.
    Address,
    /// Canonical Direct port.
    Port,
    /// Explicit literal User.
    Username,
}

/// One content-free failure, identifying only a candidate ordinal and known field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryOpenSshDiagnostic {
    /// Fixed failure class.
    pub kind: InventoryOpenSshDiagnosticKind,
    /// Optional one-based physical source line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// One-based ordinal in the complete deduplicated candidate list.
    pub candidate: usize,
    /// Optional known field, never an unknown source keyword.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<InventoryOpenSshField>,
}

/// One ordered candidate. Debug formatting also redacts the fields of Ready candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InventoryOpenSshCandidate {
    /// Valid fields without generated identities; publication requires explicit review.
    Ready {
        /// One-based ordinal in the complete candidate list.
        candidate: usize,
        /// The same typed fields as D-151, omitting `login_name`.
        fields: InventoryImportFields,
    },
    /// A candidate that cannot be selected for publication.
    Blocked {
        /// Exactly one deterministic, source-free failure.
        diagnostic: InventoryOpenSshDiagnostic,
    },
}

/// Prepare a selected UTF-8 OpenSSH source, without I/O, identities or normalization.
/// # Errors
/// Returns one fixed file error before producing any candidate results.
pub fn parse_inventory_openssh(
    input: &[u8],
) -> Result<Vec<InventoryOpenSshCandidate>, InventoryOpenSshError> {
    use InventoryOpenSshErrorKind as Kind;
    if input.len() > MAX_INVENTORY_OPENSSH_BYTES {
        return Err(file_error(Kind::RawTooLarge, None));
    }
    let source = std::str::from_utf8(input).map_err(|_| file_error(Kind::InvalidUtf8, None))?;
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let (directives, candidates) = source_directives(source)?;
    if candidates.is_empty() {
        return Err(file_error(Kind::NoCandidates, None));
    }
    if candidates.len() > MAX_INVENTORY_IMPORT_ROWS {
        return Err(file_error(Kind::TooManyCandidates, None));
    }
    Ok(candidates
        .into_iter()
        .enumerate()
        .map(|(index, (alias, line))| prepare_candidate(alias, line, index + 1, &directives))
        .collect())
}

/// Serialize all Ready/Blocked candidates for an explicit, reviewed selection.
/// # Errors
/// Returns only fixed source-free file diagnostics, never a successful prefix.
pub fn inventory_openssh_preview(input: &[u8]) -> Result<String, InventoryOpenSshError> {
    #[derive(Serialize)]
    struct Preview {
        candidates: Vec<InventoryOpenSshCandidate>,
    }
    let candidates = parse_inventory_openssh(input)?;
    serde_json::to_string(&Preview { candidates })
        .map_err(|_| file_error(InventoryOpenSshErrorKind::InvalidSyntax, None))
}

fn file_error(kind: InventoryOpenSshErrorKind, line: Option<usize>) -> InventoryOpenSshError {
    InventoryOpenSshError { kind, line }
}

// Borrow the raw token and decode lazily. Oversized values and repeated %h expansions
// must not first allocate an oversized field just to discover the existing K-1 bound.
#[derive(Clone, Copy)]
struct Token<'a>(&'a [u8]);

impl<'a> Token<'a> {
    fn bytes(self) -> Decoded<'a> {
        Decoded { raw: self.0, index: 0, quote: None }
    }

    fn text(self) -> Option<String> {
        if self.bytes().count() > MAX_TEXT_BYTES {
            return None;
        }
        String::from_utf8(self.bytes().collect()).ok()
    }

    fn literal(self) -> bool {
        self.bytes().next() != Some(b'!') && !self.bytes().any(|b| matches!(b, b'*' | b'?'))
    }
}

#[derive(Clone)]
struct Decoded<'a> {
    raw: &'a [u8],
    index: usize,
    quote: Option<u8>,
}

impl Iterator for Decoded<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        loop {
            let byte = *self.raw.get(self.index)?;
            self.index += 1;
            if byte == b'\\'
                && self.raw.get(self.index).is_some_and(|next| {
                    matches!(next, b'\\' | b'\'' | b'"') || (*next == b' ' && self.quote.is_none())
                })
            {
                let escaped = self.raw[self.index];
                self.index += 1;
                return Some(escaped);
            }
            if self.quote == Some(byte) {
                self.quote = None;
            } else if self.quote.is_none() && matches!(byte, b'\'' | b'"') {
                self.quote = Some(byte);
            } else {
                return Some(byte);
            }
        }
    }
}

enum OptionValue<'a> {
    Host(Vec<Token<'a>>),
    Address(Token<'a>),
    Username(Token<'a>),
    Port(Token<'a>),
    Unsupported,
}

struct Directive<'a> {
    line: usize,
    value: OptionValue<'a>,
}

type Candidates<'a> = Vec<(Token<'a>, usize)>;

fn source_directives(
    source: &str,
) -> Result<(Vec<Directive<'_>>, Candidates<'_>), InventoryOpenSshError> {
    use InventoryOpenSshErrorKind as Kind;
    let mut directives = Vec::new();
    let mut candidates: Candidates<'_> = Vec::new();
    for (index, physical) in source.split_inclusive('\n').enumerate() {
        let line = index + 1;
        let text = physical
            .strip_suffix('\n')
            .map_or(physical, |text| text.strip_suffix('\r').unwrap_or(text));
        let invalid = || file_error(Kind::InvalidSyntax, Some(line));
        if text.bytes().any(|b| matches!(b, 0 | b'\r')) {
            return Err(invalid());
        }
        let text = text.trim_start_matches([' ', '\t']);
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let end = text.find([' ', '\t', '=']).unwrap_or(text.len());
        let keyword = &text[..end];
        if keyword.is_empty() || !keyword.is_ascii() || keyword.contains(['\'', '"', '\\']) {
            return Err(invalid());
        }
        let rest = text[end..].trim_start_matches([' ', '\t']);
        let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start_matches([' ', '\t']);
        let tokens = tokenize(rest.as_bytes()).ok_or_else(invalid)?;
        if tokens.is_empty() {
            return Err(invalid());
        }
        let value = if keyword.eq_ignore_ascii_case("host") {
            for token in &tokens {
                let mut bytes = token.bytes();
                if bytes.next().is_none() || token.bytes().eq(*b"!") {
                    return Err(invalid());
                }
                if token.literal()
                    && candidates.len() <= MAX_INVENTORY_IMPORT_ROWS
                    && !candidates.iter().any(|(alias, _)| alias.bytes().eq(token.bytes()))
                {
                    candidates.push((*token, line));
                }
            }
            OptionValue::Host(tokens)
        } else if keyword.eq_ignore_ascii_case("include") || keyword.eq_ignore_ascii_case("match") {
            return Err(file_error(Kind::UnsupportedScope, Some(line)));
        } else if ["hostname", "user", "port"].iter().any(|name| keyword.eq_ignore_ascii_case(name))
        {
            let [token] = tokens.as_slice() else {
                return Err(invalid());
            };
            if keyword.eq_ignore_ascii_case("hostname") {
                OptionValue::Address(*token)
            } else if keyword.eq_ignore_ascii_case("user") {
                OptionValue::Username(*token)
            } else {
                OptionValue::Port(*token)
            }
        } else {
            OptionValue::Unsupported
        };
        directives.push(Directive { line, value });
    }
    Ok((directives, candidates))
}

fn tokenize(input: &[u8]) -> Option<Vec<Token<'_>>> {
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < input.len() {
        if matches!(input[index], b' ' | b'\t') {
            index += 1;
            continue;
        }
        if input[index] == b'#' {
            break;
        }
        let start = index;
        let mut quote = None;
        while index < input.len() {
            let byte = input[index];
            if quote.is_none() && matches!(byte, b' ' | b'\t') {
                break;
            }
            if byte == b'\\'
                && input.get(index + 1).is_some_and(|next| {
                    matches!(next, b'\\' | b'\'' | b'"') || (*next == b' ' && quote.is_none())
                })
            {
                index += 2;
                continue;
            }
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() && matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            }
            index += 1;
        }
        if quote.is_some() {
            return None;
        }
        tokens.push(Token(&input[start..index]));
    }
    Some(tokens)
}

fn matches_alias(selector: Token<'_>, alias: Token<'_>) -> bool {
    let mut pattern = selector.bytes();
    if pattern.clone().next() == Some(b'!') {
        pattern.next();
    }
    let mut input = alias.bytes();
    let mut star = None;
    loop {
        match (pattern.clone().next(), input.clone().next()) {
            (Some(b'*'), _) => {
                pattern.next();
                star = Some((pattern.clone(), input.clone()));
            }
            (Some(expected), Some(actual)) if expected == b'?' || expected == actual => {
                pattern.next();
                input.next();
            }
            (None, None) => return true,
            _ => {
                let Some((restart, consumed)) = &mut star else {
                    return false;
                };
                if consumed.next().is_none() {
                    return false;
                }
                pattern = restart.clone();
                input = consumed.clone();
            }
        }
    }
}

fn applies(selectors: &[Token<'_>], alias: Token<'_>) -> bool {
    let mut positive = false;
    for selector in selectors {
        if matches_alias(*selector, alias) {
            if selector.bytes().next() == Some(b'!') {
                return false;
            }
            positive = true;
        }
    }
    positive
}

type Failure = (InventoryOpenSshDiagnosticKind, usize, Option<InventoryOpenSshField>);

fn remember(failure: &mut Option<Failure>, next: Failure) {
    let key = |(kind, line, field): Failure| {
        let profile = matches!(
            kind,
            InventoryOpenSshDiagnosticKind::UnsupportedOption
                | InventoryOpenSshDiagnosticKind::UnsupportedValue
        );
        (line, !profile, field.map_or(4, |field| field as u8))
    };
    if failure.is_none_or(|current| key(next) < key(current)) {
        *failure = Some(next);
    }
}

fn validated_text(token: Token<'_>, field: InventoryOpenSshField) -> Option<String> {
    let text = token.text()?;
    valid_text(&text, field).then_some(text)
}

fn valid_text(text: &str, field: InventoryOpenSshField) -> bool {
    let (name, kind) = match field {
        InventoryOpenSshField::Name => ("name", InventoryType::Host),
        InventoryOpenSshField::Address => ("address", InventoryType::Host),
        InventoryOpenSshField::Username => ("username", InventoryType::AccessProfile),
        InventoryOpenSshField::Port => return false,
    };
    validate_cell(name, text, kind, name).is_ok()
}

fn hostname(token: Token<'_>, alias: Token<'_>) -> Result<String, InventoryOpenSshDiagnosticKind> {
    use InventoryOpenSshDiagnosticKind::{InvalidField, UnsupportedValue};
    let mut bytes = token.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'$' || (byte == b'%' && !matches!(bytes.next(), Some(b'h' | b'%'))) {
            return Err(UnsupportedValue);
        }
    }
    validated_text(token, InventoryOpenSshField::Address).ok_or(InvalidField)?;
    let mut result = Vec::new();
    let mut bytes = token.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' && bytes.next() == Some(b'h') {
            for byte in alias.bytes() {
                if result.len() == MAX_TEXT_BYTES {
                    return Err(InvalidField);
                }
                result.push(byte);
            }
            continue;
        }
        if result.len() == MAX_TEXT_BYTES {
            return Err(InvalidField);
        }
        result.push(byte);
    }
    let mut result = String::from_utf8(result).map_err(|_| InvalidField)?;
    map_hostname(&mut result);
    if !valid_text(&result, InventoryOpenSshField::Address) {
        return Err(InvalidField);
    }
    Ok(result)
}

fn map_hostname(value: &mut str) {
    if value.parse::<IpAddr>().is_err() {
        value.make_ascii_lowercase();
    }
}

fn port(token: Token<'_>) -> Option<u16> {
    let mut bytes = token.bytes();
    let first = bytes.next()?;
    if !matches!(first, b'1'..=b'9') {
        return None;
    }
    let mut value = u16::from(first - b'0');
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u16::from(byte - b'0'))?;
    }
    Some(value)
}

fn prepare_candidate(
    alias: Token<'_>,
    alias_line: usize,
    candidate: usize,
    directives: &[Directive<'_>],
) -> InventoryOpenSshCandidate {
    use InventoryOpenSshDiagnosticKind as Kind;
    use InventoryOpenSshField as Field;
    let mut failure = None;
    let name = validated_text(alias, Field::Name);
    if name.is_none() {
        remember(&mut failure, (Kind::InvalidField, alias_line, Some(Field::Name)));
    }
    let mut address = None;
    let mut username = None;
    let mut selected_port = None;
    let mut address_seen = false;
    let mut username_seen = false;
    let mut port_seen = false;
    let mut active = true;
    for directive in directives {
        let line = directive.line;
        match &directive.value {
            OptionValue::Host(selectors) => active = applies(selectors, alias),
            _ if !active => {}
            OptionValue::Unsupported => {
                remember(&mut failure, (Kind::UnsupportedOption, line, None));
            }
            OptionValue::Address(token) => {
                match hostname(*token, alias) {
                    Ok(value) if !address_seen => address = Some(value),
                    Ok(_) => {}
                    Err(kind) => remember(&mut failure, (kind, line, Some(Field::Address))),
                }
                address_seen = true;
            }
            OptionValue::Username(token) => {
                if token.bytes().any(|b| matches!(b, b'%' | b'$')) {
                    remember(&mut failure, (Kind::UnsupportedValue, line, Some(Field::Username)));
                } else if let Some(value) = validated_text(*token, Field::Username) {
                    if !username_seen {
                        username = Some(value);
                    }
                } else {
                    remember(&mut failure, (Kind::InvalidField, line, Some(Field::Username)));
                }
                username_seen = true;
            }
            OptionValue::Port(token) => {
                if let Some(value) = port(*token) {
                    if !port_seen {
                        selected_port = Some(value);
                    }
                } else {
                    remember(&mut failure, (Kind::UnsupportedValue, line, Some(Field::Port)));
                }
                port_seen = true;
            }
        }
    }
    if !address_seen {
        address = validated_text(alias, Field::Address);
        if let Some(value) = &mut address {
            map_hostname(value);
        } else {
            remember(&mut failure, (Kind::InvalidField, alias_line, Some(Field::Address)));
        }
    }
    let fields = match (name, address, username) {
        (Some(name), Some(address), Some(username)) => {
            let fields = InventoryImportFields {
                name,
                address,
                port: selected_port.unwrap_or(22),
                username,
                login_name: None,
            };
            let row = InventoryImportRow {
                host_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0000),
                access_profile_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0001),
                fields,
            };
            if row.inventory_creates().is_err() {
                remember(&mut failure, (Kind::InvalidField, alias_line, None));
            }
            Some(row.fields)
        }
        _ => None,
    };
    if let Some((kind, line, field)) = failure {
        InventoryOpenSshCandidate::Blocked {
            diagnostic: InventoryOpenSshDiagnostic { kind, line: Some(line), candidate, field },
        }
    } else if let Some(fields) = fields {
        InventoryOpenSshCandidate::Ready { candidate, fields }
    } else {
        InventoryOpenSshCandidate::Blocked {
            diagnostic: InventoryOpenSshDiagnostic {
                kind: Kind::MissingUsername,
                line: Some(alias_line),
                candidate,
                field: Some(Field::Username),
            },
        }
    }
}
