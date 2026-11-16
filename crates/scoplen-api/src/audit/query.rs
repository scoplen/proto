// SPDX-License-Identifier: Apache-2.0
//! Decoded query syntax; URL decoding occurs exactly once in the HTTP adapter.

use uuid::Uuid;

use super::{AuditCodecError, AuditEvent, AuditOutcome, AuditResource, parse_decimal, parse_uuid};

/// Maximum complete decoded list query, including separators.
pub const MAX_AUDIT_QUERY_BYTES: usize = 4_096;
/// Maximum decoded filter expression.
pub const MAX_AUDIT_FILTER_BYTES: usize = 2_048;
/// Maximum complete decoded verification query.
pub const MAX_AUDIT_RANGE_QUERY_BYTES: usize = 128;
/// Maximum selected events in one verification request, excluding its predecessor.
pub const MAX_AUDIT_RANGE_EVENTS: u64 = 4_096;
/// Maximum original event bytes examined, including the immediate predecessor.
pub const MAX_AUDIT_VERIFY_EVENT_BYTES: usize = 16_777_216;

/// Typed AND-only predicates; absent historical attribution never matches an actor predicate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditFilter {
    /// Inclusive UTC creation-time lower bound in exact Unix milliseconds.
    pub occurred_at_ge: Option<i64>,
    /// Exclusive UTC creation-time upper bound in exact Unix milliseconds.
    pub occurred_at_lt: Option<i64>,
    /// Exact recorded actor Account, never a target, Device or current identity lookup.
    pub actor_account_id: Option<Uuid>,
    /// Exact known primary resource.
    pub resource: Option<AuditResource>,
    /// Exact safe producer class; unknown names are retained.
    pub event_class: Option<String>,
    /// Exact known outcome, including unknown.
    pub outcome: Option<AuditOutcome>,
}

impl AuditFilter {
    /// Parse the finite grammar without trimming, escapes or expression evaluation.
    /// # Errors
    /// Rejects unsupported, duplicate, oversized or malformed clauses.
    pub fn parse(text: &str) -> Result<Self, AuditCodecError> {
        if text.len() > MAX_AUDIT_FILTER_BYTES {
            return Err(AuditCodecError::TooLarge);
        }
        if !text.is_ascii() || text.is_empty() {
            return Err(AuditCodecError::InvalidField("filter"));
        }
        let mut value = Self::default();
        for (index, clause) in text.split(" and ").enumerate() {
            if index >= 6 {
                return Err(AuditCodecError::InvalidField("filter"));
            }
            let (field, quoted) =
                clause.split_once(" \"").ok_or(AuditCodecError::InvalidField("filter"))?;
            let literal = quoted
                .strip_suffix('"')
                .filter(|v| !v.contains(['"', '\\']))
                .ok_or(AuditCodecError::InvalidField("filter"))?;
            match field {
                "occurred_at ge" if value.occurred_at_ge.is_none() => {
                    value.occurred_at_ge = Some(parse_audit_timestamp(literal)?);
                }
                "occurred_at lt" if value.occurred_at_lt.is_none() => {
                    value.occurred_at_lt = Some(parse_audit_timestamp(literal)?);
                }
                "actor_account_id eq" if value.actor_account_id.is_none() => {
                    value.actor_account_id = Some(parse_uuid(literal, "actor_account_id")?);
                }
                "resource eq" if value.resource.is_none() => {
                    let (kind, id) =
                        literal.split_once(':').ok_or(AuditCodecError::InvalidField("resource"))?;
                    value.resource = Some(AuditResource {
                        kind: kind.parse()?,
                        id: parse_uuid(id, "resource.id")?,
                    });
                }
                "event_class eq" if value.event_class.is_none() => {
                    super::validate_class(literal)?;
                    value.event_class = Some(literal.into());
                }
                "outcome eq" if value.outcome.is_none() => value.outcome = Some(literal.parse()?),
                _ => return Err(AuditCodecError::InvalidField("filter")),
            }
        }
        value.validate()?;
        Ok(value)
    }

    /// Revalidate public predicates before storage use or response binding.
    /// # Errors
    /// Rejects invalid ids, classes, times or an empty/reversed time interval.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        for time in [self.occurred_at_ge, self.occurred_at_lt].into_iter().flatten() {
            format_audit_timestamp(time)?;
        }
        if self.occurred_at_ge.zip(self.occurred_at_lt).is_some_and(|(a, b)| a >= b) {
            return Err(AuditCodecError::InvalidField("time range"));
        }
        if let Some(id) = self.actor_account_id {
            super::valid_uuid(id, "actor_account_id")?;
        }
        if let Some(resource) = &self.resource {
            resource.validate()?;
        }
        if let Some(class) = &self.event_class {
            super::validate_class(class)?;
        }
        Ok(())
    }

    /// Compare a validated projection using only recorded fields.
    /// # Errors
    /// Rejects invalid predicates or event metadata; this performs no authorization.
    pub fn matches(&self, event: &AuditEvent) -> Result<bool, AuditCodecError> {
        self.validate()?;
        event.validate()?;
        let time = parse_audit_timestamp(&event.occurred_at)?;
        Ok(self.occurred_at_ge.is_none_or(|lower| time >= lower)
            && self.occurred_at_lt.is_none_or(|upper| time < upper)
            && self.actor_account_id.is_none_or(|id| event.actor_account_id == Some(id))
            && self.resource.as_ref().is_none_or(|r| event.resource.as_ref() == Some(r))
            && self.event_class.as_ref().is_none_or(|c| event.event_class.as_ref() == Some(c))
            && self.outcome.is_none_or(|outcome| event.outcome == outcome))
    }
}

/// Descending immutable timeline query; the cursor is a position, never authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditListQuery {
    /// Maximum returned items, 1..500.
    pub limit: u16,
    /// Select sequences strictly below this position.
    pub cursor: Option<u64>,
    /// AND-only recorded-field predicates.
    pub filter: AuditFilter,
}

impl Default for AuditListQuery {
    fn default() -> Self {
        Self { limit: 50, cursor: None, filter: AuditFilter::default() }
    }
}

impl AuditListQuery {
    /// Parse already decoded names/values, rejecting unknown or repeated names.
    /// # Errors
    /// Rejects invalid syntax or complete/filter byte overflow.
    pub fn from_parameters<'a>(
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AuditCodecError> {
        let mut result = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        let mut bytes = 0;
        for (name, text) in parameters {
            charge_query(&mut bytes, name, text, MAX_AUDIT_QUERY_BYTES)?;
            if !seen.insert(name) {
                return Err(AuditCodecError::InvalidField("query"));
            }
            match name {
                "limit" if !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()) => {
                    result.limit =
                        text.parse().map_err(|_| AuditCodecError::InvalidField("limit"))?;
                }
                "cursor" => result.cursor = Some(parse_decimal(text, false, "cursor")?),
                "sort" if text == "-sequence" => {}
                "filter" => result.filter = AuditFilter::parse(text)?,
                _ => return Err(AuditCodecError::InvalidField("query")),
            }
        }
        result.validate()?;
        Ok(result)
    }

    /// Recheck public fields before request dispatch or response validation.
    /// # Errors
    /// Rejects invalid bounds or predicates.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        if !(1..=500).contains(&self.limit) || self.cursor == Some(0) {
            return Err(AuditCodecError::InvalidField("query"));
        }
        self.filter.validate()
    }
}

/// Inclusive contiguous sequence selection; search filters never select verification rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditRange {
    /// First selected positive sequence.
    pub from_sequence: u64,
    /// Last selected sequence, inclusive.
    pub to_sequence: u64,
}

impl AuditRange {
    /// Construct and validate one bounded interval.
    /// # Errors
    /// Rejects zero, reversed or more than 4096 selected events.
    pub fn new(from_sequence: u64, to_sequence: u64) -> Result<Self, AuditCodecError> {
        let value = Self { from_sequence, to_sequence };
        value.validate()?;
        Ok(value)
    }
    /// Parse exactly two decoded parameters, once each.
    /// # Errors
    /// Rejects unsupported, missing, repeated, noncanonical or oversized values.
    pub fn from_parameters<'a>(
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AuditCodecError> {
        let (mut from, mut to, mut bytes) = (None, None, 0);
        for (name, text) in parameters {
            charge_query(&mut bytes, name, text, MAX_AUDIT_RANGE_QUERY_BYTES)?;
            match name {
                "from_sequence" if from.is_none() => {
                    from = Some(parse_decimal(text, false, "from_sequence")?);
                }
                "to_sequence" if to.is_none() => {
                    to = Some(parse_decimal(text, false, "to_sequence")?);
                }
                _ => return Err(AuditCodecError::InvalidField("range query")),
            }
        }
        Self::new(
            from.ok_or(AuditCodecError::InvalidField("from_sequence"))?,
            to.ok_or(AuditCodecError::InvalidField("to_sequence"))?,
        )
    }
    /// Validate the inclusive interval with overflow-safe arithmetic.
    /// # Errors
    /// Rejects invalid range syntax or excessive selected-event count.
    pub fn validate(self) -> Result<(), AuditCodecError> {
        if self.from_sequence == 0 || self.from_sequence > self.to_sequence {
            return Err(AuditCodecError::InvalidField("range"));
        }
        if self.to_sequence - self.from_sequence >= MAX_AUDIT_RANGE_EVENTS {
            return Err(AuditCodecError::TooLarge);
        }
        Ok(())
    }
    /// Number of selected events, excluding the predecessor.
    /// # Errors
    /// Rejects an invalid mutable range.
    pub fn event_count(self) -> Result<u64, AuditCodecError> {
        self.validate()?;
        Ok(self.to_sequence - self.from_sequence + 1)
    }
}

fn charge_query(
    bytes: &mut usize,
    name: &str,
    text: &str,
    bound: usize,
) -> Result<(), AuditCodecError> {
    *bytes = bytes
        .saturating_add(name.len())
        .saturating_add(text.len())
        .saturating_add(if *bytes == 0 { 1 } else { 2 });
    if *bytes > bound {
        return Err(AuditCodecError::TooLarge);
    }
    if !name.is_ascii() || !text.is_ascii() {
        return Err(AuditCodecError::InvalidField("query"));
    }
    Ok(())
}

/// Parse the normalized four-digit-year UTC profile without floating point or rounding.
/// Search bounds may predate Unix epoch; stored event/checkpoint times must be positive.
/// # Errors
/// Rejects invalid calendars, offsets, leap seconds, aliases or sub-millisecond precision.
pub fn parse_audit_timestamp(text: &str) -> Result<i64, AuditCodecError> {
    if !(20..=24).contains(&text.len()) || !crate::certificate::valid_utc_timestamp(text) {
        return Err(AuditCodecError::InvalidField("timestamp"));
    }
    let digits = |s: &str| s.parse::<i64>().map_err(|_| AuditCodecError::InvalidField("timestamp"));
    let year = digits(&text[..4])?;
    let month = digits(&text[5..7])?;
    let day = digits(&text[8..10])?;
    let mut days = days_before_year(year) - days_before_year(1970) + day - 1;
    for m in 1..month {
        days += month_days(year, m);
    }
    let seconds = days * 86_400
        + digits(&text[11..13])? * 3_600
        + digits(&text[14..16])? * 60
        + digits(&text[17..19])?;
    let fraction = if text.len() == 20 {
        0
    } else {
        let part = &text[20..text.len() - 1];
        if part.ends_with('0') {
            return Err(AuditCodecError::InvalidField("timestamp"));
        }
        digits(part)?
            * match part.len() {
                1 => 100,
                2 => 10,
                3 => 1,
                _ => return Err(AuditCodecError::InvalidField("timestamp")),
            }
    };
    Ok(seconds * 1_000 + fraction)
}

/// Format an exact integer Unix-millisecond instant using the normalized Audit UTC profile.
/// # Errors
/// Rejects instants outside the four-digit-year calendar.
pub fn format_audit_timestamp(milliseconds: i64) -> Result<String, AuditCodecError> {
    let mut days = milliseconds.div_euclid(86_400_000) + days_before_year(1970);
    if days < 0 || days >= days_before_year(10_000) {
        return Err(AuditCodecError::InvalidField("timestamp"));
    }
    let mut year = 0;
    while days >= days_before_year(year + 1) {
        year += 1;
    }
    days -= days_before_year(year);
    let mut month = 1;
    while days >= month_days(year, month) {
        days -= month_days(year, month);
        month += 1;
    }
    let within = milliseconds.rem_euclid(86_400_000);
    let mut fraction = format!("{:03}", within % 1_000);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    if !fraction.is_empty() {
        fraction.insert(0, '.');
    }
    Ok(format!(
        "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}{fraction}Z",
        days + 1,
        within / 3_600_000,
        within / 60_000 % 60,
        within / 1_000 % 60
    ))
}

fn days_before_year(year: i64) -> i64 {
    365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400
}
fn month_days(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
