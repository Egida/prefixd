/// Checked SQLx read boundary; public only for the separate CLI binary crate.
#[doc(hidden)]
#[derive(Debug)]
pub struct CheckedTimestamp(Option<chrono::DateTime<chrono::Utc>>);

fn timestamp_decode_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "PostgreSQL timestamp is outside the supported finite range",
    )
}

fn timestamp_from_micros(
    micros: i64,
) -> std::result::Result<chrono::DateTime<chrono::Utc>, std::io::Error> {
    if matches!(micros, i64::MIN | i64::MAX) {
        return Err(timestamp_decode_error());
    }
    chrono::DateTime::from_timestamp(946_684_800, 0)
        .and_then(|epoch| epoch.checked_add_signed(chrono::Duration::microseconds(micros)))
        .ok_or_else(timestamp_decode_error)
}

impl sqlx::Type<sqlx::Postgres> for CheckedTimestamp {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <chrono::DateTime<chrono::Utc> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <chrono::DateTime<chrono::Utc> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for CheckedTimestamp {
    fn decode(
        value: sqlx::postgres::PgValueRef<'r>,
    ) -> std::result::Result<Self, sqlx::error::BoxDynError> {
        use sqlx::ValueRef;
        if value.is_null() {
            return Ok(Self(None));
        }
        let timestamp = match value.format() {
            sqlx::postgres::PgValueFormat::Binary => {
                let micros = <i64 as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
                timestamp_from_micros(micros)?
            }
            sqlx::postgres::PgValueFormat::Text => {
                <chrono::DateTime<chrono::Utc> as sqlx::Decode<sqlx::Postgres>>::decode(value)?
            }
        };
        Ok(Self(Some(timestamp)))
    }
}

impl TryFrom<CheckedTimestamp> for chrono::DateTime<chrono::Utc> {
    type Error = std::io::Error;
    fn try_from(value: CheckedTimestamp) -> std::result::Result<Self, Self::Error> {
        value.0.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected NULL PostgreSQL timestamp",
            )
        })
    }
}

impl From<CheckedTimestamp> for Option<chrono::DateTime<chrono::Utc>> {
    fn from(value: CheckedTimestamp) -> Self {
        value.0
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::*;
    use chrono::Timelike;
    #[test]
    fn checked_timestamp_preserves_micros_and_rejects_overflow() {
        let epoch = chrono::DateTime::from_timestamp(946_684_800, 0).unwrap();
        for micros in [-1_000_001, -1, 0, 1, 1_000_001] {
            assert_eq!(
                timestamp_from_micros(micros).unwrap(),
                epoch + chrono::Duration::microseconds(micros)
            );
        }
        for timestamp in [
            chrono::DateTime::<chrono::Utc>::MIN_UTC,
            chrono::DateTime::<chrono::Utc>::MAX_UTC
                .with_nanosecond(999_999_000)
                .unwrap(),
        ] {
            let micros = timestamp
                .signed_duration_since(epoch)
                .num_microseconds()
                .unwrap();
            assert_eq!(timestamp_from_micros(micros).unwrap(), timestamp);
        }
        for micros in [i64::MIN, i64::MAX, i64::MIN + 1, i64::MAX - 1] {
            assert!(timestamp_from_micros(micros).is_err());
        }
        assert!(chrono::DateTime::<chrono::Utc>::try_from(CheckedTimestamp(None)).is_err());
        assert_eq!(
            Option::<chrono::DateTime<chrono::Utc>>::from(CheckedTimestamp(None)),
            None
        );
    }
}
