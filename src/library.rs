//! The source lifecycle, source kinds and the Library sort (SUR-1106 for SUR-1100; SUR-1112).
//!
//! `books.status` is a manual, three-state lifecycle — nothing derives or clears it. The server
//! column (surfc 0059) is `not null` with a CHECK, so the stored vocabulary is closed; the parse
//! fallback exists only for a local row that predates the column (SQL NULL, never re-pulled
//! because 0059's backfill did not bump `change_seq`), which is exactly the server's `shelved`.

/// Where a source sits in the reader's lifecycle. Stored as `to_read | reading | shelved`.
///
/// "Source" is the product word for a book: this is `books.status`, carried on [`BookRecord`] and
/// [`BookUpsert`] (named for the user-facing Sources surface, founder 2026-09-25). Unrelated to
/// `BookRecord::cover_source`, which says where a cover image came from.
///
/// [`BookRecord`]: crate::sync::read::BookRecord
/// [`BookUpsert`]: crate::sync::BookUpsert
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SourceStatus {
    ToRead,
    Reading,
    Shelved,
}

/// The stored form of a status — the inverse of [`parse_status`].
pub fn status_value(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::ToRead => "to_read",
        SourceStatus::Reading => "reading",
        SourceStatus::Shelved => "shelved",
    }
}

/// Absent or unrecognised → `Shelved`: the value 0059 gave every row that existed before it.
pub fn parse_status(raw: Option<&str>) -> SourceStatus {
    match raw {
        Some("to_read") => SourceStatus::ToRead,
        Some("reading") => SourceStatus::Reading,
        _ => SourceStatus::Shelved,
    }
}

/// What kind of source a book row is (SUR-1112, for SUR-1111). Stored as `book | podcast |
/// article | research_paper | video | social` — a closed set (surfc 0061 CHECK); a new kind needs a
/// core release. Only a `Book` has a reading status; the other five are the Library's "Other Media".
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SourceKind {
    Book,
    Podcast,
    Article,
    ResearchPaper,
    Video,
    Social,
}

/// The stored form of a kind — the inverse of [`parse_kind`].
pub fn kind_value(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::Book => "book",
        SourceKind::Podcast => "podcast",
        SourceKind::Article => "article",
        SourceKind::ResearchPaper => "research_paper",
        SourceKind::Video => "video",
        SourceKind::Social => "social",
    }
}

/// Absent or unrecognised → `Book`: the value 0061 gave every row that existed before it. A read
/// fallback only — core never writes it back, so a kind from a newer core survives a full-row
/// restage (merge, unmerge) unchanged.
pub fn parse_kind(raw: Option<&str>) -> SourceKind {
    match raw {
        Some("podcast") => SourceKind::Podcast,
        Some("article") => SourceKind::Article,
        Some("research_paper") => SourceKind::ResearchPaper,
        Some("video") => SourceKind::Video,
        Some("social") => SourceKind::Social,
        _ => SourceKind::Book,
    }
}

/// The synced `user_settings` key for the Library's within-rail order.
pub const LIBRARY_SORT_KEY: &str = "library_sort";

/// How the Library orders sources inside each status rail. The sort itself is the host's — core
/// owns only the synced choice, so both platforms agree on which order is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LibrarySort {
    DateAdded,
    Alphabetical,
}

/// The stored form of a sort — the inverse of [`parse_sort`].
pub fn sort_value(sort: LibrarySort) -> &'static str {
    match sort {
        LibrarySort::DateAdded => "date_added",
        LibrarySort::Alphabetical => "alphabetical",
    }
}

/// Unset or a value a newer client invented → `DateAdded`, the Library's order before SUR-1100.
pub fn parse_sort(raw: Option<&str>) -> LibrarySort {
    match raw {
        Some("alphabetical") => LibrarySort::Alphabetical,
        _ => LibrarySort::DateAdded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_and_falls_back_to_shelved() {
        for s in [
            SourceStatus::ToRead,
            SourceStatus::Reading,
            SourceStatus::Shelved,
        ] {
            assert_eq!(parse_status(Some(status_value(s))), s);
        }
        assert_eq!(parse_status(None), SourceStatus::Shelved);
        assert_eq!(parse_status(Some("finished")), SourceStatus::Shelved);
    }

    #[test]
    fn kind_round_trips_and_falls_back_to_book() {
        for k in [
            SourceKind::Book,
            SourceKind::Podcast,
            SourceKind::Article,
            SourceKind::ResearchPaper,
            SourceKind::Video,
            SourceKind::Social,
        ] {
            assert_eq!(parse_kind(Some(kind_value(k))), k);
        }
        assert_eq!(parse_kind(None), SourceKind::Book);
        assert_eq!(parse_kind(Some("zine")), SourceKind::Book);
    }
}
