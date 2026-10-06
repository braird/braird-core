//! Source links (SUR-1112, for SUR-1111): normalise a shared URL, classify it into a
//! [`SourceKind`], and choose a source's cover from the unfurl's two image candidates.
//!
//! In core, not per app, so Android and iOS dedup and classify a link identically. The frozen
//! vectors in `vendored/source-url/vectors.json` pin the behaviour for Rust, Kotlin and Swift.
//! The host lists below are the classification policy: a link that matches none is an Article.

use url::Url;

use crate::library::SourceKind;

/// Query keys that only track a click. `utm_*` is a prefix; the rest are exact (case-insensitive).
const TRACKING_PARAMS: &[&str] = &["fbclid", "gclid", "mc_cid", "mc_eid", "ref"];
/// Hosts where a global tracking key is content, and is kept: GitHub's `ref` names a branch.
const HOST_KEPT_PARAMS: &[(&str, &[&str])] = &[("github.com", &["ref"])];
/// Share and sender tokens, per host — stripped there only, because the same key means content
/// elsewhere (YouTube's `t` is a timestamp). The link is synced, so these must not carry a third
/// party's identity into the user's store.
const HOST_TRACKING_PARAMS: &[(&str, &[&str])] = &[
    ("youtube.com", &["si"]),
    ("youtu.be", &["si"]),
    ("spotify.com", &["si"]),
    ("x.com", &["t", "s"]),
    ("twitter.com", &["t", "s"]),
    ("instagram.com", &["igsh", "igshid"]),
    ("linkedin.com", &["trk", "rcm"]),
    ("tiktok.com", &["_r", "_t"]),
];

/// `host` is `domain` or one of its subdomains.
fn on_domain(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

const VIDEO_HOSTS: &[&str] = &["youtube.com", "youtu.be", "vimeo.com"];
/// Podcast apps and hosting platforms whose every page is an episode or a show.
const PODCAST_HOSTS: &[&str] = &[
    "podcasts.apple.com",
    "overcast.fm",
    "pocketcasts.com",
    "pca.st",
    "castbox.fm",
    "podbean.com",
    "buzzsprout.com",
    "simplecast.com",
    "transistor.fm",
    "libsyn.com",
    "anchor.fm",
    "podcasters.spotify.com",
];
/// Preprint servers, DOI resolvers and major journal / paper hosts.
const RESEARCH_HOSTS: &[&str] = &[
    "arxiv.org",
    "doi.org",
    "biorxiv.org",
    "medrxiv.org",
    "ssrn.com",
    "ncbi.nlm.nih.gov",
    "semanticscholar.org",
    "openreview.net",
    "aclanthology.org",
    "jstor.org",
    "sciencedirect.com",
    "link.springer.com",
    "onlinelibrary.wiley.com",
    "dl.acm.org",
    "ieeexplore.ieee.org",
    "nature.com",
    "science.org",
    "pnas.org",
    "plos.org",
    "cell.com",
    "thelancet.com",
    "nejm.org",
    "bmj.com",
];
const SOCIAL_HOSTS: &[&str] = &[
    "x.com",
    "twitter.com",
    "bsky.app",
    "threads.net",
    "threads.com",
    "instagram.com",
    "linkedin.com",
];

/// The canonical form of a shared link, or `None` when it is not an http(s) URL. Two shares of
/// one page compare equal after this: `http` → `https`, host lowercased (the URL parser does
/// this), credentials, fragment and tracking parameters dropped, a trailing `/` dropped from a
/// non-root path. The path and the remaining query keep their order and their encoding.
#[uniffi::export]
pub fn normalize_source_url(raw: String) -> Option<String> {
    let mut url = Url::parse(raw.trim()).ok()?;
    match url.scheme() {
        "https" => {}
        "http" => url.set_scheme("https").ok()?,
        _ => return None,
    }
    url.host_str()?;
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    url.set_fragment(None);
    let host = url.host_str().unwrap_or("").to_string();
    let for_host = |table: &[(&str, &'static [&'static str])]| -> &'static [&'static str] {
        table
            .iter()
            .find(|(domain, _)| on_domain(&host, domain))
            .map_or(&[], |(_, keys)| keys)
    };
    let (host_params, kept) = (for_host(HOST_TRACKING_PARAMS), for_host(HOST_KEPT_PARAMS));
    let query = url.query().map(|q| {
        q.split('&')
            .filter(|pair| {
                let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
                let tracking = key.starts_with("utm_")
                    || (TRACKING_PARAMS.contains(&&*key) && !kept.contains(&&*key))
                    || host_params.contains(&&*key);
                !key.is_empty() && !tracking
            })
            .collect::<Vec<_>>()
            .join("&")
    });
    url.set_query(query.as_deref().filter(|q| !q.is_empty()));
    let path = url.path().trim_end_matches('/').to_string();
    if !path.is_empty() {
        url.set_path(&path);
    }
    Some(url.into())
}

/// The kind a shared link is filed under. Takes a [`normalize_source_url`] result (a raw URL works too);
/// an unparseable one, or any host not listed, is an `Article`.
#[uniffi::export]
pub fn classify_source_url(url: String) -> SourceKind {
    let Some(parsed) = Url::parse(&url).ok() else {
        return SourceKind::Article;
    };
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let on = |hosts: &[&str]| hosts.iter().any(|h| on_domain(&host, h));
    let spotify_episode = host == "open.spotify.com"
        && (parsed.path().starts_with("/episode/") || parsed.path().starts_with("/show/"));
    if on(VIDEO_HOSTS) {
        SourceKind::Video
    } else if spotify_episode || on(PODCAST_HOSTS) {
        SourceKind::Podcast
    } else if on(RESEARCH_HOSTS) {
        SourceKind::ResearchPaper
    } else if on(SOCIAL_HOSTS) || host.split('.').any(|label| label == "mastodon") {
        SourceKind::Social
    } else {
        SourceKind::Article
    }
}

/// The image to use as the cover of a source created from a shared link: a podcast or a video shows
/// its artwork or thumbnail (`image_url`, og:image), anything else its site icon (`icon_url`); each
/// falls back to the other. Both come from the `fetch-link-metadata` unfurl. `None` → the host's
/// kind glyph. The result is a THIRD-PARTY URL to fetch once and copy into the app's own storage —
/// never store it as `cover_url`: it would sync in plaintext (a video thumbnail URL names the
/// video, defeating the sealed link) and every device would fetch it from the page owner's CDN.
#[uniffi::export]
pub fn pick_source_cover(
    kind: SourceKind,
    image_url: Option<String>,
    icon_url: Option<String>,
) -> Option<String> {
    match kind {
        SourceKind::Podcast | SourceKind::Video => image_url.or(icon_url),
        _ => icon_url.or(image_url),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::parse_kind;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../vendored/source-url/vectors.json")).unwrap()
    }

    fn opt(v: &Value) -> Option<String> {
        v.as_str().map(str::to_string)
    }

    #[test]
    fn normalize_matches_the_frozen_vectors() {
        for case in vectors()["normalize"].as_array().unwrap() {
            let input = case["in"].as_str().unwrap();
            assert_eq!(
                normalize_source_url(input.into()),
                opt(&case["out"]),
                "{input}"
            );
        }
    }

    #[test]
    fn classify_matches_the_frozen_vectors() {
        for case in vectors()["classify"].as_array().unwrap() {
            let url = case["url"].as_str().unwrap();
            let want = parse_kind(case["kind"].as_str());
            assert_eq!(classify_source_url(url.into()), want, "{url}");
        }
    }

    #[test]
    fn pick_matches_the_frozen_vectors() {
        for case in vectors()["pick"].as_array().unwrap() {
            let kind = parse_kind(case["kind"].as_str());
            let got = pick_source_cover(kind, opt(&case["image"]), opt(&case["icon"]));
            assert_eq!(got, opt(&case["out"]), "{case}");
        }
    }

    #[test]
    fn utm_variants_of_one_article_normalize_equal() {
        let a = normalize_source_url("https://example.com/post?utm_source=x&utm_medium=y".into());
        let b = normalize_source_url("http://EXAMPLE.com/post/?utm_campaign=z#comments".into());
        assert_eq!(a, b);
        assert_eq!(a.as_deref(), Some("https://example.com/post"));
    }
}
