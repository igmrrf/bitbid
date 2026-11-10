//! Public policy consumer, executed natively and under the WASM runner.
use bitbid_core::{
    registry_list::{ListQuery, list_indexed},
    registry_read::RegistryInfo,
};

const ME: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const STRANGER: &str = "0xcccccccccccccccccccccccccccccccccccccccc";

fn facts() -> RegistryInfo {
    RegistryInfo {
        sender: [0xaa; 20],
        recipient: [0xbb; 20],
        ipfs_cid: "arbitrary CID 🔑".into(),
        created_at: u64::MAX,
        expires_at: 1,
        max_reads: 0,
        read_count: u32::MAX,
        revoked: false,
        is_public: false,
        is_expired: false,
        limit_reached: false,
    }
}
fn query() -> ListQuery<'static> {
    ListQuery {
        user_address: ME,
        filter_user: None,
        all: false,
        expired_only: false,
        active_only: false,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ownership_public_and_explicit_user_table() {
    // A literal explicit filter overrides ownership, but never hidden filtering.
    // Public replaces the visible recipient, not its retained binary fact.
    let cases = [
        (false, ME, None, true),
        (false, OTHER, None, true),
        (false, STRANGER, None, false),
        (true, STRANGER, None, true),
        (false, STRANGER, Some(ME), true),
        (false, STRANGER, Some(OTHER), true),
        (false, ME, Some(STRANGER), false),
        (false, ME, Some("PuBlIc"), false),
        (true, STRANGER, Some("PuBlIc"), true),
        (true, ME, Some(OTHER), false),
        (true, STRANGER, Some(ME), true),
        (
            false,
            "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
            true,
        ),
        (
            false,
            STRANGER,
            Some("0XBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            true,
        ),
        (
            false,
            ME,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            false,
        ),
        (false, ME, Some(""), false),
    ];
    for (public, user, filter, visible) in cases {
        for all in [false, true] {
            for hidden in [false, true] {
                let info = RegistryInfo {
                    is_public: public,
                    ..facts()
                };
                let q = ListQuery {
                    user_address: user,
                    filter_user: filter,
                    all,
                    ..query()
                };
                let mut calls = Vec::new();
                let rows = list_indexed([("original-ID", hidden)], q, |id| {
                    calls.push(id.to_owned());
                    Ok::<_, ()>(Some(info.clone()))
                })
                .unwrap();
                assert_eq!(calls, ["original-ID"]);
                let selected = (!hidden || all) && (visible || (all && filter.is_none()));
                assert_eq!(
                    rows,
                    if selected {
                        vec![("original-ID".into(), info)]
                    } else {
                        vec![]
                    }
                );
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn chain_status_truth_table_ignores_local_time_and_counts() {
    let statuses = [
        (false, false, false, false),
        (true, false, false, true),
        (false, true, false, true),
        (false, false, true, true),
        (true, true, false, true),
        (true, false, true, true),
        (false, true, true, true),
        (true, true, true, true),
    ];
    for (revoked, limit_reached, is_expired, expired) in statuses {
        let info = RegistryInfo {
            revoked,
            limit_reached,
            is_expired,
            ..facts()
        };
        for (expired_only, active_only, expected) in [
            (false, false, true),
            (true, false, expired),
            (false, true, !expired),
            (true, true, false),
        ] {
            let rows = list_indexed(
                [("id", false)],
                ListQuery {
                    expired_only,
                    active_only,
                    ..query()
                },
                |_| Ok::<_, ()>(Some(info.clone())),
            )
            .unwrap();
            assert_eq!(
                rows,
                if expected {
                    vec![("id".into(), info.clone())]
                } else {
                    vec![]
                }
            );
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_ids_order_and_every_fact_survive_without_normalization() {
    let entries = [
        ("z", true),
        ("0X6964", false),
        ("id", false),
        ("🔑", false),
        ("", false),
    ];
    let mut trace = Vec::new();
    let info = RegistryInfo {
        revoked: true,
        is_public: true,
        is_expired: true,
        limit_reached: true,
        ..facts()
    };
    let rows = list_indexed(
        entries,
        ListQuery {
            all: true,
            ..query()
        },
        |id| {
            trace.push(id.to_owned());
            Ok::<_, ()>(Some(info.clone()))
        },
    )
    .unwrap();
    assert_eq!(trace, ["z", "0X6964", "id", "🔑", ""]);
    assert_eq!(rows, entries.map(|(id, _)| (id.into(), info.clone())));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn reads_precede_all_filters_none_skips_and_fatal_error_stops() {
    // The fatal error has no Display/Error bound and is returned unchanged.
    #[derive(Debug, PartialEq)]
    struct Fatal(u8);
    let entries = [
        ("hidden", true),
        ("skipped", false),
        ("fatal", true),
        ("never", false),
    ];
    let mut trace = Vec::new();
    let failure = list_indexed(
        entries,
        ListQuery {
            user_address: STRANGER,
            filter_user: Some("unmatched"),
            expired_only: true,
            active_only: true,
            ..query()
        },
        |id| {
            trace.push(id.to_owned());
            match id {
                "skipped" => Ok(None),
                "fatal" => Err(Fatal(47)),
                _ => Ok(Some(facts())),
            }
        },
    );
    assert_eq!(failure, Err(Fatal(47)));
    assert_eq!(trace, ["hidden", "skipped", "fatal"]);

    trace.clear();
    let rows = list_indexed(entries, query(), |id| {
        trace.push(id.to_owned());
        Ok::<_, Fatal>(if id == "skipped" { None } else { Some(facts()) })
    })
    .unwrap();
    assert_eq!(trace, ["hidden", "skipped", "fatal", "never"]);
    assert_eq!(rows, [("never".into(), facts())]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn empty_enumeration_has_no_reader_capability() {
    let rows = list_indexed(std::iter::empty(), query(), |_| -> Result<_, ()> {
        panic!("empty list touched reader")
    })
    .unwrap();
    assert!(rows.is_empty());
}
