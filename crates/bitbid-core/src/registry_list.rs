//! Pure selection over ordered registry facts. Native callers retain enumeration,
//! I/O, error classification, warnings, and presentation.
use crate::{address::bytes_to_hex, registry_read::RegistryInfo};

pub struct ListQuery<'a> {
    pub user_address: &'a str,
    pub filter_user: Option<&'a str>,
    pub all: bool,
    pub expired_only: bool,
    pub active_only: bool,
}

/// Read every enumerated entry before applying any filter. `None` skips a record;
/// a reader error returns immediately. Original IDs, order, and all facts survive.
/// The hidden flag belongs to enumeration, even if the reader reloads its index.
pub fn list_indexed<'a, E>(
    entries: impl IntoIterator<Item = (&'a str, bool)>,
    query: ListQuery<'_>,
    mut read: impl FnMut(&str) -> Result<Option<RegistryInfo>, E>,
) -> Result<Vec<(String, RegistryInfo)>, E> {
    let mut results = Vec::new();
    for (id, hidden) in entries {
        let Some(info) = read(id)? else {
            continue;
        };
        let sender = bytes_to_hex(&info.sender);
        let recipient = if info.is_public {
            "public".into()
        } else {
            bytes_to_hex(&info.recipient)
        };
        let is_mine = info.is_public
            || sender.eq_ignore_ascii_case(query.user_address)
            || recipient.eq_ignore_ascii_case(query.user_address);
        if hidden && !query.all {
            continue;
        }
        if let Some(target) = query.filter_user {
            if !sender.eq_ignore_ascii_case(target) && !recipient.eq_ignore_ascii_case(target) {
                continue;
            }
        } else if !query.all && !is_mine {
            continue;
        }
        let expired = info.is_expired || info.limit_reached || info.revoked;
        if query.expired_only && !expired {
            continue;
        }
        if query.active_only && expired {
            continue;
        }
        results.push((id.to_owned(), info));
    }
    Ok(results)
}
