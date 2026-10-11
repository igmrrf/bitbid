//! The bitbid web console: Wallet, Seal, Unseal, Registry, and Revoke panels.
//!
//! Everything secret stays in the page. Sealing and unsealing happen locally in
//! `bitbid-webapp-core`; the only network calls are JSON-RPC reads against the
//! endpoint the operator types into the Registry panel.

use bitbid_webapp_core::registry::{decode_get_logs_response, decode_get_secret_info_response,
    encode_get_secret_info_calldata, RegistryRecord};
use bitbid_webapp_core::seal;
use serde_json::json;
use yew::prelude::*;

use crate::ethereum;
use crate::rpc;

#[derive(Clone, PartialEq)]
enum Status {
    Idle,
    Working(&'static str),
    Ok(String),
    Err(String),
}

impl Status {
    fn line(&self) -> Html {
        match self {
            Status::Idle => html! {},
            Status::Working(msg) => html! { <p class="status" data-state="work">{ msg }</p> },
            Status::Ok(msg) => html! { <p class="status" data-state="ok">{ msg }</p> },
            Status::Err(msg) => html! { <p class="status" data-state="err">{ msg }</p> },
        }
    }
}

pub struct App {
    wallet_address: String,
    wallet_manual: String,
    wallet_status: Status,

    seal_plaintext: String,
    seal_recipient_key: String,
    seal_share: String,
    seal_status: Status,

    unseal_share: String,
    unseal_secret_key: String,
    unseal_plaintext: String,
    unseal_status: Status,

    rpc_url: String,
    registry_address: String,
    registry_filter: String,
    records: Vec<RegistryRecord>,
    registry_status: Status,

    revoke_id: String,
    revoke_record: Option<RegistryRecord>,
    revoke_status: Status,
}

pub enum Msg {
    WalletManual(String),
    WalletConnect,
    WalletConnected(Result<String, String>),

    SealPlaintext(String),
    SealRecipientKey(String),
    SealRun,

    UnsealShare(String),
    UnsealSecretKey(String),
    UnsealRun,

    RpcUrl(String),
    RegistryAddress(String),
    RegistryFilter(String),
    RegistryLoad,
    RegistryLoaded(Result<Vec<RegistryRecord>, String>),

    RevokeId(String),
    RevokeLookup,
    RevokeLoaded(Result<RegistryRecord, String>),
    RevokeExplain,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            wallet_address: String::new(),
            wallet_manual: String::new(),
            wallet_status: Status::Idle,
            seal_plaintext: String::new(),
            seal_recipient_key: String::new(),
            seal_share: String::new(),
            seal_status: Status::Idle,
            unseal_share: String::new(),
            unseal_secret_key: String::new(),
            unseal_plaintext: String::new(),
            unseal_status: Status::Idle,
            rpc_url: "http://127.0.0.1:8545".to_string(),
            registry_address: String::new(),
            registry_filter: String::new(),
            records: Vec::new(),
            registry_status: Status::Idle,
            revoke_id: String::new(),
            revoke_record: None,
            revoke_status: Status::Idle,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::WalletManual(v) => {
                self.wallet_manual = v;
                true
            }
            Msg::WalletConnect => {
                self.wallet_status = Status::Working("requesting accounts...");
                ctx.link().send_future(async {
                    Msg::WalletConnected(ethereum::request_account().await)
                });
                true
            }
            Msg::WalletConnected(Ok(addr)) => {
                self.registry_filter = addr.clone();
                self.wallet_address = addr.clone();
                self.wallet_status = Status::Ok(format!("connected: {addr}"));
                true
            }
            Msg::WalletConnected(Err(e)) => {
                self.wallet_status = Status::Err(e);
                true
            }

            Msg::SealPlaintext(v) => {
                self.seal_plaintext = v;
                true
            }
            Msg::SealRecipientKey(v) => {
                self.seal_recipient_key = v;
                true
            }
            Msg::SealRun => {
                match seal::seal_to_share_string(
                    self.seal_plaintext.as_bytes(),
                    self.seal_recipient_key.trim(),
                ) {
                    Ok(share) => {
                        self.seal_share = share;
                        self.seal_status = Status::Ok("sealed locally; share string ready".into());
                    }
                    Err(e) => {
                        self.seal_share.clear();
                        self.seal_status = Status::Err(format!("{e}"));
                    }
                }
                true
            }

            Msg::UnsealShare(v) => {
                self.unseal_share = v;
                true
            }
            Msg::UnsealSecretKey(v) => {
                self.unseal_secret_key = v;
                true
            }
            Msg::UnsealRun => {
                let key = self.unseal_secret_key.trim();
                match bitbid_webapp_core::address::hex_to_bytes(key) {
                    Ok(bytes) => match seal::unseal_to_string(self.unseal_share.trim(), &bytes) {
                        Ok(plain) => {
                            self.unseal_plaintext = plain;
                            self.unseal_status = Status::Ok("unsealed locally".into());
                        }
                        Err(e) => {
                            self.unseal_plaintext.clear();
                            self.unseal_secret_key.clear();
                            self.unseal_status = Status::Err(format!("{e}"));
                        }
                    },
                    Err(e) => {
                        self.unseal_plaintext.clear();
                        self.unseal_status = Status::Err(format!("invalid private key hex: {e}"));
                    }
                }
                true
            }

            Msg::RpcUrl(v) => {
                self.rpc_url = v;
                true
            }
            Msg::RegistryAddress(v) => {
                self.registry_address = v;
                true
            }
            Msg::RegistryFilter(v) => {
                self.registry_filter = v;
                true
            }
            Msg::RegistryLoad => {
                self.registry_status = Status::Working("reading registry logs...");
                let url = self.rpc_url.trim().to_string();
                let registry = self.registry_address.trim().to_string();
                let filter = self.registry_filter.trim().to_string();
                ctx.link().send_future(async move {
                    Msg::RegistryLoaded(fetch_registry(&url, &registry, &filter).await)
                });
                true
            }
            Msg::RegistryLoaded(Ok(records)) => {
                self.registry_status = Status::Ok(format!("{} record(s)", records.len()));
                self.records = records;
                true
            }
            Msg::RegistryLoaded(Err(e)) => {
                self.records.clear();
                self.registry_status = Status::Err(e);
                true
            }

            Msg::RevokeId(v) => {
                self.revoke_id = v;
                true
            }
            Msg::RevokeLookup => {
                self.revoke_status = Status::Working("calling getSecretInfo...");
                let url = self.rpc_url.trim().to_string();
                let registry = self.registry_address.trim().to_string();
                let id = self.revoke_id.trim().to_string();
                ctx.link().send_future(async move {
                    Msg::RevokeLoaded(lookup_record(&url, &registry, &id).await)
                });
                true
            }
            Msg::RevokeLoaded(Ok(rec)) => {
                self.revoke_status = Status::Ok("record found".into());
                self.revoke_record = Some(rec);
                true
            }
            Msg::RevokeLoaded(Err(e)) => {
                self.revoke_record = None;
                self.revoke_status = Status::Err(e);
                true
            }
            Msg::RevokeExplain => {
                self.revoke_status = Status::Ok(
                    "Revoke requires an on-chain signed transaction from the owner's wallet. \
                     This read-only console never holds your key, so it cannot sign one."
                        .into(),
                );
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <>
                <header class="masthead">
                    <div class="shell masthead__bar">
                        <span class="brand">{ "bit" }<span class="brand__verm">{ "bid" }</span>{ " console" }</span>
                        <span class="label masthead__note">{ "no secret leaves this page" }</span>
                    </div>
                </header>

                <main class="shell">
                    { self.wallet_panel(ctx) }
                    { self.seal_panel(ctx) }
                    { self.unseal_panel(ctx) }
                    { self.registry_panel(ctx) }
                    { self.revoke_panel(ctx) }
                </main>
            </>
        }
    }
}

impl App {
    fn panel(fig: &str, title: &str, body: Html) -> Html {
        html! {
            <section class="module">
                <div class="module__rail">
                    <div class="nameplate"><span class="label">{ title }</span></div>
                    <div class="module__fig mono">{ fig }</div>
                </div>
                <div class="module__main">{ body }</div>
            </section>
        }
    }

    fn field(label: &str, id: &str, value: &str, oninput: Callback<InputEvent>, mono: bool) -> Html {
        let class = classes!("field", mono.then_some("field--mono"));
        html! {
            <label class={class} for={id.to_string()}>
                <span class="label">{ label }</span>
                <input id={id.to_string()} value={value.to_string()} oninput={oninput} />
            </label>
        }
    }

    fn area(label: &str, id: &str, value: &str, oninput: Callback<InputEvent>, rows: u32) -> Html {
        html! {
            <label class="field field--mono" for={id.to_string()}>
                <span class="label">{ label }</span>
                <textarea id={id.to_string()} rows={rows.to_string()} value={value.to_string()} oninput={oninput} />
            </label>
        }
    }

    fn wallet_panel(&self, ctx: &Context<Self>) -> Html {
        let on_manual = ctx.link().callback(|e: InputEvent| Msg::WalletManual(input_value(&e)));
        let body = html! {
            <>
                <p class="lede">
                    { "Connect an injected EIP-1193 wallet to filter registry results, or type an \
                       address by hand. The address is only ever used as a filter — it is never sent \
                       anywhere, and no key or mnemonic is requested." }
                </p>
                <div class="controls">
                    <button class="btn btn--crank" onclick={ctx.link().callback(|_| Msg::WalletConnect)}>
                        <span class="btn__key"></span>{ "connect wallet" }
                    </button>
                </div>
                <div class="grid2">
                    { Self::field("connected address", "wallet-address", &self.wallet_address, Callback::from(|_| ()), true) }
                    { Self::field("manual address (filter only)", "wallet-manual", &self.wallet_manual, on_manual, true) }
                </div>
                { self.wallet_status.line() }
            </>
        };
        Self::panel("FIG. 01", "WALLET / EIP-1193", body)
    }

    fn seal_panel(&self, ctx: &Context<Self>) -> Html {
        let on_plain = ctx.link().callback(|e: InputEvent| Msg::SealPlaintext(input_value(&e)));
        let on_key = ctx.link().callback(|e: InputEvent| Msg::SealRecipientKey(input_value(&e)));
        let body = html! {
            <>
                <p class="lede">
                    { "Seal runs entirely in your browser: ECDH on secp256k1 derives a key-wrap via \
                       HKDF-SHA256, and the payload is encrypted with AES-256-GCM. Give a recipient \
                       public key (SEC1, 0x04…). The share string also opens in the CLI." }
                </p>
                <div class="grid2">
                    { Self::area("plaintext", "seal-plain", &self.seal_plaintext, on_plain, 5) }
                    <div>
                        { Self::field("recipient public key (SEC1)", "seal-key", &self.seal_recipient_key, on_key, true) }
                        <div class="controls">
                            <button class="btn btn--crank" onclick={ctx.link().callback(|_| Msg::SealRun)}>
                                <span class="btn__key"></span>{ "seal" }
                            </button>
                        </div>
                        { self.seal_status.line() }
                    </div>
                </div>
                <div class="readout-pane">
                    <span class="label">{ "share string" }</span>
                    <textarea class="readout" rows="5" readonly=true value={self.seal_share.clone()} />
                </div>
            </>
        };
        Self::panel("FIG. 02", "SEAL / ECDH + AES-256-GCM", body)
    }

    fn unseal_panel(&self, ctx: &Context<Self>) -> Html {
        let on_share = ctx.link().callback(|e: InputEvent| Msg::UnsealShare(input_value(&e)));
        let on_key = ctx.link().callback(|e: InputEvent| Msg::UnsealSecretKey(input_value(&e)));
        let body = html! {
            <>
                <p class="lede">
                    { "Paste a share string or an IPFS payload JSON and the recipient private key (hex). Unseal derives the \
                       same ECDH shared secret and decrypts locally. A wrong key or a tampered payload \
                       fails the AEAD check and yields no plaintext." }
                </p>
                <div class="grid2">
                    { Self::area("share string", "unseal-share", &self.unseal_share, on_share, 5) }
                    <div>
                        { Self::field("recipient private key (hex)", "unseal-key", &self.unseal_secret_key, on_key, true) }
                        <div class="controls">
                            <button class="btn" onclick={ctx.link().callback(|_| Msg::UnsealRun)}>
                                { "unseal" }
                            </button>
                        </div>
                        { self.unseal_status.line() }
                    </div>
                </div>
                <div class="readout-pane">
                    <span class="label">{ "plaintext" }</span>
                    <textarea class="readout" rows="5" readonly=true value={self.unseal_plaintext.clone()} />
                </div>
            </>
        };
        Self::panel("FIG. 03", "UNSEAL / DECRYPT", body)
    }

    fn registry_panel(&self, ctx: &Context<Self>) -> Html {
        let on_url = ctx.link().callback(|e: InputEvent| Msg::RpcUrl(input_value(&e)));
        let on_addr = ctx.link().callback(|e: InputEvent| Msg::RegistryAddress(input_value(&e)));
        let on_filter = ctx.link().callback(|e: InputEvent| Msg::RegistryFilter(input_value(&e)));
        let rows = self.records.iter().map(|r| {
            let state = if r.revoked {
                "revoked"
            } else if r.is_public {
                "public"
            } else {
                "live"
            };
            html! {
                <tr key={r.id.clone()}>
                    <td class="mono">{ short(&r.id) }</td>
                    <td class="mono">{ r.cid.clone() }</td>
                    <td class="mono">{ short(&r.owner) }</td>
                    <td class="mono">{ r.expires_at.to_string() }</td>
                    <td class="mono">{ format!("{} / {}", r.reads, r.max_reads) }</td>
                    <td class="mono">{ state }</td>
                </tr>
            }
        });
        let body = html! {
            <>
                <p class="lede">
                    { "Read-only explorer over eth_getLogs. Requests go only to the JSON-RPC endpoint \
                       below; the address filter is applied locally." }
                </p>
                <div class="grid3">
                    { Self::field("json-rpc endpoint", "rpc-url", &self.rpc_url, on_url, true) }
                    { Self::field("registry contract", "registry", &self.registry_address, on_addr, true) }
                    { Self::field("filter address", "registry-filter", &self.registry_filter, on_filter, true) }
                </div>
                <div class="controls">
                    <button class="btn btn--crank" onclick={ctx.link().callback(|_| Msg::RegistryLoad)}>
                        <span class="btn__key"></span>{ "read registry" }
                    </button>
                </div>
                { self.registry_status.line() }
                <div class="table-wrap">
                    <table class="records">
                        <thead>
                            <tr>
                                <th>{ "id" }</th><th>{ "cid" }</th><th>{ "owner" }</th>
                                <th>{ "expires_at" }</th><th>{ "reads" }</th><th>{ "state" }</th>
                            </tr>
                        </thead>
                        <tbody>{ for rows }</tbody>
                    </table>
                </div>
            </>
        };
        Self::panel("FIG. 04", "REGISTRY / ETH_GETLOGS", body)
    }

    fn revoke_panel(&self, ctx: &Context<Self>) -> Html {
        let on_id = ctx.link().callback(|e: InputEvent| Msg::RevokeId(input_value(&e)));
        let lookup = self.revoke_record.as_ref().map(|r| {
            html! {
                <div class="readout-pane">
                    <span class="label">{ "record" }</span>
                    <p class="readout">
                        { "id " }<b>{ r.id.clone() }</b><br />
                        { "cid " }<b>{ r.cid.clone() }</b><br />
                        { "owner " }<b>{ r.owner.clone() }</b><br />
                        { "expires_at " }<b>{ r.expires_at.to_string() }</b><br />
                        { "reads " }<b>{ format!("{} / {}", r.reads, r.max_reads) }</b><br />
                        { "revoked " }<b>{ r.revoked.to_string() }</b>
                    </p>
                </div>
            }
        });
        let body = html! {
            <>
                <p class="lede">
                    { "Look up a single record with eth_call getSecretInfo. Revocation itself is an \
                       on-chain signed transaction from the owner's wallet; this console is read-only \
                       and holds no keys, so it cannot perform it." }
                </p>
                { Self::field("secret id", "revoke-id", &self.revoke_id, on_id, true) }
                <div class="controls">
                    <button class="btn" onclick={ctx.link().callback(|_| Msg::RevokeLookup)}>
                        { "look up" }
                    </button>
                    <button class="btn btn--ghost" onclick={ctx.link().callback(|_| Msg::RevokeExplain)}>
                        { "revoke" }
                    </button>
                </div>
                { self.revoke_status.line() }
                { lookup }
            </>
        };
        Self::panel("FIG. 05", "REVOKE / NOT AVAILABLE", body)
    }
}

fn input_value(e: &InputEvent) -> String {
    e.target_unchecked_into::<web_sys::HtmlInputElement>().value()
}

fn short(value: &str) -> String {
    if value.len() <= 14 {
        return value.to_string();
    }
    format!("{}…{}", &value[..8], &value[value.len() - 4..])
}

async fn fetch_registry(
    url: &str,
    registry: &str,
    filter: &str,
) -> Result<Vec<RegistryRecord>, String> {
    if url.is_empty() {
        return Err("no JSON-RPC endpoint configured".into());
    }
    if registry.is_empty() {
        return Err("no registry contract address configured".into());
    }
    let params = json!([{
        "address": registry,
        "fromBlock": "0x0",
        "toBlock": "latest",
    }]);
    let body = rpc::rpc_raw(url, "eth_getLogs", params).await?;
    let mut records = decode_get_logs_response(&body).map_err(|e| e.to_string())?;
    if !filter.is_empty() {
        let needle = filter.to_lowercase();
        records.retain(|r| {
            r.owner.to_lowercase() == needle || r.recipient.to_lowercase() == needle
        });
    }
    Ok(records)
}

async fn lookup_record(url: &str, registry: &str, id: &str) -> Result<RegistryRecord, String> {
    if url.is_empty() || registry.is_empty() {
        return Err("json-rpc endpoint and registry address are required".into());
    }
    if id.is_empty() {
        return Err("a secret id is required".into());
    }
    let calldata = encode_get_secret_info_calldata(id).map_err(|e| e.to_string())?;
    let params = json!([{ "to": registry, "data": calldata }, "latest"]);
    let body = rpc::rpc_raw(url, "eth_call", params).await?;
    decode_get_secret_info_response(&body, id).map_err(|e| e.to_string())
}
