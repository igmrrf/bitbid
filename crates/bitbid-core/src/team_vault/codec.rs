use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::BTreeMap;

pub type D = [u8; 32];
pub type Id = [u8; 16];
pub type Result<T> = super::Result<T>;
pub const RECORD_MAX: usize = 16 * 1024 * 1024;
pub const EXPORT_MAX: usize = 256 * 1024 * 1024;
pub const LIST_MAX: usize = 10000;
const PREFIX: &[u8] = b"bitbid-team-v1/";
pub fn ensure(b: bool, why: &'static str) -> Result<()> {
    if b { Ok(()) } else { Err(why.into()) }
}
pub fn arr<const N: usize>(b: &[u8]) -> Result<[u8; N]> {
    b.try_into().map_err(|_| "field length".into())
}
pub fn num(b: &[u8], width: usize) -> Result<u64> {
    ensure(b.len() == width, "numeric width")?;
    Ok(b.iter().fold(0, |n, x| (n << 8) | u64::from(*x)))
}
pub fn add(n: u64) -> Result<u64> {
    n.checked_add(1).ok_or("integer overflow".into())
}
pub fn nonzero(b: &[u8]) -> Result<()> {
    ensure(b.iter().any(|x| *x != 0), "zero identifier")
}
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or("offset overflow")?;
        ensure(end <= self.b.len(), "truncated frame")?;
        let v = &self.b[self.pos..end];
        self.pos = end;
        Ok(v)
    }
    fn size(&mut self, n: usize) -> Result<usize> {
        Ok(num(self.take(n)?, n)? as usize)
    }
    fn field(&mut self) -> Result<&'a [u8]> {
        let n = self.size(4)?;
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        ensure(self.pos == self.b.len(), "trailing bytes")
    }
}
pub fn fields<'a>(b: &'a [u8], label: &str, arity: usize) -> Result<Vec<&'a [u8]>> {
    ensure(b.len() <= EXPORT_MAX, "frame budget")?;
    let mut c = Cursor { b, pos: 0 };
    ensure(c.take(PREFIX.len())? == PREFIX, "domain")?;
    let n = c.size(2)?;
    ensure(c.take(n)? == label.as_bytes(), "label")?;
    ensure(c.size(2)? == arity, "arity")?;
    let mut out = Vec::new();
    out.try_reserve_exact(arity)
        .map_err(|_| "frame allocation")?;
    for _ in 0..arity {
        out.push(c.field()?);
    }
    c.end()?;
    Ok(out)
}
pub fn list(b: &[u8]) -> Result<Vec<&[u8]>> {
    let mut c = Cursor { b, pos: 0 };
    let n = c.size(4)?;
    ensure(n <= LIST_MAX, "list bound")?;
    ensure(n <= b.len().saturating_sub(4) / 4, "list byte budget")?;
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| "list allocation")?;
    for _ in 0..n {
        v.push(c.field()?);
    }
    c.end()?;
    Ok(v)
}
pub fn t(label: &str, fs: &[&[u8]]) -> Vec<u8> {
    let mut v = PREFIX.to_vec();
    v.extend((label.len() as u16).to_be_bytes());
    v.extend(label.as_bytes());
    v.extend((fs.len() as u16).to_be_bytes());
    for f in fs {
        v.extend((f.len() as u32).to_be_bytes());
        v.extend(*f)
    }
    v
}
pub fn ordered<T: Ord>(previous: &mut Option<T>, key: T) -> Result<()> {
    if let Some(p) = previous.as_ref() {
        ensure(p < &key, "duplicate or unsorted map")?;
    }
    *previous = Some(key);
    Ok(())
}
pub fn text(b: &[u8], max: usize) -> Result<&str> {
    ensure(b.len() <= max, "text bound")?;
    std::str::from_utf8(b).map_err(|_| "utf8".into())
}
pub fn token(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("bitbid-team1:").ok_or("token prefix")?;
    ensure(s.len() <= EXPORT_MAX * 4 / 3 + 8, "transport budget")?;
    let mut b = Vec::new();
    b.try_reserve_exact(s.len().saturating_mul(3) / 4 + 3)
        .map_err(|_| "transport allocation")?;
    URL_SAFE_NO_PAD
        .decode_vec(s, &mut b)
        .map_err(|_| "base64url")?;
    ensure(URL_SAFE_NO_PAD.encode(&b) == s, "noncanonical base64url")?;
    Ok(b)
}
#[derive(Clone)]
pub struct Wire {
    pub bytes: Vec<u8>,
    pub kind: String,
    pub signer: Option<D>,
    pub payload: Vec<u8>,
}
impl Wire {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let f = fields(b, "wire", 4)?;
        ensure(num(f[0], 2)? == 1 && num(f[1], 2)? == 1, "version/suite")?;
        let kind = text(f[2], 32)?;
        ensure(
            b.len()
                <= if kind == "export" {
                    EXPORT_MAX
                } else {
                    RECORD_MAX
                },
            "wire byte bound",
        )?;
        let signed = match kind {
            "identity" | "grant" | "content" | "authority" | "snapshot" | "acceptance"
            | "team-anchor" | "export" => true,
            "pass-wrapper" | "recovery-wrapper" | "trust-wrapper" => false,
            _ => return Err("unknown kind".into()),
        };
        let (signer, payload) = if signed {
            let e = fields(f[3], "signed-envelope", 3)?;
            arr::<64>(e[2])?;
            (Some(arr(e[0])?), copy(e[1])?)
        } else {
            (None, copy(f[3])?)
        };
        Ok(Self {
            bytes: copy(b)?,
            kind: kind.into(),
            signer,
            payload,
        })
    }
    pub fn signature(&self) -> Result<[u8; 64]> {
        let w = fields(&self.bytes, "wire", 4)?;
        let e = fields(w[3], "signed-envelope", 3)?;
        arr(e[2])
    }
    pub fn hash(&self) -> D {
        super::crypto::hash(&self.bytes)
    }
}
#[derive(Clone)]
pub struct Identity {
    pub account: Id,
    pub generation: u64,
    pub key: D,
    pub x: D,
    pub ed: D,
}
impl Identity {
    pub fn parse(w: &Wire) -> Result<Self> {
        ensure(w.kind == "identity", "identity kind")?;
        let f = fields(&w.payload, "identity", 4)?;
        let account = arr(f[0])?;
        nonzero(&account)?;
        let generation = num(f[1], 8)?;
        ensure(generation > 0, "generation")?;
        let key = super::crypto::hash(&w.payload);
        ensure(w.signer == Some(key), "identity signer binding")?;
        Ok(Self {
            account,
            generation,
            key,
            x: arr(f[2])?,
            ed: arr(f[3])?,
        })
    }
}
#[derive(Default)]
pub struct Store {
    pub wires: BTreeMap<D, Wire>,
    pub identities: BTreeMap<D, Identity>,
}
impl Store {
    pub fn load(records: &[Vec<u8>]) -> Result<Self> {
        ensure(records.len() <= LIST_MAX, "record count")?;
        let mut s = Self::default();
        for b in records {
            let w = Wire::parse(b)?;
            ensure(w.kind != "export", "nested export")?;
            let h = w.hash();
            ensure(s.wires.insert(h, w).is_none(), "duplicate wire")?;
        }
        for w in s.wires.values().filter(|w| w.kind == "identity") {
            let i = Identity::parse(w)?;
            super::crypto::verify(w, &i)?;
            ensure(
                s.identities.insert(i.key, i).is_none(),
                "duplicate identity",
            )?;
        }
        Ok(s)
    }
    pub fn get(&self, h: &D, kind: &str) -> Result<&Wire> {
        let w = self.wires.get(h).ok_or("missing record")?;
        ensure(w.kind == kind, "wrong record kind")?;
        if let Some(k) = w.signer {
            let i = self.identities.get(&k).ok_or("missing signer identity")?;
            super::crypto::verify(w, i)?;
        }
        Ok(w)
    }
    pub fn identity(&self, key: &D, account: &Id) -> Result<&Identity> {
        let i = self.identities.get(key).ok_or("missing identity")?;
        ensure(i.account == *account, "identity account binding")?;
        Ok(i)
    }
}

pub fn copy(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| "buffer allocation")?;
    out.extend_from_slice(bytes);
    Ok(out)
}
