//! Bounds-checked DNS wire parsing for the request path.
//!
//! Everything here treats its input as untrusted: every read is checked and
//! every loop is bounded by the packet length or a fixed jump limit, so no
//! input can panic the server. The module backs the cache key, the 0x20
//! question-case echo, DNSSEC stripping and the hickory-free cache-hit path.

use hickory_proto::{
    op::Message,
    rr::{Name, Record},
};
use std::collections::{HashMap, HashSet};

const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
const MAX_POINTER_JUMPS: usize = 128;
/// Longest canonical key: a 255-byte name plus qtype, qclass and the flags
/// byte (255 + 2 + 2 + 1). Callers must provide at least this many bytes.
pub const MIN_CANONICAL_BUFFER: usize = 260;

const QR_BIT: u16 = 0x8000;
const AA_BIT: u16 = 0x0400;
const TC_BIT: u16 = 0x0200;
const Z_BIT: u16 = 0x0040;
const RA_BIT: u16 = 0x0080;
const RD_BIT: u16 = 0x0100;
const CD_BIT: u16 = 0x0010;
const AD_BIT: u16 = 0x0020;
const DO_BIT: u32 = 0x0000_8000;

/// Positive TTL cap: 7 days, the cap RFC 8767 §4 recommends.
pub const MAX_TTL: u32 = 604_800;

/// RFC 8767 §4 (updating RFC 2181 §8): a TTL is unsigned, so one with the
/// high-order bit set is a large positive value, capped like any other at
/// [`MAX_TTL`] (the RFC's recommended 7 days). The plaintext path applies its
/// own lower cap on top.
pub fn rfc8767_ttl(ttl: u32) -> u32 {
    ttl.min(MAX_TTL)
}

const CNAME_TYPE: u16 = 5;
const SOA_TYPE: u16 = 6;
const DNAME_TYPE: u16 = 39;
const OPT_TYPE: u16 = 41;
const TSIG_TYPE: u16 = 250;
const SIG0_TYPE: u16 = 24;
/// Upper bounds for the terminal-answer classifier's CNAME/DNAME walk.
const MAX_CHAIN_STEPS: usize = 16;
const MAX_CHAIN_RECORDS: usize = 64;
/// QTYPEs answered FORMERR locally, never forwarded: the reserved TYPE 0, the
/// meta-TYPEs OPT (41) and TSIG (250) and the unassigned meta range 128-248,
/// which includes NXNAME (RFC 6895 §3.1, RFC 9824 §3.5). TKEY (249) is REFUSED with the transfer
/// types; MAILB/MAILA (253, 254) are QTYPEs and forward like any other.
pub fn is_meta_qtype(qtype: u16) -> bool {
    matches!(qtype, 0 | 41 | 250 | 128..=248)
}
/// QTYPEs that ask for a zone transfer or key exchange, refused locally.
pub const TRANSFER_TYPES: [u16; 3] = [249, 251, 252]; // TKEY, IXFR, AXFR

/// DNSSEC record types stripped from responses sent to DO=0 clients.
const DNSSEC_TYPES: [u16; 8] = [43, 46, 47, 48, 50, 51, 59, 60];

/// The 12-byte header, readable before the rest of the packet is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub opcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    /// QR bit: such packets are dropped, never answered (response loops).
    pub fn is_response(&self) -> bool {
        self.flags & QR_BIT != 0
    }

    /// RD bit, echoed into locally built error responses.
    pub fn recursion_desired(&self) -> bool {
        self.flags & RD_BIT != 0
    }
}

/// Reads the fixed header. `None` means the packet is too short to answer.
pub fn header(raw: &[u8]) -> Option<Header> {
    if raw.len() < HEADER_LEN {
        return None;
    }
    Some(Header {
        id: u16::from_be_bytes([raw[0], raw[1]]),
        flags: u16::from_be_bytes([raw[2], raw[3]]),
        opcode: (raw[2] >> 3) & 0x0f,
        qdcount: u16::from_be_bytes([raw[4], raw[5]]),
        ancount: u16::from_be_bytes([raw[6], raw[7]]),
        nscount: u16::from_be_bytes([raw[8], raw[9]]),
        arcount: u16::from_be_bytes([raw[10], raw[11]]),
    })
}

fn be16(raw: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*raw.get(at)?, *raw.get(at + 1)?]))
}

fn be32(raw: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*raw.get(at)?, *raw.get(at + 1)?, *raw.get(at + 2)?, *raw.get(at + 3)?]))
}

/// The parsed question of a one-question message.
///
/// `name` is the encoded name bytes starting at offset 12; it is the exact
/// client case for the uncompressed question every legitimate query uses.
/// A compressed question keeps its pointer bytes in `name` while `lower`
/// holds the decompressed lowercase form.
pub struct QueryView<'a> {
    pub id: u16,
    pub flags: u16,
    pub opcode: u8,
    pub qdcount: u16,
    pub qname_wire: &'a [u8],
    pub qname_lower: [u8; 255],
    pub qname_len: u8,
    /// The question name uses a compression pointer. Such queries are valid
    /// but unusual; plaintext 0x20 randomization and strict upstream question
    /// echo are skipped for them.
    pub qname_compressed: bool,
    pub qtype: u16,
    pub qclass: u16,
    pub rd: bool,
    pub cd: bool,
    pub edns_present: bool,
    pub edns_do: bool,
    /// The 16-bit EDNS flags field. DO is bit 15.
    pub edns_flags: u16,
    /// Any EDNS flag other than DO, such as Compact Answers OK (RFC 9824).
    /// Such queries bypass caching and coalescing.
    pub edns_other_flags: bool,
    /// A header flag with no meaning in a query (AA, TC or the reserved Z
    /// bit) is set. Such queries bypass caching and coalescing.
    pub unfamiliar_header_flags: bool,
    /// An EDNS option other than the hop-scoped [`HOP_OPTIONS`]. Such queries
    /// bypass caching and coalescing.
    pub edns_options: bool,
    /// A hop-scoped option ([`HOP_OPTIONS`]) is present; the upstream copy of
    /// the query drops it.
    pub edns_hop_options: bool,
    /// A client ECS option is malformed (RFC 7871 §6). The server answers
    /// FORMERR after EDNS version negotiation (RFC 6891 §6.1.3), never forwards it.
    pub edns_bad_ecs: bool,
    pub edns_payload: u16,
    /// EDNS version from the OPT TTL. The server answers non-zero with BADVERS.
    pub edns_version: u8,
    pub has_answer_or_authority: bool,
    pub has_non_opt_additional: bool,
    /// TSIG (250) or SIG(0) (24) present in the additional section.
    pub signed: bool,
}

impl QueryView<'_> {
    /// The query header's AD bit (a client that asked for authenticated data).
    pub fn authentic_data(&self) -> bool {
        self.flags & AD_BIT != 0
    }
}

struct NameInfo {
    /// Offset just past the encoded name at the original position.
    end: usize,
    /// Uncompressed length in bytes, including the root label.
    len: u8,
    compressed: bool,
}

/// Validates one wire name starting at `start` and writes its lowercased,
/// uncompressed form (labels plus root) into `out`.
///
/// Pointers may only point strictly backwards and at most 128 are followed.
/// Labels are at most 63 bytes and the whole name at most 255 bytes.
fn read_name(raw: &[u8], start: usize, out: &mut [u8; MAX_NAME_LEN]) -> Option<NameInfo> {
    read_name_with(raw, start, out, true, true)
}

/// [`read_name`] with a choice of case and pointer rule: `fold == false` keeps
/// the label bytes exactly as sent, for rewriting a name literally; `strict`
/// also refuses a pointer into the header, which is not a prior name (RFC 1035
/// §4.1.4). Responses are read strictly. Queries keep the lenient rule their
/// compressed-question handling is built on.
fn read_name_with(
    raw: &[u8],
    start: usize,
    out: &mut [u8; MAX_NAME_LEN],
    fold: bool,
    strict: bool,
) -> Option<NameInfo> {
    let mut pos = start;
    let mut out_len = 0usize;
    let mut jumps = 0usize;
    let mut compressed = false;
    let mut end = None;
    loop {
        let len = *raw.get(pos)?;
        match len & 0xc0 {
            0x00 if len == 0 => {
                if out_len >= MAX_NAME_LEN {
                    return None;
                }
                out[out_len] = 0;
                out_len += 1;
                return Some(NameInfo { end: end.unwrap_or(pos + 1), len: out_len as u8, compressed });
            }
            0x00 => {
                let len = len as usize;
                if len > MAX_LABEL_LEN {
                    return None;
                }
                let label = raw.get(pos + 1..pos + 1 + len)?;
                // One byte for the length prefix, `len` bytes of label and at
                // least one byte left for the terminating root label.
                if out_len + 1 + len >= MAX_NAME_LEN {
                    return None;
                }
                out[out_len] = len as u8;
                out_len += 1;
                for &byte in label {
                    out[out_len] = if fold { byte.to_ascii_lowercase() } else { byte };
                    out_len += 1;
                }
                pos += 1 + len;
            }
            0xc0 => {
                if end.is_none() {
                    end = Some(pos + 2);
                }
                let target = (((len & 0x3f) as usize) << 8) | (*raw.get(pos + 1)? as usize);
                if target >= pos || (strict && target < HEADER_LEN) {
                    return None;
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                compressed = true;
                pos = target;
            }
            _ => return None,
        }
    }
}

struct RecordHeader {
    rtype: u16,
    class: u16,
    ttl: u32,
    ttl_off: usize,
    rdata: usize,
    end: usize,
    /// Uncompressed owner length, including the root label.
    name_len: u8,
    /// The owner name is the root (a single uncompressed root label).
    root_name: bool,
}

/// Reads one resource-record header, skipping over its RDATA.
fn record_header(raw: &[u8], start: usize, scratch: &mut [u8; MAX_NAME_LEN]) -> Option<RecordHeader> {
    record_header_with(raw, start, scratch, true)
}

fn record_header_with(
    raw: &[u8],
    start: usize,
    scratch: &mut [u8; MAX_NAME_LEN],
    strict: bool,
) -> Option<RecordHeader> {
    let name = read_name_with(raw, start, scratch, true, strict)?;
    let fields = name.end;
    let ttl_off = fields.checked_add(4)?;
    let rlen = be16(raw, fields.checked_add(8)?)? as usize;
    let rdata = fields.checked_add(10)?;
    let end = rdata.checked_add(rlen)?;
    if end > raw.len() {
        return None;
    }
    Some(RecordHeader {
        rtype: be16(raw, fields)?,
        class: be16(raw, fields.checked_add(2)?)?,
        ttl: be32(raw, ttl_off)?,
        ttl_off,
        rdata,
        end,
        name_len: name.len,
        root_name: name.len == 1,
    })
}

/// Client options that describe this hop, never the question: ECS (8,
/// RFC 8932 §5.3.1: not sent upstream), Cookie (10, per client and server),
/// TCP keepalive (11) and Padding (12). They are removed from the upstream
/// query and do not make a query uncacheable.
pub const HOP_OPTIONS: [u16; 4] = [8, 10, 11, 12];

/// (any non-hop option, any hop option, a malformed ECS option) in a
/// validated OPT RDATA.
fn option_kinds(raw: &[u8], mut pos: usize, end: usize) -> Option<(bool, bool, bool)> {
    let (mut shared, mut hop, mut bad_ecs) = (false, false, false);
    while pos + 4 <= end {
        let code = be16(raw, pos)?;
        let len = be16(raw, pos + 2)? as usize;
        if code == 8 && !ecs_valid(raw.get(pos + 4..pos + 4 + len)?) {
            bad_ecs = true;
        }
        if HOP_OPTIONS.contains(&code) {
            hop = true;
        } else {
            shared = true;
        }
        pos += 4 + len;
    }
    Some((shared, hop, bad_ecs))
}

/// RFC 7871 §6 for a query: FAMILY 1 or 2, SOURCE within the family, SCOPE 0,
/// exactly ceil(SOURCE/8) address octets with no bits set past SOURCE.
fn ecs_valid(data: &[u8]) -> bool {
    let [family_hi, family_lo, source, scope, address @ ..] = data else { return false };
    let bits = match u16::from_be_bytes([*family_hi, *family_lo]) {
        1 => 32,
        2 => 128,
        _ => return false,
    };
    if *source > bits || *scope != 0 || address.len() != usize::from(source.div_ceil(8)) {
        return false;
    }
    let spare = source % 8;
    spare == 0 || address.last().is_none_or(|last| last & (0xff >> spare) == 0)
}

/// An OPT RR whose RDLEN is non-zero must contain whole [code, len, data]
/// options; a truncated option is a malformed request.
fn opt_options_valid(raw: &[u8], mut pos: usize, end: usize) -> bool {
    while pos < end {
        if end - pos < 4 {
            return false;
        }
        let Some(len) = be16(raw, pos + 2) else {
            return false;
        };
        let len = len as usize;
        if end - pos - 4 < len {
            return false;
        }
        pos += 4 + len;
    }
    true
}

pub(crate) fn is_dnssec_type(rtype: u16) -> bool {
    DNSSEC_TYPES.contains(&rtype)
}

struct QuestionInfo<'a> {
    name: &'a [u8],
    lower: [u8; MAX_NAME_LEN],
    len: u8,
    end: usize,
    compressed: bool,
    qtype: u16,
    qclass: u16,
}

/// Parses the question section of a message with exactly one question,
/// without looking at the remaining sections.
fn read_question(raw: &[u8]) -> Option<QuestionInfo<'_>> {
    let head = header(raw)?;
    if head.qdcount != 1 {
        return None;
    }
    let mut lower = [0u8; MAX_NAME_LEN];
    let name = read_name(raw, HEADER_LEN, &mut lower)?;
    Some(QuestionInfo {
        name: &raw[HEADER_LEN..name.end],
        lower,
        len: name.len,
        end: name.end,
        compressed: name.compressed,
        qtype: be16(raw, name.end)?,
        qclass: be16(raw, name.end.checked_add(2)?)?,
    })
}

/// Parses a query (or a response question) with exactly one question.
///
/// Returns `None` for a short header, `qdcount != 1`, a malformed or looping
/// name, out-of-bounds sections, trailing bytes after the counted sections, a
/// duplicate or non-root OPT, or a malformed OPT option.
pub fn parse_query(raw: &[u8]) -> Option<QueryView<'_>> {
    let head = header(raw)?;
    let q = read_question(raw)?;
    let mut pos = q.end.checked_add(4)?;
    if pos > raw.len() {
        return None;
    }
    let mut view = QueryView {
        id: head.id,
        flags: head.flags,
        opcode: head.opcode,
        qdcount: head.qdcount,
        qname_wire: q.name,
        qname_lower: q.lower,
        qname_len: q.len,
        qname_compressed: q.compressed,
        qtype: q.qtype,
        qclass: q.qclass,
        rd: head.flags & RD_BIT != 0,
        cd: head.flags & CD_BIT != 0,
        edns_present: false,
        edns_do: false,
        edns_flags: 0,
        edns_other_flags: false,
        unfamiliar_header_flags: head.flags & (AA_BIT | TC_BIT | Z_BIT) != 0,
        edns_options: false,
        edns_hop_options: false,
        edns_bad_ecs: false,
        edns_payload: 0,
        edns_version: 0,
        has_answer_or_authority: head.ancount > 0 || head.nscount > 0,
        has_non_opt_additional: false,
        signed: false,
    };
    let mut scratch = [0u8; MAX_NAME_LEN];
    for _ in 0..head.ancount as usize + head.nscount as usize {
        pos = record_header(raw, pos, &mut scratch)?.end;
    }
    for _ in 0..head.arcount {
        let record = record_header(raw, pos, &mut scratch)?;
        if record.rtype == OPT_TYPE {
            // RFC 6891 §6.1.2: the OPT owner name is the root.
            if !record.root_name || view.edns_present {
                return None;
            }
            view.edns_present = true;
            view.edns_payload = record.class;
            view.edns_version = (record.ttl >> 16) as u8;
            view.edns_flags = record.ttl as u16;
            view.edns_do = view.edns_flags & DO_BIT as u16 != 0;
            view.edns_other_flags = view.edns_flags & !(DO_BIT as u16) != 0;
            if !opt_options_valid(raw, record.rdata, record.end) {
                return None;
            }
            (view.edns_options, view.edns_hop_options, view.edns_bad_ecs) =
                option_kinds(raw, record.rdata, record.end)?;
        } else {
            view.has_non_opt_additional = true;
            // SIG(0) is a SIG with "type covered" 0 (RFC 2931 §3); a SIG that
            // covers a real type is ordinary RRset data, not authentication.
            if record.rtype == TSIG_TYPE
                || (record.rtype == SIG0_TYPE && raw.get(record.rdata..record.rdata + 2) == Some(&[0, 0]))
            {
                view.signed = true;
            }
        }
        pos = record.end;
    }
    // Reject bytes that no counted section explains; otherwise a truncated
    // section could hide behind an exact-looking parse.
    if pos != raw.len() {
        return None;
    }
    Some(view)
}

/// Canonical cache-key bytes: lowercased qname wire, qtype BE, qclass BE and
/// one flags byte (bit0 DO, bit1 CD, bit2 query AD, bit3 EDNS present).
///
/// The caller must provide at least `MIN_CANONICAL_BUFFER` (260) bytes; a
/// longer result is refused rather than truncated.
pub fn canonical_key(view: &QueryView<'_>, out: &mut [u8]) -> Option<usize> {
    if out.len() < MIN_CANONICAL_BUFFER {
        return None;
    }
    let n = view.qname_len as usize;
    let total = n.checked_add(5)?;
    if total > out.len() {
        return None;
    }
    out[..n].copy_from_slice(&view.qname_lower[..n]);
    out[n..n + 2].copy_from_slice(&view.qtype.to_be_bytes());
    out[n + 2..n + 4].copy_from_slice(&view.qclass.to_be_bytes());
    let mut flags = 0u8;
    if view.edns_do {
        flags |= 1;
    }
    if view.cd {
        flags |= 1 << 1;
    }
    if view.flags & AD_BIT != 0 {
        flags |= 1 << 2;
    }
    if view.edns_present {
        flags |= 1 << 3;
    }
    out[n + 4] = flags;
    Some(total)
}

/// Writes the dot-separated, no-final-dot lowercased form of the question
/// name into `out` and returns its length. The root name writes zero bytes.
///
/// This is the form [`crate::rules::Rules::blocked_bytes`], [`crate::rules::rewrite`]
/// and the reverse-zone matcher expect. `qname_lower` is already lowercased
/// by the question parse, so the fast path needs no allocation here.
pub fn dotted_name(view: &QueryView<'_>, out: &mut [u8; MAX_NAME_LEN]) -> Option<usize> {
    dotted_target(&view.qname_lower[..view.qname_len as usize], out)
}

/// [`dotted_name`] for any uncompressed wire name, such as a CNAME target.
/// A dot inside a label is written as a backslash, a byte no rule or rewrite
/// name holds, so every `.` in the output separates whole labels:
/// `z\.w.ads.test` stays under `ads.test`, and the single label `ads\.test`
/// never reads as two.
pub fn dotted_target(wire: &[u8], out: &mut [u8; MAX_NAME_LEN]) -> Option<usize> {
    let mut pos = 0;
    let mut len = 0;
    loop {
        let label = *wire.get(pos)? as usize;
        if label == 0 {
            return Some(len);
        }
        if label > MAX_LABEL_LEN || pos + 1 + label > wire.len() {
            return None;
        }
        if len > 0 {
            *out.get_mut(len)? = b'.';
            len += 1;
        }
        let end = len.checked_add(label)?;
        let bytes = wire.get(pos + 1..pos + 1 + label)?;
        let dst = out.get_mut(len..end)?;
        dst.copy_from_slice(bytes);
        dst.iter_mut().filter(|byte| **byte == b'.').for_each(|byte| *byte = b'\\');
        len = end;
        pos += 1 + label;
    }
}

/// Copies the client's question name over the response's when both are the
/// same name (case-insensitively) of the same uncompressed length.
///
/// A response whose question is compressed keeps its original case: moving
/// the client's bytes would leave compression pointers pointing at the wrong
/// offsets, so this call is a no-op (`false`) for that case.
pub fn copy_question_case(client_raw: &[u8], response: &mut [u8]) -> bool {
    let len = {
        let Some(client) = read_question(client_raw) else {
            return false;
        };
        let Some(resp) = read_question(response) else {
            return false;
        };
        if client.compressed || resp.compressed || client.len != resp.len {
            return false;
        }
        let len = client.len as usize;
        if client.lower[..len] != resp.lower[..len] {
            return false;
        }
        len
    };
    let Some(src) = client_raw.get(HEADER_LEN..HEADER_LEN + len) else {
        return false;
    };
    let Some(dst) = response.get_mut(HEADER_LEN..HEADER_LEN + len) else {
        return false;
    };
    dst.copy_from_slice(src);
    true
}

/// Checks that a response answers this query: same ID and opcode, and the
/// same question name (case-insensitively), type and class.
pub fn question_matches(response_raw: &[u8], query: &QueryView<'_>) -> bool {
    question_matches_with(response_raw, query, true)
}

/// [`question_matches`] without the ID check, for DoH: the HTTP exchange
/// correlates the response, so its DNS ID is not meaningful (RFC 8484 §4.1).
pub fn question_matches_any_id(response_raw: &[u8], query: &QueryView<'_>) -> bool {
    question_matches_with(response_raw, query, false)
}

fn question_matches_with(response_raw: &[u8], query: &QueryView<'_>, check_id: bool) -> bool {
    let Some(head) = header(response_raw) else {
        return false;
    };
    if (check_id && head.id != query.id) || head.opcode != query.opcode {
        return false;
    }
    let Some(question) = read_question(response_raw) else {
        return false;
    };
    let n = query.qname_len as usize;
    question.qtype == query.qtype
        && question.qclass == query.qclass
        && question.len as usize == n
        && question.lower[..n] == query.qname_lower[..n]
}

/// Checks that a response echoes the exact question bytes the upstream
/// received: same ID and opcode, and an uncompressed question with identical
/// name bytes (case included), type and class.
///
/// This is the 0x20 validation used on plaintext fallback; a queried name
/// that was itself compressed falls back to case-insensitive matching at the
/// caller because its cache bytes are a pointer, not a name.
pub fn question_matches_exact(response_raw: &[u8], query: &QueryView<'_>) -> bool {
    let Some(head) = header(response_raw) else {
        return false;
    };
    if head.id != query.id || head.opcode != query.opcode {
        return false;
    }
    let Some(question) = read_question(response_raw) else {
        return false;
    };
    !question.compressed
        && question.qtype == query.qtype
        && question.qclass == query.qclass
        && question.name == query.qname_wire
}

/// One CNAME, DNAME or terminal-type record from the answer section.
struct ChainRecord {
    name: Box<[u8]>,
    rtype: u16,
    target: Option<Box<[u8]>>,
}

enum ChainNext {
    Next(Box<[u8]>),
    End,
    Ambiguous,
}

/// Offset of `parent` inside `name` at a label boundary. Both are encoded
/// names in the lowercased uncompressed form produced by `read_name`.
fn suffix_offset(parent: &[u8], name: &[u8]) -> Option<usize> {
    let mut offset = 0;
    loop {
        if name.get(offset..) == Some(parent) {
            return Some(offset);
        }
        let len = *name.get(offset)? as usize;
        if len == 0 || len > MAX_LABEL_LEN {
            return None;
        }
        offset = offset.checked_add(1 + len)?;
        if offset >= name.len() {
            return None;
        }
    }
}

/// Applies the DNAME nearest the root (RFC 6672: one below another is not
/// legal, and a lookup meets the upper one first) to `current`; two different
/// targets at that owner are ambiguous. A DNAME at its own owner does not apply.
fn dname_next(chain: &[ChainRecord], current: &[u8]) -> ChainNext {
    let mut best: Option<(usize, &[u8])> = None;
    let mut ambiguous = false;
    for record in chain {
        if record.rtype != DNAME_TYPE {
            continue;
        }
        let Some(offset) = suffix_offset(&record.name, current) else {
            continue;
        };
        if offset == 0 {
            continue;
        }
        let Some(target) = record.target.as_deref() else {
            continue;
        };
        match best {
            None => best = Some((offset, target)),
            Some((best_offset, best_target)) => {
                if offset > best_offset {
                    best = Some((offset, target));
                    ambiguous = false;
                } else if offset == best_offset && target != best_target {
                    ambiguous = true;
                }
            }
        }
    }
    if ambiguous {
        return ChainNext::Ambiguous;
    }
    let Some((prefix_len, target)) = best else {
        return ChainNext::End;
    };
    let mut next = Vec::with_capacity(prefix_len + target.len());
    next.extend_from_slice(&current[..prefix_len]);
    next.extend_from_slice(target);
    if next.len() > MAX_NAME_LEN {
        return ChainNext::Ambiguous;
    }
    ChainNext::Next(next.into_boxed_slice())
}

/// `name` is `zone` or below it; both are uncompressed lowercase wire names.
fn zone_of(zone: &[u8], name: &[u8]) -> bool {
    let mut pos = 0;
    while pos < name.len() {
        if name[pos..] == *zone {
            return true;
        }
        pos += 1 + name[pos] as usize;
    }
    false
}

/// Classifies a response as terminal for `qtype`, following a bounded
/// CNAME/DNAME chain from the lowercased query name.
///
/// Terminal means an NXDOMAIN with an authority SOA, a positive answer of the
/// query type reachable through the chain, or a NOERROR NODATA with an
/// authority SOA. Referrals, SOA-less negatives, chains that only carry
/// CNAMEs, loops and other rcodes are not terminal. `None` means the packet
/// is malformed or is not a response, or it contradicts itself: an
/// NXDOMAIN whose Answer holds data other than aliases at the query name or
/// anywhere on its alias chain, or a NOERROR whose chain ends at a name that
/// holds only other types.
pub fn terminal_answer(raw: &[u8], qname_lower: &[u8], qtype: u16) -> Option<bool> {
    let head = header(raw)?;
    if !head.is_response() {
        return None;
    }
    let question = read_question(raw)?;
    let n = question.len as usize;
    if question.qtype != qtype || question.lower[..n] != *qname_lower {
        return Some(false);
    }
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = question.end.checked_add(4)?;
    if pos > raw.len() {
        return None;
    }
    let mut chain = Vec::new();
    // (owner, type, covered type of an RRSIG) of every Answer record in the
    // question's class that is not an alias.
    let mut data: Vec<(Box<[u8]>, u16, u16)> = Vec::new();
    let mut aliases = 0usize;
    for _ in 0..head.ancount {
        let record = record_header(raw, pos, &mut scratch)?;
        if record.class == question.qclass && record.rtype != CNAME_TYPE && record.rtype != DNAME_TYPE {
            let covered = if record.rtype == RRSIG_TYPE { be16(raw, record.rdata).unwrap_or(0) } else { 0 };
            data.push((scratch[..record.name_len as usize].into(), record.rtype, covered));
        }
        // Only records in the question's class can answer it (RFC 1034 §3.6).
        if record.class == question.qclass
            && (record.rtype == CNAME_TYPE || record.rtype == DNAME_TYPE || record.rtype == qtype)
        {
            // The bound limits CNAME/DNAME chain work, not the number of
            // members in one RRset: a legitimate 100-record answer is still a
            // terminal answer.
            if record.rtype == CNAME_TYPE || record.rtype == DNAME_TYPE {
                if aliases >= MAX_CHAIN_RECORDS {
                    return Some(false);
                }
                aliases += 1;
            }
            let name: Box<[u8]> = scratch[..record.name_len as usize].into();
            let target = if record.rtype == CNAME_TYPE || record.rtype == DNAME_TYPE {
                let info = read_name(raw, record.rdata, &mut scratch)?;
                // The target must be encoded entirely inside this RDATA.
                if info.end != record.end {
                    return None;
                }
                Some(scratch[..info.len as usize].into())
            } else {
                None
            };
            chain.push(ChainRecord { name, rtype: record.rtype, target });
        }
        pos = record.end;
    }
    // A negative is usable only with an SOA of the question's class whose
    // owner is at or above the name or a chain target (RFC 2308 §5).
    let mut soa = false;
    for _ in 0..head.nscount {
        let record = record_header(raw, pos, &mut scratch)?;
        if record.rtype == SOA_TYPE && record.class == question.qclass {
            let zone = &scratch[..record.name_len as usize];
            soa |= zone_of(zone, qname_lower)
                || chain.iter().filter_map(|r| r.target.as_deref()).any(|target| zone_of(zone, target));
        }
        pos = record.end;
    }
    let rcode = head.flags & 0x000f;
    if rcode == 3 {
        // NXDOMAIN says no name exists, so no data may sit at the query
        // name or at any name its alias chain passes through. An RRSIG over an
        // alias is alias data.
        let mut current: Box<[u8]> = qname_lower.into();
        let mut names: Vec<Box<[u8]>> = Vec::new();
        for _ in 0..MAX_CHAIN_STEPS {
            if names.contains(&current) {
                break;
            }
            names.push(current.clone());
            let cname =
                chain.iter().find(|r| r.rtype == CNAME_TYPE && r.name == current).and_then(|r| r.target.clone());
            match cname {
                Some(target) => current = target,
                None => match dname_next(&chain, &current) {
                    ChainNext::Next(target) => current = target,
                    _ => break,
                },
            }
        }
        let alias = |rtype: u16, covered: u16| {
            matches!(rtype, CNAME_TYPE | DNAME_TYPE)
                || (rtype == RRSIG_TYPE && matches!(covered, CNAME_TYPE | DNAME_TYPE))
        };
        if data.iter().any(|(owner, rtype, covered)| names.contains(owner) && !alias(*rtype, *covered)) {
            return None;
        }
        return Some(soa);
    }
    if rcode != 0 {
        return Some(false);
    }
    let mut current: Box<[u8]> = qname_lower.into();
    let mut seen: Vec<Box<[u8]>> = Vec::new();
    for _ in 0..MAX_CHAIN_STEPS {
        if seen.iter().any(|seen| seen.as_ref() == current.as_ref()) {
            return Some(false);
        }
        seen.push(current.clone());
        let mut terminal_qtype = false;
        let mut cname: Option<Box<[u8]>> = None;
        let mut cname_conflict = false;
        for record in &chain {
            if record.name.as_ref() != current.as_ref() {
                continue;
            }
            if record.rtype == qtype {
                terminal_qtype = true;
            }
            if record.rtype == CNAME_TYPE {
                if let Some(target) = &record.target {
                    match &cname {
                        None => cname = Some(target.clone()),
                        Some(existing) if existing.as_ref() != target.as_ref() => cname_conflict = true,
                        Some(_) => {}
                    }
                }
            }
        }
        if cname_conflict {
            return Some(false);
        }
        if terminal_qtype {
            // RFC 2181 §10.1: a CNAME owner has no other data. CNAME plus the
            // queried type at one owner is ambiguous, so never cacheable.
            return Some(qtype == CNAME_TYPE || cname.is_none());
        }
        if let Some(target) = cname {
            current = target;
            continue;
        }
        match dname_next(&chain, &current) {
            ChainNext::Next(target) => current = target,
            ChainNext::End => {
                // The chain ends at a name that holds only other types
                // (an RRSIG over the queried type or an alias excepted). ANY
                // asks for every type.
                let other = |(owner, rtype, covered): &(Box<[u8]>, u16, u16)| {
                    *owner == current
                        && *rtype != qtype
                        && !(*rtype == RRSIG_TYPE && (*covered == qtype || matches!(*covered, CNAME_TYPE | DNAME_TYPE)))
                };
                if qtype != 255 && data.iter().any(other) {
                    return None;
                }
                return Some(soa);
            }
            ChainNext::Ambiguous => return Some(false),
        }
    }
    Some(false)
}

/// Calls `visit` with every name an Answer section can lead a client to, in
/// the question's class: each record's owner and each CNAME/DNAME target, as
/// lowercase uncompressed wire names, skipping `qname_lower` itself and an
/// owner repeated by the previous record. It is a flat pass: it does not follow
/// the chain, so a loop, a conflict, an overlong chain or a missing link hides
/// nothing. `visit` returns true to stop. `None` means the packet is malformed
/// (names seen before the damage were still visited).
pub fn answer_names(raw: &[u8], qname_lower: &[u8], visit: &mut impl FnMut(&[u8]) -> bool) -> Option<()> {
    let head = header(raw)?;
    let question = read_question(raw)?;
    let mut owner = [0u8; MAX_NAME_LEN];
    let mut last_owner = [0u8; MAX_NAME_LEN];
    let mut last = 0usize;
    let mut pos = question.end.checked_add(4)?;
    for _ in 0..head.ancount {
        let record = record_header(raw, pos, &mut owner)?;
        pos = record.end;
        if record.class != question.qclass {
            continue;
        }
        let name = &owner[..record.name_len as usize];
        if name != qname_lower && !(last == name.len() && last_owner[..last] == *name) {
            if visit(name) {
                return Some(());
            }
            last_owner[..name.len()].copy_from_slice(name);
            last = name.len();
        }
        if record.rtype == CNAME_TYPE || record.rtype == DNAME_TYPE {
            let mut buf = [0u8; MAX_NAME_LEN];
            let info = read_name(raw, record.rdata, &mut buf)?;
            // The target must be encoded entirely inside this RDATA.
            if info.end != record.end {
                return None;
            }
            let name = &buf[..info.len as usize];
            if name != qname_lower && visit(name) {
                return Some(());
            }
        }
    }
    Some(())
}

/// (section 0..3, lowercased owner, type, CNAME/DNAME target)
type ScrubRecord = (u8, Box<[u8]>, u16, Option<Box<[u8]>>);

const NS_TYPE: u16 = 2;
const NSEC_TYPE: u16 = 47;
const NSEC3_TYPE: u16 = 50;
const RRSIG_TYPE: u16 = 46;

/// Scrubs a validated reply that arrived over the unauthenticated plaintext
/// fallback, where an off-path attacker can add records (compare RFC 5452 §6,
/// accepting only in-domain records).
///
/// * An Answer RR whose owner is off the question / CNAME / DNAME chain makes
///   the reply invalid (`None`).
/// * Authority keeps only SOA, NS, NSEC, NSEC3 and RRSIG, and only owners at
///   or above a chain name; NSEC/NSEC3/RRSIG owners may also sit below a kept
///   SOA/NS owner (a denial proof names its neighbours, not the query).
/// * Additional keeps only OPT.
///
/// `Some(None)` means nothing needed removing. `Some(Some(bytes))` is the
/// rewritten, uncompressed message. DoH replies are not scrubbed: that transport is authenticated.
pub fn scrub_plain_reply(raw: &[u8]) -> Option<Option<Vec<u8>>> {
    let head = header(raw)?;
    let question = read_question(raw)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = question.end.checked_add(4)?;
    let mut records: Vec<ScrubRecord> = Vec::new();
    let sections = [head.ancount, head.nscount, head.arcount];
    for (section, &count) in sections.iter().enumerate() {
        for _ in 0..count {
            let record = record_header(raw, pos, &mut scratch)?;
            let owner: Box<[u8]> = scratch[..record.name_len as usize].into();
            let target = if section == 0 && (record.rtype == CNAME_TYPE || record.rtype == DNAME_TYPE) {
                let info = read_name(raw, record.rdata, &mut scratch)?;
                Some(scratch[..info.len as usize].into())
            } else {
                None
            };
            records.push((section as u8, owner, record.rtype, target));
            pos = record.end;
        }
    }
    let mut chain: Vec<Box<[u8]>> = vec![question.lower[..question.len as usize].into()];
    for _ in 0..MAX_CHAIN_STEPS {
        let before = chain.len();
        for (section, owner, rtype, target) in &records {
            let Some(target) = target else { continue };
            if *section != 0 {
                continue;
            }
            let applies = if *rtype == CNAME_TYPE {
                chain.contains(owner)
            } else {
                chain.iter().any(|name| suffix_offset(owner, name).is_some_and(|offset| offset > 0))
            };
            if applies && !chain.contains(target) {
                chain.push(target.clone());
                // Bound the work inside the pass too: one pass over an
                // in-order chain would otherwise collect every alias, each
                // scan of the chain costing its whole length. Aliases past
                // the bound stay off the chain, so their owners invalidate
                // the reply.
                if chain.len() > MAX_CHAIN_RECORDS {
                    break;
                }
            }
        }
        if chain.len() == before || chain.len() > MAX_CHAIN_RECORDS {
            break;
        }
    }
    let above = |owner: &[u8]| chain.iter().any(|name| suffix_offset(owner, name).is_some());
    // A set, so a denial owner is checked by looking up each of its at most
    // 128 ancestors rather than against every SOA and NS owner in turn.
    let zones: HashSet<&[u8]> = records
        .iter()
        .filter(|(section, owner, rtype, _)| *section == 1 && matches!(*rtype, SOA_TYPE | NS_TYPE) && above(owner))
        .map(|(_, owner, ..)| owner.as_ref())
        .collect();
    let under_zone = |owner: &[u8]| {
        let mut offset = 0;
        while let Some(&len) = owner.get(offset) {
            if zones.contains(&owner[offset..]) {
                return true;
            }
            if len == 0 {
                return false;
            }
            offset += 1 + len as usize;
        }
        false
    };
    let mut keep = Vec::with_capacity(records.len());
    for (section, owner, rtype, _) in &records {
        let ok = match section {
            // An Answer owner is on the chain; only a DNAME (or its RRSIG)
            // may sit above it.
            0 => {
                let ok = chain.contains(owner) || (matches!(*rtype, DNAME_TYPE | RRSIG_TYPE) && above(owner));
                if !ok {
                    return None;
                }
                true
            }
            1 => match *rtype {
                SOA_TYPE | NS_TYPE => above(owner),
                NSEC_TYPE | NSEC3_TYPE | RRSIG_TYPE => above(owner) || under_zone(owner),
                _ => false,
            },
            _ => *rtype == OPT_TYPE,
        };
        keep.push(ok);
    }
    if keep.iter().all(|&ok| ok) {
        return Some(None);
    }
    let expanded = expand_names(raw, false)?;
    let ehead = header(&expanded)?;
    let mut pos = HEADER_LEN;
    for _ in 0..ehead.qdcount {
        pos = read_name_with(&expanded, pos, &mut scratch, true, true)?.end.checked_add(4)?;
    }
    let mut out = expanded[..pos].to_vec();
    let mut counts = [0u16; 3];
    for (&(section, ..), &ok) in records.iter().zip(&keep) {
        let record = record_header_with(&expanded, pos, &mut scratch, true)?;
        if ok {
            out.extend_from_slice(&expanded[pos..record.end]);
            counts[section as usize] += 1;
        }
        pos = record.end;
    }
    for (i, count) in counts.iter().enumerate() {
        out[6 + 2 * i..8 + 2 * i].copy_from_slice(&count.to_be_bytes());
    }
    Some(Some(out))
}

/// Sets the EDNS DO bit, appending a root-name OPT (payload 1232) when the
/// packet has none. The result is bounded to the 65535-byte DNS maximum.
/// Returns `None` for an input over that bound or for a type-41 record whose
/// owner is not the root.
pub fn set_do_bit(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() > u16::MAX as usize {
        return None;
    }
    let head = header(raw)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        let name = read_name(raw, pos, &mut scratch)?;
        pos = name.end.checked_add(4)?;
        if pos > raw.len() {
            return None;
        }
    }
    let ordinary = head.ancount as usize + head.nscount as usize;
    for i in 0..ordinary + head.arcount as usize {
        let record = record_header(raw, pos, &mut scratch)?;
        if i >= ordinary && record.rtype == OPT_TYPE {
            if !record.root_name {
                return None;
            }
            let mut out = raw.to_vec();
            let ttl = record.ttl | DO_BIT;
            out.get_mut(record.ttl_off..record.ttl_off + 4)?.copy_from_slice(&ttl.to_be_bytes());
            return Some(out);
        }
        pos = record.end;
    }
    if pos != raw.len() || raw.len().checked_add(11)? > u16::MAX as usize {
        return None;
    }
    let arcount = head.arcount.checked_add(1)?;
    let mut out = Vec::with_capacity(raw.len() + 11);
    out.extend_from_slice(raw);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    // Root owner, TYPE 41, CLASS 1232, TTL 0x00008000 (DO), RDLEN 0.
    out.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]);
    Some(out)
}

/// Clears the AD bit in a response header. Everything else is left untouched.
/// RFC 1035 §4.1.1: a client reply carries the client's RD, RA=1 (this
/// service recurses) and a zero reserved Z bit, whatever the upstream or the
/// cached copy said.
pub fn normalize_rd_ra(raw: &mut [u8], rd: bool) {
    if raw.len() >= 4 {
        raw[2] = (raw[2] & !0x01) | u8::from(rd);
        raw[3] = (raw[3] | 0x80) & !0x40;
    }
}

/// Clears AA: a forwarder never claims authority for relayed upstream data
/// (RFC 1035 §4.1.1; unbound and dnsproxy do the same).
pub fn clear_aa(raw: &mut [u8]) {
    if let Some(flags) = raw.get_mut(2) {
        *flags &= !0x04;
    }
}

pub fn clear_ad(raw: &mut [u8]) {
    if let Some(flags) = raw.get_mut(3) {
        *flags &= !0x20;
    }
}

/// Sets the response CD bit to the client's value (RFC 4035 §3.2.2).
pub fn set_cd(raw: &mut [u8], cd: bool) {
    if let Some(flags) = raw.get_mut(3) {
        if cd {
            *flags |= 0x10;
        } else {
            *flags &= !0x10;
        }
    }
}

/// Rebuilds a response for the client: removes DNSSEC record types (unless
/// the query itself asked for that type, RFC 4035 §3.2.1), drops OPT for
/// non-EDNS clients and clears the OPT DO bit for EDNS clients that did not
/// set DO. AD and the response code are preserved. Slow path only.
///
/// hickory rebuilds the message and serializes the question name in
/// lowercase, so the client's 0x20 case is lost; callers must apply
/// [`copy_question_case`] afterwards (the server already does).
pub fn strip_response_for_client(
    response_raw: &[u8],
    client_edns: bool,
    client_do: bool,
    strip_dnssec: bool,
    qtype: u16,
) -> Option<Vec<u8>> {
    let mut msg = Message::from_vec(response_raw).ok()?;
    if strip_dnssec {
        fn keep(record: &Record, qtype: u16) -> bool {
            let rtype = u16::from(record.record_type());
            !is_dnssec_type(rtype) || rtype == qtype
        }
        msg.answers.retain(|record| keep(record, qtype));
        msg.authorities.retain(|record| keep(record, qtype));
        msg.additionals.retain(|record| keep(record, qtype));
    }
    match msg.edns.as_mut() {
        None => {}
        Some(_) if !client_edns => msg.edns = None,
        // Do not advertise DNSSEC material the client never asked for, and
        // never echo a DO bit the client did not send.
        Some(edns) if !client_do => {
            edns.set_dnssec_ok(false);
        }
        Some(_) => {}
    }
    msg.to_vec().ok()
}

/// Writes the policy block answer for `view` into `out`, replacing its
/// contents: NXDOMAIN with RA, the query's RD and CD, the question as the
/// client sent it, one authority record `<qname> 10 IN SOA . . 1 3600 600
/// 86400 10` (the negative lifetime is the SOA TTL and MINIMUM, RFC 2308 §3)
/// and, for an EDNS query, an OPT advertising 1232 bytes that echoes DO
/// (RFC 6891 §6.1.1, §6.2.3). This is byte for byte what the parsed path
/// builds with hickory, including the pointer to the question name for the
/// SOA owner (RFC 1035 §4.1.4).
///
/// The question name must be uncompressed (`qname_compressed` false). The
/// result is at most 12 + 259 + 34 + 11 = 316 bytes, under the 512-byte UDP
/// floor, so it never needs truncation. With enough capacity in `out` it does
/// not allocate.
pub fn blocked_response_into(view: &QueryView<'_>, out: &mut Vec<u8>) {
    let flags = QR_BIT | RA_BIT | (view.flags & (RD_BIT | CD_BIT)) | 3;
    out.clear();
    out.extend_from_slice(&view.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    // QDCOUNT 1, ANCOUNT 0, NSCOUNT 1, ARCOUNT 1 with EDNS.
    out.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, u8::from(view.edns_present)]);
    out.extend_from_slice(view.qname_wire);
    out.extend_from_slice(&view.qtype.to_be_bytes());
    out.extend_from_slice(&view.qclass.to_be_bytes());
    out.extend_from_slice(&[
        0xc0, 0x0c, // owner: pointer to the question name at offset 12
        0, 6, 0, 1, // SOA, IN
        0, 0, 0, 10, // TTL 10
        0, 22, // RDLENGTH
        0, 0, // MNAME and RNAME: the root
        0, 0, 0, 1, // SERIAL
        0, 0, 0x0e, 0x10, // REFRESH 3600
        0, 0, 0x02, 0x58, // RETRY 600
        0, 1, 0x51, 0x80, // EXPIRE 86400
        0, 0, 0, 10, // MINIMUM 10
    ]);
    if view.edns_present {
        // Root owner, TYPE 41, CLASS = payload 1232, TTL = extended RCODE 0,
        // version 0 and the DO bit, RDLEN 0.
        out.extend_from_slice(&[0, 0, 41, 0x04, 0xd0]);
        out.extend_from_slice(&(if view.edns_do { DO_BIT } else { 0 }).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
    }
}

/// Builds a minimal error response: echoes the ID, opcode, RD and CD bits and
/// (when it parses) the question. A compressed question name is not echoed
/// (the reply would have to decompress it, which could amplify a small
/// request) and the reply has QDCOUNT 0. A valid request OPT is echoed with
/// its payload clamped to 512..=1232, version 0, DO clear and, for extended
/// RCODEs such as BADVERS, the high bits. A malformed request OPT is omitted.
pub fn minimal_error_response(raw_request: &[u8], rcode: u16) -> Option<Vec<u8>> {
    let head = header(raw_request)?;
    // Only an uncompressed question can be echoed without inflating the reply.
    let question = if head.qdcount == 1 { read_question(raw_request).filter(|q| !q.compressed) } else { None };
    // Only a fully well-formed request has an OPT we can safely echo.
    let view = parse_query(raw_request);
    // A malformed OPT still means the client speaks EDNS: answer with a safe
    // OPT (RFC 6891 §7) rather than none.
    let request_edns = view.as_ref().map_or_else(|| opt_version(raw_request).is_some(), |v| v.edns_present);
    let client_do = view.as_ref().is_some_and(|v| v.edns_present && v.edns_do);
    let extended = (rcode >> 4) as u8;
    let include_opt = request_edns || extended > 0;
    // RFC 6891 §6.2.3: a response advertises the responder's own payload
    // size, not an echo of the client's.
    let payload: u16 = 1232;
    let mut flags = QR_BIT | RA_BIT | (head.flags & (RD_BIT | CD_BIT)) | ((head.opcode as u16) << 11);
    flags |= rcode & 0x000f;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&head.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(question.is_some() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // ANCOUNT, NSCOUNT
    out.extend_from_slice(&(include_opt as u16).to_be_bytes());
    if let Some(question) = question {
        out.extend_from_slice(question.name);
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&question.qclass.to_be_bytes());
    }
    if include_opt {
        // Root owner, TYPE 41, CLASS = payload, TTL = extended RCODE with
        // version 0 and DO clear, RDLEN 0.
        out.extend_from_slice(&[0, 0, 41]);
        out.extend_from_slice(&payload.to_be_bytes());
        out.extend_from_slice(&(((extended as u32) << 24) | if client_do { DO_BIT } else { 0 }).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
    }
    Some(out)
}

/// The EDNS version of the first type-41 record in the additional section,
/// however malformed its owner or options. Stops quietly at the first
/// unreadable record: only used to shape error replies (safe OPT, BADVERS).
pub fn opt_version(raw: &[u8]) -> Option<u8> {
    let head = header(raw)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        pos = read_name(raw, pos, &mut scratch)?.end + 4;
    }
    let ordinary = head.ancount as usize + head.nscount as usize;
    for i in 0..ordinary + head.arcount as usize {
        let record = record_header(raw, pos, &mut scratch)?;
        if i >= ordinary && record.rtype == OPT_TYPE {
            return Some((record.ttl >> 16) as u8);
        }
        pos = record.end;
    }
    None
}

/// Rebuilds a UDP truncation reply from the parsed query and a cached answer
/// without parsing either: the client's ID and question, QR/RA/RD/CD and the
/// full answer's RCODE, TC=1, no answers or authority records, AD clear, and
/// an OPT advertising `payload` (our own size) only when the client sent one. Slow-path
/// `reply(&q, rcode)` plus `metadata.truncation` produces the same bytes.
///
/// Only the low four RCODE bits of `answer` are copied. That is complete
/// today: the cache stores only header RCODE 0 (NOERROR) and 3 (NXDOMAIN)
/// responses (`cache::Cache::normalize` / `wire::terminal_answer`), so an
/// extended RCODE from an OPT cannot reach this builder.
pub fn truncated_response(view: &QueryView<'_>, answer: &[u8], payload: u16) -> Option<Vec<u8>> {
    let answer_flags = header(answer)?.flags;
    let name = if view.qname_compressed { &view.qname_lower[..view.qname_len as usize] } else { view.qname_wire };
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 4 + 11 * usize::from(view.edns_present));
    build_truncated(view, answer_flags, payload, &mut out);
    Some(out)
}

/// [`truncated_response`] into the caller's buffer: clears `out` and writes
/// the reply using its existing capacity, so a warm buffer makes no allocator
/// call. It allocates only if `out` has to grow.
pub fn truncated_response_into(view: &QueryView<'_>, answer: &[u8], payload: u16, out: &mut Vec<u8>) -> Option<()> {
    let answer_flags = header(answer)?.flags;
    out.clear();
    build_truncated(view, answer_flags, payload, out);
    Some(())
}

fn build_truncated(view: &QueryView<'_>, answer_flags: u16, payload: u16, out: &mut Vec<u8>) {
    // The client's question name bytes carry its 0x20 case. A compressed
    // question has no pointer-free bytes to copy, so echo its decompressed
    // name instead (the fast path never takes one).
    let name = if view.qname_compressed { &view.qname_lower[..view.qname_len as usize] } else { view.qname_wire };
    let mut flags = QR_BIT | TC_BIT | RA_BIT | ((view.opcode as u16) << 11) | (answer_flags & 0x000f);
    if view.rd {
        flags |= RD_BIT;
    }
    if view.cd {
        flags |= CD_BIT;
    }
    out.extend_from_slice(&view.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // ANCOUNT, NSCOUNT
    out.extend_from_slice(&u16::from(view.edns_present).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&view.qtype.to_be_bytes());
    out.extend_from_slice(&view.qclass.to_be_bytes());
    if view.edns_present {
        // Root owner, TYPE 41, CLASS = our payload size, TTL = extended RCODE 0,
        // version 0 and the client's DO bit, RDLEN 0.
        let edns_flags: u32 = if view.edns_do { DO_BIT } else { 0 };
        out.extend_from_slice(&[0, 0, OPT_TYPE as u8]);
        out.extend_from_slice(&payload.to_be_bytes());
        out.extend_from_slice(&edns_flags.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
    }
}

/// Walks the wire, leaving compression pointers, DNSSEC and unknown RDATA
/// untouched. Returns the offset of every record TTL (OPT TTLs excluded).
fn skip_name(raw: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let n = *raw.get(*pos)?;
        *pos += 1;
        if n & 0xc0 == 0xc0 {
            raw.get(*pos)?;
            *pos += 1;
            return Some(());
        }
        if n & 0xc0 != 0 {
            return None;
        }
        if n == 0 {
            return Some(());
        }
        *pos += n as usize;
        if *pos > raw.len() {
            return None;
        }
    }
}

/// TTL field offsets (in wire order) and the first SOA TTL offset found in
/// the authority section.
pub(crate) struct TtlFields {
    pub offsets: Box<[u16]>,
    pub soa: Option<u16>,
}

pub(crate) fn ttl_fields(raw: &[u8]) -> Option<TtlFields> {
    let field = |i| Some(u16::from_be_bytes([*raw.get(i)?, *raw.get(i + 1)?]) as usize);
    let mut pos = 12;
    for _ in 0..field(4)? {
        skip_name(raw, &mut pos)?;
        pos = pos.checked_add(4)?;
    }
    let counts = [field(6)?, field(8)?, field(10)?];
    let mut offsets = Vec::with_capacity(counts.iter().sum());
    let mut soa = None;
    for (section, &count) in counts.iter().enumerate() {
        for _ in 0..count {
            skip_name(raw, &mut pos)?;
            let typ = field(pos)?;
            let ttl_off = pos.checked_add(4)?;
            let len = field(pos.checked_add(8)?)?;
            if typ != OPT_TYPE as usize {
                let off = u16::try_from(ttl_off).ok()?;
                offsets.push(off);
                // The negative-cache SOA lives in the authority section.
                if section == 1 && typ == 6 && soa.is_none() {
                    soa = Some(off);
                }
            }
            pos = ttl_off.checked_add(6)?.checked_add(len)?;
            if pos > raw.len() {
                return None;
            }
        }
    }
    Some(TtlFields { offsets: offsets.into_boxed_slice(), soa })
}

/// Caps every record TTL at [`MAX_TTL`] ([`rfc8767_ttl`]). Returns false when
/// the TTL walk fails; nothing is changed then.
pub fn cap_ttls(raw: &mut [u8]) -> bool {
    let Some(fields) = ttl_fields(raw) else { return false };
    for &off in fields.offsets.iter() {
        let p = off as usize;
        let ttl = u32::from_be_bytes([raw[p], raw[p + 1], raw[p + 2], raw[p + 3]]);
        raw[p..p + 4].copy_from_slice(&rfc8767_ttl(ttl).to_be_bytes());
    }
    true
}

pub fn ttl_offsets(raw: &[u8]) -> Option<Box<[u16]>> {
    ttl_fields(raw).map(|fields| fields.offsets)
}

/// RFC 2181 §5.2: every RR in a set carries the set's lowest TTL, capped at
/// the profile's [`MAX_TTL`].
///
/// The parsed message and the wire offsets are paired in document order. If
/// they do not line up (for example a record kind hickory consumes on its
/// own), nothing is changed.
pub fn normalize_rrset_ttls(msg: &Message, raw: &mut [u8]) -> bool {
    let Some(fields) = ttl_fields(raw) else { return false };
    let records: Vec<&Record> =
        msg.answers.iter().chain(msg.authorities.iter()).chain(msg.additionals.iter()).collect();
    if records.len() != fields.offsets.len() {
        return false;
    }
    // (owner, type, class) -> lowest TTL in that RRset.
    let mut lowest: HashMap<(&Name, u16, u16), u32> = HashMap::with_capacity(records.len());
    for record in &records {
        let key = (&record.name, u16::from(record.record_type()), u16::from(record.dns_class));
        lowest
            .entry(key)
            .and_modify(|ttl| *ttl = (*ttl).min(rfc8767_ttl(record.ttl)))
            .or_insert(rfc8767_ttl(record.ttl).min(MAX_TTL));
    }
    for (record, &offset) in records.iter().zip(fields.offsets.iter()) {
        let key = (&record.name, u16::from(record.record_type()), u16::from(record.dns_class));
        let Some(ttl) = lowest.get(&key) else { return false };
        let p = offset as usize;
        let Some(field) = raw.get_mut(p..p + 4) else { return false };
        field.copy_from_slice(&ttl.to_be_bytes());
    }
    true
}

/// One field of a fixed RDATA layout.
#[derive(Clone, Copy)]
enum Field {
    /// A domain name, possibly compressed on input.
    Name,
    /// A fixed number of opaque bytes.
    Bytes(usize),
    /// A length-prefixed character string.
    Chars,
    /// Everything left in RDATA.
    Rest,
    /// One or more character strings filling the RDATA.
    CharsRest,
}

use Field::{Bytes, Chars, CharsRest, Name as N, Rest};

/// RDATA layouts whose structure this forwarder validates (RFC 1035 and the
/// legacy RFC 3597 §4 types). Types without an entry are opaque.
fn rdata_layout(rtype: u16, class: u16) -> Option<&'static [Field]> {
    Some(match rtype {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 39 => &[N],
        14 | 17 => &[N, N],
        6 => &[N, N, Bytes(20)],
        15 | 18 | 21 | 36 => &[Bytes(2), N],
        26 => &[Bytes(2), N, N],
        24 => &[Bytes(18), N, Rest],
        30 => &[N, Rest],
        33 => &[Bytes(6), N],
        35 => &[Bytes(4), Chars, Chars, Chars, N],
        // WKS is an IN-class format: address, protocol, bitmap.
        11 if class == 1 => &[Bytes(5), Rest],
        1 if class == 1 => &[Bytes(4)],
        28 if class == 1 => &[Bytes(16)],
        13 => &[Chars, Chars],
        16 => &[CharsRest],
        _ => return None,
    })
}

/// Types whose embedded names RFC 3597 §4 forbids compressing when sent.
const LEGACY_NAME_TYPES: [u16; 8] = [17, 18, 21, 24, 26, 30, 33, 35];

/// Walks one RDATA against its layout. `None` means it does not fit exactly
/// in `start..end`; `Some(true)` means a name used a compression pointer.
/// With `out`, the RDATA is rewritten with every name literal.
fn walk_rdata(
    raw: &[u8],
    layout: &[Field],
    start: usize,
    end: usize,
    scratch: &mut [u8; MAX_NAME_LEN],
    mut out: Option<&mut Vec<u8>>,
) -> Option<bool> {
    let mut pos = start;
    let mut pointer = false;
    for field in layout {
        match *field {
            Field::Name => {
                let name = read_name_with(raw, pos, scratch, false, true)?;
                if name.end > end {
                    return None;
                }
                pointer |= name.compressed;
                if let Some(out) = out.as_deref_mut() {
                    out.extend_from_slice(&scratch[..name.len as usize]);
                }
                pos = name.end;
            }
            Field::Bytes(n) => {
                let field = raw.get(pos..pos.checked_add(n)?).filter(|_| pos + n <= end)?;
                if let Some(out) = out.as_deref_mut() {
                    out.extend_from_slice(field);
                }
                pos += n;
            }
            Field::Chars => {
                let n = *raw.get(pos).filter(|_| pos < end)? as usize + 1;
                let field = raw.get(pos..pos.checked_add(n)?).filter(|_| pos + n <= end)?;
                if let Some(out) = out.as_deref_mut() {
                    out.extend_from_slice(field);
                }
                pos += n;
            }
            Field::CharsRest => {
                if pos >= end {
                    return None;
                }
                while pos < end {
                    let n = *raw.get(pos)? as usize + 1;
                    let field = raw.get(pos..pos.checked_add(n)?).filter(|_| pos + n <= end)?;
                    if let Some(out) = out.as_deref_mut() {
                        out.extend_from_slice(field);
                    }
                    pos += n;
                }
            }
            Field::Rest => {
                if let Some(out) = out.as_deref_mut() {
                    out.extend_from_slice(&raw[pos..end]);
                }
                pos = end;
            }
        }
    }
    (pos == end).then_some(pointer)
}

/// Forbidden content (RFC 6895 §3.1; the TuDoor attack class): a structurally valid upstream message whose
/// Answer or Authority holds a record no server may send there: an OPT or a
/// Q-TYPE or meta-TYPE (128-255: TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY and
/// the unassigned range), or whose Answer holds a class other than the
/// question's. Such a message is invalid, so
/// a plain attempt that receives one fails at once. A malformed message is not
/// this: it is `false`. A foreign-class Authority record is only ignored
/// (`terminal_answer`: such an SOA makes a negative unusable).
pub fn forbidden_record(raw: &[u8]) -> bool {
    let Some(head) = header(raw) else { return false };
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    let mut class = None;
    for _ in 0..head.qdcount {
        let Some(end) = read_name_with(raw, pos, &mut scratch, true, true).and_then(|name| name.end.checked_add(4))
        else {
            return false;
        };
        class = be16(raw, end.wrapping_sub(2));
        pos = end;
    }
    let class = class.filter(|_| head.qdcount == 1);
    for i in 0..head.ancount as usize + head.nscount as usize {
        let Some(record) = record_header_with(raw, pos, &mut scratch, true) else { return false };
        let foreign = i < head.ancount as usize && class.is_some_and(|c| c != record.class);
        if record.rtype == OPT_TYPE || (128..=255).contains(&record.rtype) || foreign {
            return true;
        }
        pos = record.end;
    }
    false
}

/// Validates an upstream response's whole structure and returns the bytes to
/// relay. `None` means invalid wire: a name, count, RDLENGTH or known RDATA
/// layout that does not hold (RFC 1035) or a record [`forbidden_record`]
/// names, so the attempt must fail rather than relay it. Valid bytes pass
/// through untouched, except that a compressed name inside a legacy-type RDATA (RFC 3597 §4) makes the message
/// be rewritten with every name literal.
pub fn normalize_upstream(raw: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    let head = header(raw)?;
    if forbidden_record(raw) {
        return None;
    }
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        pos = read_name_with(raw, pos, &mut scratch, true, true)?.end.checked_add(4)?;
        if pos > raw.len() {
            return None;
        }
    }
    let mut rewrite = false;
    let mut seen_opt = false;
    let ordinary = head.ancount as usize + head.nscount as usize;
    for i in 0..ordinary + head.arcount as usize {
        let record = record_header_with(raw, pos, &mut scratch, true)?;
        if record.rtype == OPT_TYPE {
            // RFC 6891 §6.1.1: one OPT, root-owned, in Additional, with whole
            // options and a version this forwarder speaks. Anything else is
            // invalid upstream data, never relayed or cached.
            // A version other than 0 is a failed attempt. The extended RCODE
            // byte is kept for the client (RFC 6891 §6.1.3); `unusable_rcode` ends
            // the hop-scoped BADVERS/BADCOOKIE attempts.
            if seen_opt
                || i < ordinary
                || !record.root_name
                || (record.ttl >> 16) & 0xff != 0
                || !opt_options_valid(raw, record.rdata, record.end)
            {
                return None;
            }
            seen_opt = true;
        }
        if let Some(layout) = rdata_layout(record.rtype, record.class) {
            let pointer = walk_rdata(raw, layout, record.rdata, record.end, &mut scratch, None)?;
            rewrite |= pointer && LEGACY_NAME_TYPES.contains(&record.rtype);
        }
        // RFC 8945: a TSIG covers the exchange it rode on, not a relayed or
        // cached copy, and this forwarder cannot verify it. Drop it.
        rewrite |= i >= ordinary && record.rtype == TSIG_TYPE;
        pos = record.end;
    }
    if pos != raw.len() {
        return None;
    }
    if !rewrite {
        return Some(std::borrow::Cow::Borrowed(raw));
    }
    expand_names(raw, true).map(std::borrow::Cow::Owned)
}

/// Rewrites a validated message with no compression at all: question and
/// owner names literal, known-layout RDATA names literal, everything else
/// copied. Offsets shift, so no old pointer may survive.
fn expand_names(raw: &[u8], drop_tsig: bool) -> Option<Vec<u8>> {
    let head = header(raw)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut out = Vec::with_capacity(raw.len() + 64);
    out.extend_from_slice(&raw[..HEADER_LEN]);
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        let name = read_name_with(raw, pos, &mut scratch, false, true)?;
        out.extend_from_slice(&scratch[..name.len as usize]);
        out.extend_from_slice(raw.get(name.end..name.end + 4)?);
        pos = name.end + 4;
    }
    let ordinary = head.ancount as usize + head.nscount as usize;
    let mut dropped = 0u16;
    for i in 0..ordinary + head.arcount as usize {
        let record = record_header_with(raw, pos, &mut scratch, true)?;
        if drop_tsig && i >= ordinary && record.rtype == TSIG_TYPE {
            dropped += 1;
            pos = record.end;
            continue;
        }
        let name = read_name_with(raw, pos, &mut scratch, false, true)?;
        out.extend_from_slice(&scratch[..name.len as usize]);
        out.extend_from_slice(raw.get(name.end..name.end + 8)?);
        let rdlen_at = out.len();
        out.extend_from_slice(&[0, 0]);
        match rdata_layout(record.rtype, record.class) {
            Some(layout) => {
                walk_rdata(raw, layout, record.rdata, record.end, &mut scratch, Some(&mut out))?;
            }
            None => out.extend_from_slice(raw.get(record.rdata..record.end)?),
        }
        let rdlen = u16::try_from(out.len() - rdlen_at - 2).ok()?;
        out[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
        pos = record.end;
    }
    let arcount = head.arcount - dropped;
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    (out.len() <= u16::MAX as usize).then_some(out)
}

/// Placeholder type for a record the hickory view cannot hold (private use).
const VIEW_PLACEHOLDER_TYPE: u16 = 0xfeff;

/// A hickory view of an already validated response, for classification and
/// TTL pairing. hickory refuses some wire this forwarder relays verbatim
/// (empty RDATA, a SIG outside Additional, an IN-only layout under another
/// class). Such a record, and the question type when it matches, is replaced
/// in the view only by a placeholder type with one RDATA byte, keeping record
/// order and count, so the relayed bytes stay exact. A record with a layout
/// this module validated that hickory still refuses stays invalid.
pub fn hickory_view(raw: &[u8]) -> Option<Message> {
    if let Some(message) = parse_exact(raw) {
        return Some(message);
    }
    let expanded = expand_names(raw, false)?;
    let head = header(&expanded)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        pos = read_name_with(&expanded, pos, &mut scratch, true, true)?.end + 4;
    }
    let mut view = expanded[..pos].to_vec();
    let question_type = (head.qdcount == 1).then(|| be16(&expanded, pos - 4)).flatten();
    let mut remap_question = false;
    let ordinary = head.ancount as usize + head.nscount as usize;
    for i in 0..ordinary + head.arcount as usize {
        let record = record_header_with(&expanded, pos, &mut scratch, true)?;
        let bytes = &expanded[pos..record.end];
        // The record alone, in the section it came from.
        let mut probe = vec![0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        probe[if i < ordinary { 7 } else { 11 }] = 1;
        probe.extend_from_slice(bytes);
        if parse_exact(&probe).is_some() {
            view.extend_from_slice(bytes);
        } else if rdata_layout(record.rtype, record.class).is_none() || record.rtype == SIG0_TYPE {
            let fields = record.ttl_off - 4;
            view.extend_from_slice(&expanded[pos..fields]);
            view.extend_from_slice(&VIEW_PLACEHOLDER_TYPE.to_be_bytes());
            view.extend_from_slice(&expanded[fields + 2..fields + 8]);
            view.extend_from_slice(&[0, 1, 0]);
            remap_question |= question_type == Some(record.rtype);
        } else {
            return None;
        }
        pos = record.end;
    }
    if remap_question {
        let name = read_name_with(&view, HEADER_LEN, &mut scratch, true, true)?;
        view[name.end..name.end + 2].copy_from_slice(&VIEW_PLACEHOLDER_TYPE.to_be_bytes());
    }
    parse_exact(&view)
}

fn parse_exact(raw: &[u8]) -> Option<Message> {
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
    let mut decoder = BinDecoder::new(raw);
    let message = Message::read(&mut decoder).ok()?;
    (decoder.index() == raw.len()).then_some(message)
}

/// Shapes an upstream response for this client's transaction (RFC 6891 §6.1.1,
/// RFC 6840 §5.6, RFC 1035 §4.1.1): the reserved Z bit is never relayed and the OPT is
/// rebuilt for this client, never relayed. A client without EDNS gets none;
/// an EDNS client gets version 0, its own DO bit (and CO when it asked and the upstream agreed), `payload` as the
/// forwarder's UDP size and no upstream flags; the extended RCODE byte is
/// relayed whole (RFC 6891 §6.1.3). Only Extended DNS Error options survive
/// from the upstream OPT, re-emitted with their source attributed (RFC 8914
/// §3). Returns whether an OPT remains. `raw` must already be validated by
/// [`normalize_upstream`].
pub fn present_for_client(
    raw: &mut Vec<u8>,
    client_edns: bool,
    client_do: bool,
    client_co: bool,
    payload: u16,
) -> bool {
    if let Some(flags) = raw.get_mut(3) {
        *flags &= !0x40; // Z: bit 6 of the second flag octet
    }
    let mut ede = Vec::new();
    let mut upstream_co = false;
    let mut extended = 0u32;
    if let Some((start, end, last, rdata)) = find_opt(raw) {
        let (mut start, mut end, mut rdata) = (start, end, rdata);
        if !last {
            // Later records may point past the OPT; rewrite literal first.
            let Some(expanded) = expand_names(raw, false) else { return false };
            *raw = expanded;
            let Some(found) = find_opt(raw) else { return false };
            (start, end, _, rdata) = found;
        }
        extended = be32(raw, start + 5).map_or(0, |ttl| ttl & 0xff00_0000);
        upstream_co = be16(raw, start + 7).is_some_and(|flags| flags & CO_FLAG != 0);
        let mut pos = rdata;
        while pos + 4 <= end {
            let len = usize::from(be16(raw, pos + 2).unwrap_or(0));
            if be16(raw, pos) == Some(15) {
                if let Some(option) = raw.get(pos + 4..pos + 4 + len) {
                    attribute_ede(option, &mut ede);
                }
            }
            pos += 4 + len;
        }
        raw.drain(start..end);
        let arcount = u16::from_be_bytes([raw[10], raw[11]]).saturating_sub(1);
        raw[10..12].copy_from_slice(&arcount.to_be_bytes());
    }
    if !client_edns {
        return false;
    }
    // The attribution adds bytes; EDE is supplemental, so it goes first
    // rather than let the message pass the DNS maximum.
    if raw.len() + 11 + ede.len() > u16::MAX as usize {
        ede.clear();
    }
    raw.extend_from_slice(&[0, 0, 41]);
    raw.extend_from_slice(&payload.to_be_bytes());
    // CO is the client's own request (RFC 9824 §2): echoed only when the
    // upstream honoured it, never taken from the upstream alone.
    let flags = extended
        | (if client_do { DO_BIT } else { 0 })
        | (if client_co && upstream_co { u32::from(CO_FLAG) } else { 0 });
    raw.extend_from_slice(&flags.to_be_bytes());
    raw.extend_from_slice(&(ede.len() as u16).to_be_bytes());
    raw.extend_from_slice(&ede);
    let arcount = u16::from_be_bytes([raw[10], raw[11]]).saturating_add(1);
    raw[10..12].copy_from_slice(&arcount.to_be_bytes());
    true
}

/// Builds the upstream request from a client query: its header, its question
/// and an OPT of our own, nothing else. A forwarder's two sides are separate
/// transactions (RFC 6891 §7), so the client's Answer, Authority and
/// Additional records are not ours to send: RFC 1035 §4.1 gives a standard
/// query nothing to carry there, and a client could otherwise put up to 64 KB
/// of its own records in our request. The header keeps the ID (the pool
/// replaces it), the opcode and the RD, AD and CD bits this forwarder acts on;
/// AA, TC, Z and RCODE are zero, as a query sets them (RFC 1035 §4.1.1).
///
/// OPT is hop-by-hop and is never forwarded (RFC 6891 §§6.1.1, 6.1.4). The
/// new OPT keeps only the advertised payload (already set to this forwarder's
/// own size), version 0, and the DO and Compact Answers OK flags, which ask
/// for data this forwarder relays; every other flag (Z) is zero and no client
/// option (ECS, Cookie, NSID, keepalive, padding, unknown codes) is carried.
/// A query without OPT gets none. `None` for an unreadable query.
pub fn upstream_query(raw: &[u8]) -> Option<Vec<u8>> {
    let head = header(raw)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut end = HEADER_LEN;
    for _ in 0..head.qdcount {
        end = read_name_with(raw, end, &mut scratch, true, true)?.end + 4;
    }
    // A question name can only point backwards, into the bytes kept here.
    let mut out = raw.get(..end)?.to_vec();
    out[2] &= 0x79; // opcode and RD
    out[3] &= 0x30; // AD and CD
    out[6..12].fill(0);
    if let Some((start, ..)) = find_opt(raw) {
        let payload = be16(raw, start + 3)?;
        let flags = be16(raw, start + 7)? & ((DO_BIT as u16) | CO_FLAG);
        out.extend_from_slice(&[0, 0, 41]);
        out.extend_from_slice(&payload.to_be_bytes());
        out.extend_from_slice(&[0, 0]); // extended RCODE and version 0
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out[11] = 1;
    }
    Some(out)
}

/// RFC 8914 §3: an Extended DNS Error received from the upstream is passed on
/// as a new option of our own whose EXTRA-TEXT names its source, since the
/// client would otherwise take it for this forwarder's own error: the
/// INFO-CODE is kept and the text becomes `upstream` or `upstream: <text>`.
/// A malformed option (no INFO-CODE) is dropped.
fn attribute_ede(option: &[u8], out: &mut Vec<u8>) {
    let [info_hi, info_lo, text @ ..] = option else { return };
    const SOURCE: &[u8] = b"upstream";
    let separator: &[u8] = if text.is_empty() { b"" } else { b": " };
    let Ok(len) = u16::try_from(2 + SOURCE.len() + separator.len() + text.len()) else { return };
    out.extend_from_slice(&[0, 15]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[*info_hi, *info_lo]);
    out.extend_from_slice(SOURCE);
    out.extend_from_slice(separator);
    out.extend_from_slice(text);
}

/// The OPT record of a validated response as `(start, end, is_last, rdata)`.
fn find_opt(raw: &[u8]) -> Option<(usize, usize, bool, usize)> {
    let head = header(raw)?;
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        pos = read_name_with(raw, pos, &mut scratch, true, true)?.end + 4;
    }
    let ordinary = head.ancount as usize + head.nscount as usize;
    let total = ordinary + head.arcount as usize;
    for i in 0..total {
        let record = record_header_with(raw, pos, &mut scratch, true)?;
        if i >= ordinary && record.rtype == OPT_TYPE {
            return Some((pos, record.end, i + 1 == total, record.rdata));
        }
        pos = record.end;
    }
    None
}

/// Compact Answers OK, the EDNS flag bit (RFC 9824 §2) in the 16-bit flags.
pub const CO_FLAG: u16 = 0x4000;

/// The 16-bit EDNS flags of a validated response's OPT, if it has one.
pub fn response_opt_flags(raw: &[u8]) -> Option<u16> {
    let (start, ..) = find_opt(raw)?;
    be16(raw, start + 7)
}

/// Sets the advertised UDP payload of a request's OPT (RFC 6891 §6.2.3: the
/// requestor states its own size). Returns false when there is no OPT.
pub fn set_opt_payload(raw: &mut [u8], payload: u16) -> bool {
    let Some((start, ..)) = find_opt(raw) else { return false };
    // Root owner (1) + type (2) puts CLASS at start + 3.
    match raw.get_mut(start + 3..start + 5) {
        Some(field) => {
            field.copy_from_slice(&payload.to_be_bytes());
            true
        }
        None => false,
    }
}

/// Overwrites the first authority-section SOA TTL, if there is one.
pub fn set_authority_soa_ttl(raw: &mut [u8], ttl: u32) -> Option<()> {
    let fields = ttl_fields(raw)?;
    let p = fields.soa? as usize;
    raw.get_mut(p..p + 4)?.copy_from_slice(&ttl.to_be_bytes());
    Some(())
}

/// Removes every EDE option (code 15) from the OPT record (RFC 8914 §3).
/// Returns true when at least one option was removed.
pub fn drop_ede_options(raw: &mut Vec<u8>) -> bool {
    drop_edns_option(raw, 15)
}

/// EDNS TCP keepalive (RFC 7828): meaningful only on a TCP DNS connection.
pub const EDNS_TCP_KEEPALIVE: u16 = 11;

/// Removes every option with `code` from the OPT record. Returns true when at
/// least one option was removed.
pub fn drop_edns_option(raw: &mut Vec<u8>, code: u16) -> bool {
    let Some(head) = header(raw) else { return false };
    let mut scratch = [0u8; MAX_NAME_LEN];
    let mut pos = HEADER_LEN;
    for _ in 0..head.qdcount {
        let Some(name) = read_name(raw, pos, &mut scratch) else { return false };
        let Some(end) = name.end.checked_add(4) else { return false };
        if end > raw.len() {
            return false;
        }
        pos = end;
    }
    let ordinary = head.ancount as usize + head.nscount as usize;
    for index in 0..ordinary + head.arcount as usize {
        let Some(record) = record_header(raw, pos, &mut scratch) else { return false };
        if index >= ordinary && record.rtype == OPT_TYPE {
            if !record.root_name {
                return false;
            }
            return remove_options_of_code(raw, record.rdata, record.end, code, record.ttl_off + 4);
        }
        pos = record.end;
    }
    false
}

fn remove_options_of_code(raw: &mut Vec<u8>, start: usize, end: usize, code: u16, rdlen_off: usize) -> bool {
    let mut pos = start;
    let mut kept = Vec::with_capacity(end.saturating_sub(start));
    let mut removed = false;
    while pos < end {
        let Some(option) = be16(raw, pos) else { return false };
        let Some(len) = be16(raw, pos + 2).map(usize::from) else { return false };
        let Some(next) = pos.checked_add(4).and_then(|next| next.checked_add(len)) else { return false };
        if next > end {
            return false;
        }
        if option == code {
            removed = true;
        } else {
            kept.extend_from_slice(&raw[pos..next]);
        }
        pos = next;
    }
    if !removed {
        return false;
    }
    let new_len = kept.len();
    raw.splice(start..end, kept);
    let Some(field) = raw.get_mut(rdlen_off..rdlen_off + 2) else { return false };
    let Ok(new_len) = u16::try_from(new_len) else { return false };
    field.copy_from_slice(&new_len.to_be_bytes());
    true
}

/// Copies `answer` into `out` with its EDE options removed and TC set when
/// the result fits `limit`. Returns false when nothing was removed or the
/// answer still does not fit.
pub fn drop_ede_to_fit(answer: &[u8], limit: u16, out: &mut Vec<u8>) -> bool {
    out.clear();
    out.extend_from_slice(answer);
    if !drop_ede_options(out) || out.len() > usize::from(limit) {
        return false;
    }
    // TC is bit 1 of the second header byte (0x0200 in network order).
    if let Some(flags) = out.get_mut(2) {
        *flags |= 0x02;
    }
    true
}

pub fn patch(raw: &mut [u8], offsets: &[u16], age: u32, stale: bool, id: u16) {
    raw[..2].copy_from_slice(&id.to_be_bytes());
    for &p in offsets {
        let p = p as usize;
        let ttl = rfc8767_ttl(u32::from_be_bytes(raw[p..p + 4].try_into().unwrap()));
        // An expired RR gets the stale TTL (RFC 8767 §4); an unexpired one
        // keeps its remaining lifetime.
        let ttl = ttl.saturating_sub(age);
        raw[p..p + 4].copy_from_slice(&if stale && ttl == 0 { 30 } else { ttl }.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
        rr::{rdata::A, rdata::CNAME, rdata::NULL, rdata::SOA, Name, RData, RecordType},
    };
    use proptest::prelude::*;

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn raw_query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut raw = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        raw.extend_from_slice(name);
        raw.extend_from_slice(&qtype.to_be_bytes());
        raw.extend_from_slice(&[0, 1]);
        raw
    }

    fn hickory_query(name: &str, qtype: RecordType) -> Message {
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        query
    }

    fn bump_arcount(raw: &mut [u8]) {
        let count = u16::from_be_bytes([raw[10], raw[11]]).checked_add(1).unwrap();
        raw[10..12].copy_from_slice(&count.to_be_bytes());
    }

    fn append_record(raw: &mut Vec<u8>, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) {
        raw.push(0); // root owner name
        raw.extend_from_slice(&rtype.to_be_bytes());
        raw.extend_from_slice(&class.to_be_bytes());
        raw.extend_from_slice(&ttl.to_be_bytes());
        raw.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        raw.extend_from_slice(rdata);
        bump_arcount(raw);
    }

    #[test]
    fn parses_query_and_canonical_key() {
        let raw = raw_query(&wire_name("www.Example.COM"), 1);
        let view = parse_query(&raw).unwrap();
        assert_eq!(view.id, 0x1234);
        assert_eq!(view.opcode, 0);
        assert_eq!(view.qdcount, 1);
        assert_eq!(view.qtype, 1);
        assert_eq!(view.qclass, 1);
        assert_eq!(view.qname_wire, wire_name("www.Example.COM").as_slice());
        assert_eq!(&view.qname_lower[..view.qname_len as usize], wire_name("www.example.com").as_slice());
        assert!(view.rd && !view.cd);
        assert!(!view.edns_present && !view.has_answer_or_authority && !view.has_non_opt_additional);

        let mut key = [0u8; MIN_CANONICAL_BUFFER];
        let len = canonical_key(&view, &mut key).unwrap();
        assert_eq!(len, view.qname_len as usize + 5);
        assert_eq!(&key[..view.qname_len as usize], wire_name("www.example.com").as_slice());
        assert_eq!(&key[view.qname_len as usize..view.qname_len as usize + 4], &[0u8, 1, 0, 1]);
        assert_eq!(key[view.qname_len as usize + 4], 0);

        let upper = raw_query(&wire_name("WWW.eXaMpLe.cOm"), 1);
        let upper_view = parse_query(&upper).unwrap();
        let mut upper_key = [0u8; MIN_CANONICAL_BUFFER];
        let upper_len = canonical_key(&upper_view, &mut upper_key).unwrap();
        assert_eq!(len, upper_len);
        assert_eq!(key[..len], upper_key[..upper_len]);
        assert_ne!(view.qname_wire, upper_view.qname_wire);

        assert!(canonical_key(&view, &mut [0u8; MIN_CANONICAL_BUFFER - 1]).is_none());
        let mut with_flags = hickory_query("www.example.com.", RecordType::A);
        with_flags.metadata.checking_disabled = true;
        with_flags.edns.get_or_insert_with(Edns::new).set_dnssec_ok(true);
        let with_flags = with_flags.to_vec().unwrap();
        let with_flags = parse_query(&with_flags).unwrap();
        let mut flags_key = [0u8; MIN_CANONICAL_BUFFER];
        canonical_key(&with_flags, &mut flags_key).unwrap();
        assert_eq!(flags_key[with_flags.qname_len as usize + 4], 0b1011);
    }

    #[test]
    fn dotted_name_is_lowercase_dot_separated_and_unterminated() {
        let raw = raw_query(&wire_name("WWW.Example.COM"), 1);
        let view = parse_query(&raw).unwrap();
        let mut out = [0u8; MAX_NAME_LEN];
        let len = dotted_name(&view, &mut out).unwrap();
        assert_eq!(&out[..len], b"www.example.com");

        // The root name writes nothing: rules and reverse lookups see "".
        let raw = raw_query(&wire_name("."), 1);
        let view = parse_query(&raw).unwrap();
        assert_eq!(dotted_name(&view, &mut out), Some(0));

        // A dot inside a label is data, not a separator.
        let mut with_dot = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        with_dot.extend_from_slice(&[3, b'a', b'.', b'b', 0]);
        with_dot.extend_from_slice(&[0, 1, 0, 1]);
        let view = parse_query(&with_dot).unwrap();
        let len = dotted_name(&view, &mut out).unwrap();
        assert_eq!(&out[..len], b"a\\b");
    }

    #[test]
    fn rejects_a_compression_pointer_into_the_header() {
        // A pointer below offset 12 would decode header bytes as a name; a
        // client query is never forwarded with one.
        for target in 0u8..12 {
            let mut raw = vec![0x03, 0x61, 0x62, 0x63, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            raw.extend_from_slice(&[0xc0, target, 0, 1, 0, 1]);
            assert!(parse_query(&raw).is_none(), "target {target}");
        }
        let lead = hex_bytes("000701000001000000000000c00200010001");
        assert!(parse_query(&lead).is_none());
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn normalizes_rd_ra_and_z() {
        let mut raw = vec![0, 1, 0x80, 0x40, 0, 0, 0, 0, 0, 0, 0, 0];
        normalize_rd_ra(&mut raw, true);
        assert_eq!((raw[2], raw[3]), (0x81, 0x80));
        normalize_rd_ra(&mut raw, false);
        assert_eq!((raw[2], raw[3]), (0x80, 0x80));
        raw[3] = 0x50; // RA=0, Z=1, rcode bits kept
        normalize_rd_ra(&mut raw, true);
        assert_eq!((raw[2], raw[3]), (0x81, 0x90));
    }

    #[test]
    fn rejects_malformed_names() {
        // Forward pointer: target 16 is not before the pointer at 12.
        assert!(parse_query(&raw_query(&[0xc0, 0x10], 1)).is_none());

        // Self pointer.
        assert!(parse_query(&raw_query(&[0xc0, 0x0c], 1)).is_none());

        // Two pointers forming a loop; the second points forward.
        let mut looping = vec![0u8; 16];
        looping[2] = 0xc0;
        looping[3] = 0x0c;
        looping[12] = 0xc0;
        looping[13] = 0x02;
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&looping, 12, &mut out).is_none());

        // More than 128 pointer jumps.
        let mut chain = vec![0u8; 402];
        for pos in (2..=400).step_by(2) {
            let target = pos - 2;
            chain[pos] = 0xc0 | ((target >> 8) as u8);
            chain[pos + 1] = (target & 0xff) as u8;
        }
        assert!(read_name(&chain, 400, &mut out).is_none());

        // Label longer than 63 bytes (reserved top bits) and names over 255.
        assert!(parse_query(&raw_query(&[0x40, 0, 1, 0, 0, 1], 1)).is_none());
        let mut long = Vec::new();
        for _ in 0..4 {
            long.push(63);
            long.extend_from_slice(&[b'x'; 63]);
        }
        long.push(0);
        assert!(parse_query(&raw_query(&long, 1)).is_none());

        // Truncated label, header-only packet, wrong question counts.
        assert!(parse_query(&raw_query(&[0x03, b'w', b'w'], 1)).is_none());
        assert!(parse_query(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(parse_query(&[0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
        let mut two = vec![0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0];
        two.extend_from_slice(&wire_name("a.test"));
        two.extend_from_slice(&[0, 1, 0, 1]);
        two.extend_from_slice(&wire_name("b.test"));
        two.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_query(&two).is_none());
        assert!(parse_query(&[]).is_none());

        // Bytes after the counted sections are not accepted as a query.
        let mut trailing = raw_query(&wire_name("trail.test"), 1);
        trailing.push(0);
        assert!(parse_query(&trailing).is_none());
    }

    #[test]
    fn parses_edns_and_additionals() {
        let mut plain = hickory_query("edns.test.", RecordType::A);
        plain.add_additional(Record::from_rdata(
            Name::from_ascii("edns.test.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let plain = plain.to_vec().unwrap();
        let view = parse_query(&plain).unwrap();
        assert!(!view.edns_present);
        assert!(view.has_non_opt_additional && !view.signed);

        let mut query = hickory_query("edns.test.", RecordType::A);
        let edns = query.edns.get_or_insert_with(Edns::new);
        edns.set_max_payload(4096).set_dnssec_ok(true);
        edns.options_mut().insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(65001, vec![1, 2, 3]));
        let query = query.to_vec().unwrap();
        let view = parse_query(&query).unwrap();
        assert!(view.edns_present && view.edns_do && view.edns_options);
        assert_eq!(view.edns_payload, 4096);
        assert_eq!(view.edns_version, 0);

        // TSIG in additional marks the message signed (RDATA is not decoded).
        let mut tsig = raw_query(&wire_name("signed.test"), 1);
        append_record(&mut tsig, 250, 255, 0, &[]);
        assert!(parse_query(&tsig).unwrap().signed);

        // Duplicate OPT and a truncated option are malformed.
        let mut duplicate = raw_query(&wire_name("opt.test"), 1);
        append_record(&mut duplicate, 41, 1232, 0, &[]);
        append_record(&mut duplicate, 41, 1232, 0, &[]);
        assert!(parse_query(&duplicate).is_none());
        let mut bad_option = raw_query(&wire_name("opt.test"), 1);
        append_record(&mut bad_option, 41, 1232, 0, &[0, 10, 0]);
        assert!(parse_query(&bad_option).is_none());
        // RFC 6891: an OPT owner name must be the root.
        let mut non_root = raw_query(&wire_name("opt.test"), 1);
        non_root.extend_from_slice(&wire_name("x"));
        non_root.extend_from_slice(&41u16.to_be_bytes());
        non_root.extend_from_slice(&1232u16.to_be_bytes());
        non_root.extend_from_slice(&0u32.to_be_bytes());
        non_root.extend_from_slice(&0u16.to_be_bytes());
        bump_arcount(&mut non_root);
        assert!(parse_query(&non_root).is_none());
    }

    #[test]
    fn copy_case_and_match_questions() {
        let mut client = hickory_query("MiXeD.TeSt.", RecordType::A);
        client.metadata.id = 7;
        let client = client.to_vec().unwrap();
        let mut response = hickory_query("mixed.test.", RecordType::A);
        response.metadata.message_type = MessageType::Response;
        let mut response = response.to_vec().unwrap();
        let original_len = response.len();
        assert!(copy_question_case(&client, &mut response));
        assert_eq!(response.len(), original_len);
        let name_len = wire_name("MiXeD.TeSt").len();
        assert_eq!(&response[12..12 + name_len], &client[12..12 + name_len]);
        assert_eq!(parse_query(&response).unwrap().qname_wire, wire_name("MiXeD.TeSt").as_slice());

        let mut other = hickory_query("other.test.", RecordType::A).to_vec().unwrap();
        assert!(!copy_question_case(&client, &mut other));
        assert!(!copy_question_case(&client, &mut [0u8; 12]));
        assert!(!copy_question_case(&client, &mut response[..12]));

        // A compressed response question is left alone.
        let mut compressed = vec![0x03, 0x61, 0x62, 0x63, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        compressed.extend_from_slice(&[0xc0, 0x00, 0, 1, 0, 1]);
        let client_abc = raw_query(&wire_name("abc"), 1);
        let mut compressed_copy = compressed.clone();
        assert!(!copy_question_case(&client_abc, &mut compressed_copy));
        assert_eq!(compressed_copy, compressed);

        let view = parse_query(&client).unwrap();
        let mut matching = hickory_query("mixed.test.", RecordType::A);
        matching.metadata.message_type = MessageType::Response;
        matching.metadata.id = view.id;
        assert!(question_matches(&matching.to_vec().unwrap(), &view));
        matching.metadata.id = view.id.wrapping_add(1);
        assert!(!question_matches(&matching.to_vec().unwrap(), &view));
        matching.metadata.id = view.id;
        matching.metadata.op_code = OpCode::Status;
        assert!(!question_matches(&matching.to_vec().unwrap(), &view));
        matching.metadata.op_code = OpCode::Query;
        matching.queries[0].set_query_type(RecordType::AAAA);
        assert!(!question_matches(&matching.to_vec().unwrap(), &view));
        let mut different = hickory_query("other.test.", RecordType::A);
        different.metadata.message_type = MessageType::Response;
        different.metadata.id = view.id;
        assert!(!question_matches(&different.to_vec().unwrap(), &view));
    }

    fn response(name: &str, qtype: RecordType, rcode: ResponseCode) -> Message {
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.metadata.response_code = rcode;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        message
    }

    fn soa(owner: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.test.").unwrap(),
                Name::from_ascii("hostmaster.test.").unwrap(),
                1,
                3600,
                600,
                86400,
                60,
            )),
        )
    }

    #[test]
    fn terminal_answer_needs_the_question_class_and_an_enclosing_soa() {
        // RFC 1034 §3.6, RFC 2308 §5.
        let raw = |message: &Message| message.to_vec().unwrap();
        let qname = wire_name("www.test");
        let mut other_class = response("www.test.", RecordType::A, ResponseCode::NoError);
        let mut record = Record::from_rdata(Name::from_ascii("www.test.").unwrap(), 60, RData::A(A::new(192, 0, 2, 1)));
        record.dns_class = hickory_proto::rr::DNSClass::CH;
        other_class.add_answer(record);
        assert_eq!(terminal_answer(&raw(&other_class), &qname, 1), Some(false));
        let mut unrelated = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        unrelated.add_authority(soa("example."));
        assert_eq!(terminal_answer(&raw(&unrelated), &qname, 1), Some(false));
        let mut root = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        root.add_authority(soa("."));
        assert_eq!(terminal_answer(&raw(&root), &qname, 1), Some(true));
        let mut aa = raw(&root);
        aa[2] |= 0x04;
        clear_aa(&mut aa);
        assert_eq!(aa[2] & 0x04, 0);
    }

    #[test]
    fn terminal_answer_classifies_chains() {
        let name = Name::from_ascii("www.test.").unwrap();
        let alias = Name::from_ascii("alias.test.").unwrap();
        let raw = |message: &Message| message.to_vec().unwrap();
        let qname = wire_name("www.test");

        let mut nx = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        assert_eq!(terminal_answer(&raw(&nx), &qname, 1), Some(false));
        nx.add_authority(soa("test."));
        assert_eq!(terminal_answer(&raw(&nx), &qname, 1), Some(true));

        let empty = response("www.test.", RecordType::A, ResponseCode::NoError);
        assert_eq!(terminal_answer(&raw(&empty), &qname, 1), Some(false));
        let mut nodata = empty.clone();
        nodata.add_authority(soa("test."));
        assert_eq!(terminal_answer(&raw(&nodata), &qname, 1), Some(true));

        let mut positive = response("www.test.", RecordType::A, ResponseCode::NoError);
        positive.add_answer(Record::from_rdata(name.clone(), 60, RData::A(A::new(192, 0, 2, 1))));
        assert_eq!(terminal_answer(&raw(&positive), &qname, 1), Some(true));

        let mut chain = response("www.test.", RecordType::A, ResponseCode::NoError);
        chain.add_answer(Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(alias.clone()))));
        assert_eq!(terminal_answer(&raw(&chain), &qname, 1), Some(false));
        let mut chain_soa = chain.clone();
        chain_soa.add_authority(soa("test."));
        assert_eq!(terminal_answer(&raw(&chain_soa), &qname, 1), Some(true));
        chain.add_answer(Record::from_rdata(alias.clone(), 60, RData::A(A::new(192, 0, 2, 2))));
        assert_eq!(terminal_answer(&raw(&chain), &qname, 1), Some(true));
        // A record at an unrelated owner does not finish the chain.
        let mut unrelated = response("www.test.", RecordType::A, ResponseCode::NoError);
        unrelated.add_answer(Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(alias.clone()))));
        unrelated.add_answer(Record::from_rdata(
            Name::from_ascii("other.test.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 3)),
        ));
        assert_eq!(terminal_answer(&raw(&unrelated), &qname, 1), Some(false));
        // CNAME plus the queried type at one owner is ambiguous (RFC 2181 §10.1).
        let mut ambiguous = response("www.test.", RecordType::A, ResponseCode::NoError);
        ambiguous.add_answer(Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(alias.clone()))));
        ambiguous.add_answer(Record::from_rdata(name.clone(), 60, RData::A(A::new(192, 0, 2, 5))));
        assert_eq!(terminal_answer(&raw(&ambiguous), &qname, 1), Some(false));

        let mut looped = response("www.test.", RecordType::A, ResponseCode::NoError);
        looped.add_answer(Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(alias.clone()))));
        looped.add_answer(Record::from_rdata(alias.clone(), 60, RData::CNAME(CNAME(name.clone()))));
        assert_eq!(terminal_answer(&raw(&looped), &qname, 1), Some(false));

        let mut referral = response("www.test.", RecordType::A, ResponseCode::NoError);
        referral.add_authority(Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            60,
            RData::Unknown { code: RecordType::NS, rdata: NULL::with(wire_name("ns.test.")) },
        ));
        assert_eq!(terminal_answer(&raw(&referral), &qname, 1), Some(false));

        let failed = response("www.test.", RecordType::A, ResponseCode::ServFail);
        assert_eq!(terminal_answer(&raw(&failed), &qname, 1), Some(false));

        // A compressed CNAME target is still decoded by the wire walker.
        let mut compressed = response("www.test.", RecordType::A, ResponseCode::NoError);
        compressed.add_answer(Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(alias.clone()))));
        compressed.add_answer(Record::from_rdata(alias.clone(), 60, RData::A(A::new(192, 0, 2, 4))));
        assert_eq!(terminal_answer(&compressed.to_vec().unwrap(), &qname, 1), Some(true));

        // DNAME rewrites the unmatched prefix: a.sub.example -> a.sub.example.net.
        let mut dname = response("a.sub.example.", RecordType::A, ResponseCode::NoError);
        dname.add_answer(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            60,
            RData::Unknown { code: RecordType::DNAME, rdata: NULL::with(wire_name("example.net.")) },
        ));
        assert_eq!(terminal_answer(&dname.to_vec().unwrap(), &wire_name("a.sub.example"), 1), Some(false));
        dname.add_answer(Record::from_rdata(
            Name::from_ascii("a.sub.example.net.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 5)),
        ));
        assert_eq!(terminal_answer(&dname.to_vec().unwrap(), &wire_name("a.sub.example"), 1), Some(true));
        // A DNAME at its own owner does not apply.
        let mut at_owner = response("example.", RecordType::A, ResponseCode::NoError);
        at_owner.add_answer(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            60,
            RData::Unknown { code: RecordType::DNAME, rdata: NULL::with(wire_name("example.net.")) },
        ));
        at_owner.add_answer(Record::from_rdata(
            Name::from_ascii("example.net.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 6)),
        ));
        assert_eq!(terminal_answer(&at_owner.to_vec().unwrap(), &wire_name("example"), 1), Some(false));
    }

    #[test]
    fn answer_names_is_a_flat_pass_that_a_broken_chain_cannot_hide_from() {
        let visited = |message: &Message, qname: &str| {
            let mut seen = Vec::new();
            let mut text = [0u8; MAX_NAME_LEN];
            answer_names(&message.to_vec().unwrap(), &wire_name(qname), &mut |name| {
                let n = dotted_target(name, &mut text).unwrap();
                seen.push(String::from_utf8(text[..n].to_vec()).unwrap());
                false
            })
            .unwrap();
            seen
        };
        let cname = |owner: &str, target: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
            )
        };
        let a = |owner: &str| Record::from_rdata(Name::from_ascii(owner).unwrap(), 60, RData::A(A::new(192, 0, 2, 1)));

        // A plain answer has nothing beyond the query name.
        let mut plain = response("www.test.", RecordType::A, ResponseCode::NoError);
        plain.add_answer(a("www.test."));
        plain.add_answer(a("www.test."));
        assert!(visited(&plain, "www.test").is_empty());

        // Owners and targets, in packet order, repeated owners once.
        let mut chain = response("www.test.", RecordType::A, ResponseCode::NoError);
        chain.add_answer(cname("www.test.", "mid.test."));
        chain.add_answer(cname("mid.test.", "end.test."));
        chain.add_answer(a("end.test."));
        chain.add_answer(a("end.test."));
        assert_eq!(visited(&chain, "www.test"), ["mid.test", "mid.test", "end.test", "end.test"]);

        // A loop, a conflict and a missing link still expose every name.
        let mut looped = response("www.test.", RecordType::A, ResponseCode::NoError);
        looped.add_answer(cname("www.test.", "a.test."));
        looped.add_answer(cname("a.test.", "www.test."));
        looped.add_answer(cname("a.test.", "cloak.test."));
        assert!(visited(&looped, "www.test").contains(&"cloak.test".to_string()));
        let mut conflict = response("www.test.", RecordType::A, ResponseCode::NoError);
        conflict.add_answer(cname("www.test.", "a.test."));
        conflict.add_answer(cname("www.test.", "cloak.test."));
        assert!(visited(&conflict, "www.test").contains(&"cloak.test".to_string()));
        let mut gap = response("www.test.", RecordType::A, ResponseCode::NoError);
        gap.add_answer(cname("www.test.", "a.test."));
        gap.add_answer(a("cloak.test."));
        assert!(visited(&gap, "www.test").contains(&"cloak.test".to_string()));

        // DNAME target and synthesized owner; another class is ignored.
        let mut dname = response("a.sub.example.", RecordType::A, ResponseCode::NoError);
        dname.add_answer(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            60,
            RData::Unknown { code: RecordType::DNAME, rdata: NULL::with(wire_name("example.net.")) },
        ));
        dname.add_answer(a("a.sub.example.net."));
        assert_eq!(visited(&dname, "a.sub.example"), ["example", "example.net", "a.sub.example.net"]);
        let mut other = response("www.test.", RecordType::A, ResponseCode::NoError);
        let mut record = a("cloak.test.");
        record.dns_class = hickory_proto::rr::DNSClass::CH;
        other.add_answer(record);
        assert!(visited(&other, "www.test").is_empty());

        // `true` stops the pass.
        let mut count = 0;
        answer_names(&chain.to_vec().unwrap(), &wire_name("www.test"), &mut |_| {
            count += 1;
            true
        });
        assert_eq!(count, 1);

        // A dot inside a label never reads as a separator.
        let mut out = [0u8; MAX_NAME_LEN];
        let n = dotted_target(b"\x03a.b\x04test\x00", &mut out).unwrap();
        assert_eq!(&out[..n], b"a\\b.test");
        assert_eq!(dotted_target(&wire_name("a.b.test"), &mut [0u8; MAX_NAME_LEN]), Some(8));
    }

    #[test]
    fn exact_question_match_checks_case() {
        let client = hickory_query("MiXeD.TeSt.", RecordType::A).to_vec().unwrap();
        let view = parse_query(&client).unwrap();
        assert!(!view.qname_compressed);
        let mut echo_message = hickory_query("mixed.test.", RecordType::A);
        echo_message.metadata.message_type = MessageType::Response;
        let mut echo = echo_message.to_vec().unwrap();
        assert!(copy_question_case(&client, &mut echo));
        assert!(question_matches(&echo, &view));
        assert!(question_matches_exact(&echo, &view));

        let name_len = wire_name("MiXeD.TeSt").len();
        echo[12..12 + name_len].make_ascii_lowercase();
        assert!(question_matches(&echo, &view));
        assert!(!question_matches_exact(&echo, &view));

        let mut wrong = hickory_query("mixed.test.", RecordType::A);
        wrong.metadata.message_type = MessageType::Response;
        let mut wrong = wrong.to_vec().unwrap();
        assert!(copy_question_case(&client, &mut wrong));
        wrong[0..2].copy_from_slice(&1u16.to_be_bytes());
        assert!(!question_matches_exact(&wrong, &view));
        wrong[0..2].copy_from_slice(&view.id.to_be_bytes());
        let qtype_at = 12 + name_len;
        wrong[qtype_at..qtype_at + 2].copy_from_slice(&28u16.to_be_bytes());
        assert!(!question_matches_exact(&wrong, &view));
    }

    #[test]
    fn set_do_bit_patches_or_appends_opt() {
        let mut with_edns = hickory_query("do.test.", RecordType::A);
        with_edns.edns.get_or_insert_with(Edns::new).set_max_payload(1400);
        let raw = with_edns.to_vec().unwrap();
        let out = set_do_bit(&raw).unwrap();
        assert_eq!(out.len(), raw.len());
        let parsed = Message::from_vec(&out).unwrap();
        let edns = parsed.edns.unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), 1400);
        assert!(!Message::from_vec(&raw).unwrap().edns.unwrap().flags().dnssec_ok);

        let plain = hickory_query("do.test.", RecordType::A).to_vec().unwrap();
        let out = set_do_bit(&plain).unwrap();
        assert_eq!(out.len(), plain.len() + 11);
        assert_eq!(header(&out).unwrap().arcount, 1);
        let parsed = Message::from_vec(&out).unwrap();
        let edns = parsed.edns.unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(parsed.metadata.id, 0x1234);
        assert_eq!(parsed.queries[0].name().to_ascii(), "do.test.");

        assert!(set_do_bit(&[0u8; 11]).is_none());
        assert!(set_do_bit(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]).is_none());

        // A type-41 record with a non-root owner is malformed: refuse rather
        // than append a second, root-owned OPT.
        let mut non_root = raw_query(&wire_name("do.test"), 1);
        non_root.extend_from_slice(&wire_name("x"));
        non_root.extend_from_slice(&41u16.to_be_bytes());
        non_root.extend_from_slice(&1232u16.to_be_bytes());
        non_root.extend_from_slice(&0u32.to_be_bytes());
        non_root.extend_from_slice(&0u16.to_be_bytes());
        bump_arcount(&mut non_root);
        assert!(set_do_bit(&non_root).is_none());

        // The 65535-byte bound also applies when an existing OPT is patched in
        // place; otherwise this would return an oversized same-size copy.
        let mut huge = raw_query(&wire_name("do.test"), 1);
        append_record(&mut huge, 41, 1232, 0, &[]);
        append_record(&mut huge, 16, 1, 0, &vec![0; 33_000]);
        append_record(&mut huge, 16, 1, 0, &vec![0; 33_000]);
        assert!(huge.len() > u16::MAX as usize);
        assert!(set_do_bit(&huge).is_none());
    }

    #[test]
    fn strips_dnssec_and_opt() {
        let name = Name::from_ascii("strip.test.").unwrap();
        let mut response = Message::new(9, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(name.clone(), RecordType::A));
        response.add_answer(Record::from_rdata(name.clone(), 300, RData::A(A::new(192, 0, 2, 7))));
        for code in [RecordType::RRSIG, RecordType::NSEC] {
            response.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::Unknown { code, rdata: NULL::with(vec![0, 1, 2]) },
            ));
        }
        response.add_authority(Record::from_rdata(
            name.clone(),
            300,
            RData::Unknown { code: RecordType::NSEC3, rdata: NULL::with(vec![0, 1, 2]) },
        ));
        response.metadata.authentic_data = true;
        response.edns.get_or_insert_with(Edns::new).set_dnssec_ok(true);
        let raw = response.to_vec().unwrap();

        let out = strip_response_for_client(&raw, false, false, true, 1).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        assert!(parsed.edns.is_none());
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].data, RData::A(A::new(192, 0, 2, 7)));
        assert!(parsed.authorities.is_empty());
        assert!(parsed.metadata.authentic_data);
        assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 1);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1);
        assert_eq!(u16::from_be_bytes([out[8], out[9]]), 0);
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0);

        // An explicit DNSSEC qtype keeps its own records, strips unrelated ones.
        let out = strip_response_for_client(&raw, true, true, true, u16::from(RecordType::RRSIG)).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        assert_eq!(parsed.answers.len(), 2);
        assert!(parsed.answers.iter().any(|r| r.record_type() == RecordType::RRSIG));
        assert!(parsed.answers.iter().any(|r| r.record_type() == RecordType::A));
        assert!(parsed.authorities.is_empty());
        assert!(parsed.edns.unwrap().flags().dnssec_ok);

        // An EDNS client that did not set DO keeps OPT but not the DO bit.
        let out = strip_response_for_client(&raw, true, false, true, 1).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        assert!(parsed.edns.is_some_and(|e| !e.flags().dnssec_ok));
        assert!(parsed.metadata.authentic_data);

        // Without stripping, DNSSEC stays but OPT still goes to non-EDNS clients.
        let out = strip_response_for_client(&raw, false, false, false, 1).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        assert_eq!(parsed.answers.len(), 3);
        assert!(parsed.edns.is_none());
        assert!(strip_response_for_client(&[0u8; 11], false, false, true, 1).is_none());
    }

    #[test]
    fn clears_only_the_ad_bit() {
        let mut response = hickory_query("ad.test.", RecordType::A).to_vec().unwrap();
        response[2] |= 0x04; // AA
        response[3] |= 0x20; // AD
        let before: Vec<u8> = response[..4].to_vec();
        clear_ad(&mut response);
        assert_eq!(response[3] & 0x20, 0);
        assert_eq!(&response[..2], &before[..2]);
        assert_eq!(response[2], before[2]);
        assert_eq!(response[3], before[3] & !0x20);
        clear_ad(&mut []);
    }

    #[test]
    fn builds_minimal_error_responses() {
        let raw = raw_query(&wire_name("Err.Test"), 1);
        let out = minimal_error_response(&raw, u16::from(ResponseCode::Refused)).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        assert_eq!(parsed.metadata.id, 0x1234);
        assert_eq!(parsed.metadata.response_code, ResponseCode::Refused);
        assert!(parsed.metadata.recursion_desired);
        assert_eq!(parsed.queries.len(), 1);
        assert!(parsed.edns.is_none());
        assert_eq!(&out[12..raw.len()], &raw[12..]);

        let mut empty = raw.clone();
        empty[4..6].copy_from_slice(&0u16.to_be_bytes());
        let out = minimal_error_response(&empty, u16::from(ResponseCode::Refused)).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::Refused);
        assert!(parsed.queries.is_empty());

        let mut bad = raw.clone();
        bad[12] = 0x3f; // label length 63 runs past the end of the question
        let out = minimal_error_response(&bad, u16::from(ResponseCode::FormErr)).unwrap();
        assert_eq!(Message::from_vec(&out).unwrap().metadata.response_code, ResponseCode::FormErr);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 0);

        let mut bad_version = raw_query(&wire_name("bad.edns"), 1);
        append_record(&mut bad_version, 41, 1232, 1 << 16, &[]);
        let out = minimal_error_response(&bad_version, u16::from(ResponseCode::BADVERS)).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        // hickory's From<u16> maps 16 to BADSIG, so compare the wire code.
        assert_eq!(u16::from(parsed.metadata.response_code), 16);
        assert_eq!(parsed.queries.len(), 1);
        let edns = parsed.edns.as_ref().unwrap();
        assert_eq!(edns.rcode_high(), 1);
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.version(), 0);
        assert!(!edns.flags().dnssec_ok);
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1);
        assert_eq!(out[3] & 0x0f, 0); // low rcode stays 0

        // A valid request OPT is echoed on ordinary errors, with the payload
        // clamped to 512..=1232 and version 0; DO is echoed only if sent.
        for rcode in [ResponseCode::FormErr, ResponseCode::Refused, ResponseCode::NotImp] {
            for payload in [4096u16, 64000] {
                let mut request = hickory_query("edns.err.", RecordType::A);
                request.edns.get_or_insert_with(Edns::new).set_max_payload(payload).set_dnssec_ok(true);
                let request = request.to_vec().unwrap();
                let out = minimal_error_response(&request, u16::from(rcode)).unwrap();
                let parsed = Message::from_vec(&out).unwrap();
                assert_eq!(parsed.metadata.response_code, rcode);
                let edns = parsed.edns.unwrap();
                assert_eq!(edns.max_payload(), 1232, "our size, not the client's {payload}");
                assert_eq!(edns.version(), 0);
                assert!(edns.flags().dnssec_ok);
            }
        }
        // A request OPT advertising less than 512 still gets our size.
        let mut low = raw_query(&wire_name("edns.err"), 1);
        append_record(&mut low, 41, 100, 0x8000, &[]);
        let out = minimal_error_response(&low, u16::from(ResponseCode::FormErr)).unwrap();
        let edns = Message::from_vec(&out).unwrap().edns.unwrap();
        assert_eq!(edns.max_payload(), 1232);
        assert!(edns.flags().dnssec_ok);

        // A malformed request OPT (duplicate here) still gets one safe OPT
        // (RFC 6891 §7): root owner, payload 1232, DO clear.
        let mut duplicate = raw_query(&wire_name("edns.bad"), 1);
        append_record(&mut duplicate, 41, 1232, 0, &[]);
        append_record(&mut duplicate, 41, 1232, 0, &[]);
        let out = minimal_error_response(&duplicate, u16::from(ResponseCode::FormErr)).unwrap();
        let edns = Message::from_vec(&out).unwrap().edns.unwrap();
        assert_eq!(edns.max_payload(), 1232);
        assert!(!edns.flags().dnssec_ok);
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1);

        // CD is echoed into local errors like RD.
        let mut cd = raw.clone();
        cd[3] |= 0x10;
        let out = minimal_error_response(&cd, u16::from(ResponseCode::Refused)).unwrap();
        assert!(Message::from_vec(&out).unwrap().metadata.checking_disabled);

        assert!(minimal_error_response(&[0u8; 11], 1).is_none());

        // A compressed question is not echoed: the reply would have to
        // decompress it, which could amplify a small request. QDCOUNT stays 0.
        let mut compressed = vec![0x03, 0x61, 0x62, 0x63, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        compressed.extend_from_slice(&[0xc0, 0x00, 0, 1, 0, 1]);
        let out = minimal_error_response(&compressed, u16::from(ResponseCode::FormErr)).unwrap();
        assert_eq!(out.len(), 12);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 0);
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0);
    }

    #[test]
    fn error_responses_do_not_amplify() {
        let plain = raw_query(&wire_name("amp.test"), 1);
        let mut edns = plain.clone();
        append_record(&mut edns, 41, 4096, 0, &[]);
        let mut bad_version = plain.clone();
        append_record(&mut bad_version, 41, 4096, 1 << 16, &[]);
        let mut malformed = plain.clone();
        append_record(&mut malformed, 41, 1232, 0, &[]);
        append_record(&mut malformed, 41, 1232, 0, &[]);
        let header_only = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        // An overlapping-label question: the name is a pointer to offset 0.
        // Echoing a decompressed name would grow the reply; the header-pointer
        // rule now rejects it before that.
        let overlapping = [
            0x0e, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, // header
            0xc0, 0x00, // question name: pointer to offset 0
            0x01, 0x00, // QTYPE: high byte is label data, low byte is the root
            0x00, 0x01, // QCLASS IN
        ];
        // The pointer targets the header, so the wire parser refuses it too.
        assert!(parse_query(&overlapping).is_none());
        let cases: [(&[u8], u16); 6] = [
            (&plain, u16::from(ResponseCode::FormErr)),
            (&edns, u16::from(ResponseCode::Refused)),
            (&bad_version, u16::from(ResponseCode::BADVERS)),
            (&malformed, u16::from(ResponseCode::FormErr)),
            (&header_only, u16::from(ResponseCode::Refused)),
            (&overlapping, u16::from(ResponseCode::FormErr)),
        ];
        for (request, rcode) in cases {
            let out = minimal_error_response(request, rcode).unwrap();
            assert!(out.len() <= request.len() + 11, "{} bytes for a {} byte request", out.len(), request.len());
        }
    }

    proptest! {
        #[test]
        fn parser_and_builders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_query(&data);
            let mut response = data.clone();
            let _ = copy_question_case(&data, &mut response);
            let _ = set_do_bit(&data);
            let mut mutable = data.clone();
            clear_ad(&mut mutable);
            let _ = minimal_error_response(&data, 1);
        }
    }

    // ---- upstream response validation and presentation ----

    /// One-answer response to "a." with the given owner pointer, type, class
    /// and RDATA appended after the question.
    fn response_with(rtype: u16, class: u16, rdata: &[u8]) -> Vec<u8> {
        let mut raw = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        raw.extend_from_slice(&[0xc0, 12]);
        raw.extend_from_slice(&rtype.to_be_bytes());
        raw.extend_from_slice(&class.to_be_bytes());
        raw.extend_from_slice(&60u32.to_be_bytes());
        raw.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        raw.extend_from_slice(rdata);
        raw
    }

    #[test]
    fn upstream_known_rdata_must_fit_its_layout() {
        // Valid shapes pass through byte for byte.
        for (rtype, class, rdata) in [
            (65400u16, 1u16, &b""[..]),
            (11, 1, b"\xc0\x00\x02\x2a\x06"),
            (3, 1, b"\x01b\x00"),
            (14, 1, b"\x01b\x00\x01c\x00"),
        ] {
            let raw = response_with(rtype, class, rdata);
            assert_eq!(normalize_upstream(&raw).as_deref(), Some(raw.as_slice()), "type {rtype}");
        }
        // Name terminators, short WKS and short A are invalid wire.
        for (rtype, rdata) in [
            (3u16, &b"\x03bad"[..]),
            (7, b"\x03bad"),
            (14, b"\x01b\x00\x03bad"),
            (11, b"\xc6\x33\x64\x2a"),
            (1, b"\xc0\x00\x02"),
            (13, b"\x03bad"),
        ] {
            assert!(normalize_upstream(&response_with(rtype, 1, rdata)).is_none(), "type {rtype}");
        }
    }

    /// A response to "a." (type A, class IN) whose Answer holds `records`
    /// (owner pointer, type, class, RDATA), then `authority` the same way.
    fn shaped(records: &[(u16, u16, &[u8])], authority: &[(u16, u16, &[u8])]) -> Vec<u8> {
        let mut raw = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, records.len() as u8, 0, authority.len() as u8, 0, 0];
        raw.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        for (rtype, class, rdata) in records.iter().chain(authority) {
            raw.extend_from_slice(&[0xc0, 12]);
            raw.extend_from_slice(&rtype.to_be_bytes());
            raw.extend_from_slice(&class.to_be_bytes());
            raw.extend_from_slice(&60u32.to_be_bytes());
            raw.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            raw.extend_from_slice(rdata);
        }
        raw
    }

    #[test]
    fn upstream_meta_types_and_foreign_classes_are_invalid_in_answer_and_authority() {
        // RFC 6895 §3.1.
        let a = (1u16, 1u16, &b"\xc0\x00\x02\x01"[..]);
        assert!(normalize_upstream(&shaped(&[a], &[])).is_some(), "control");
        for rtype in [128u16, 200, 248, 249, 250, 251, 252, 253, 254, 255, OPT_TYPE] {
            let bad = (rtype, 1u16, &b"x"[..]);
            assert!(normalize_upstream(&shaped(&[a, bad], &[])).is_none(), "type {rtype} in Answer");
            assert!(normalize_upstream(&shaped(&[a], &[bad])).is_none(), "type {rtype} in Authority");
        }
        for class in [255u16, 254, 3, 4, 65280] {
            let bad = (1u16, class, &b"\xc0\x00\x02\x02"[..]);
            assert!(normalize_upstream(&shaped(&[a, bad], &[])).is_none(), "class {class} in Answer");
            // A foreign-class Authority record is ignored, not fatal (see
            // `terminal_answer_needs_the_question_class_and_an_enclosing_soa`).
            assert!(normalize_upstream(&shaped(&[a], &[bad])).is_some(), "class {class} in Authority");
        }
        // Types just outside the range and a CH question answered in CH stay valid.
        for rtype in [127u16, 256, 65280] {
            assert!(normalize_upstream(&shaped(&[a, (rtype, 1, b"x")], &[])).is_some(), "type {rtype}");
        }
        let mut chaos = shaped(&[(16, 3, b"\x01x")], &[]);
        chaos[17..19].copy_from_slice(&3u16.to_be_bytes());
        assert!(normalize_upstream(&chaos).is_some(), "a CH answer to a CH question");
        // QCLASS ANY is never forwarded, so no answer to it is usable, not
        // even IN data.
        for class in [1u16, 3] {
            let mut any = shaped(&[(1, class, b"\xc0\x00\x02\x03")], &[]);
            any[17..19].copy_from_slice(&255u16.to_be_bytes());
            assert!(normalize_upstream(&any).is_none(), "class {class} answer to QCLASS ANY");
        }
        // Additional is not checked: a TSIG there is dropped, not invalid.
        let mut signed = shaped(&[a], &[]);
        append_record(&mut signed, 250, 255, 0, &[0; 20]);
        assert!(normalize_upstream(&signed).is_some());
    }

    #[test]
    fn terminal_answer_rejects_contradictory_shapes() {
        let qname = wire_name("www.test");
        let raw = |message: &Message| message.to_vec().unwrap();
        let address =
            |owner: &str| Record::from_rdata(Name::from_ascii(owner).unwrap(), 60, RData::A(A::new(192, 0, 2, 1)));
        let text = |owner: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["x".into()])),
            )
        };
        let cname = |owner: &str, target: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_ascii(target).unwrap())),
            )
        };

        // NXDOMAIN with a non-alias answer at the query name.
        let mut nx = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        nx.add_authority(soa("test."));
        nx.add_answer(address("www.test."));
        assert_eq!(terminal_answer(&raw(&nx), &qname, 1), None);
        // ... of another type too, and for any query type.
        let mut other = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        other.add_authority(soa("test."));
        other.add_answer(text("www.test."));
        assert_eq!(terminal_answer(&raw(&other), &qname, 1), None);
        let mut any_nx = response("www.test.", RecordType::ANY, ResponseCode::NXDomain);
        any_nx.add_authority(soa("test."));
        any_nx.add_answer(text("www.test."));
        assert_eq!(terminal_answer(&raw(&any_nx), &qname, 255), None);
        // NXDOMAIN whose alias tail is itself answered; also two hops down.
        let mut tail = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        tail.add_authority(soa("test."));
        tail.add_answer(cname("www.test.", "tail.test."));
        tail.add_answer(address("tail.test."));
        assert_eq!(terminal_answer(&raw(&tail), &qname, 1), None);
        let mut deep = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        deep.add_authority(soa("test."));
        deep.add_answer(cname("www.test.", "mid.test."));
        deep.add_answer(cname("mid.test.", "tail.test."));
        deep.add_answer(text("tail.test."));
        assert_eq!(terminal_answer(&raw(&deep), &qname, 1), None);
        // Valid: NXDOMAIN after a CNAME chain, and data for a name off the chain
        // is the plaintext scrub's concern, not a contradiction here.
        let mut valid = response("www.test.", RecordType::A, ResponseCode::NXDomain);
        valid.add_authority(soa("test."));
        valid.add_answer(cname("www.test.", "mid.test."));
        valid.add_answer(cname("mid.test.", "gone.test."));
        assert_eq!(terminal_answer(&raw(&valid), &qname, 1), Some(true));

        // NOERROR whose Answer holds only another type at the query name.
        let mut mismatch = response("www.test.", RecordType::A, ResponseCode::NoError);
        mismatch.add_answer(text("www.test."));
        assert_eq!(terminal_answer(&raw(&mismatch), &qname, 1), None);
        // ... or at the end of a CNAME chain.
        let mut chained = response("www.test.", RecordType::A, ResponseCode::NoError);
        chained.add_answer(cname("www.test.", "tail.test."));
        chained.add_answer(text("tail.test."));
        assert_eq!(terminal_answer(&raw(&chained), &qname, 1), None);
        // Valid: ANY returns whatever exists, a TXT query matches its own type,
        // an alias to a name with the right type is positive, an empty NODATA
        // stays NODATA.
        let mut any = response("www.test.", RecordType::ANY, ResponseCode::NoError);
        any.add_answer(text("www.test."));
        assert_eq!(terminal_answer(&raw(&any), &qname, 255), Some(false));
        let mut txt = response("www.test.", RecordType::TXT, ResponseCode::NoError);
        txt.add_answer(text("www.test."));
        assert_eq!(terminal_answer(&raw(&txt), &qname, 16), Some(true));
        let mut positive = response("www.test.", RecordType::A, ResponseCode::NoError);
        positive.add_answer(cname("www.test.", "tail.test."));
        positive.add_answer(address("tail.test."));
        assert_eq!(terminal_answer(&raw(&positive), &qname, 1), Some(true));
        let mut nodata = response("www.test.", RecordType::A, ResponseCode::NoError);
        nodata.add_authority(soa("test."));
        assert_eq!(terminal_answer(&raw(&nodata), &qname, 1), Some(true));
    }

    #[test]
    fn upstream_pointer_into_the_header_is_invalid() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x63");
        raw[19..21].copy_from_slice(&[0xc0, 0x04]); // owner pointer, was 12
        assert!(normalize_upstream(&raw).is_none());
        // The same name pointing at the question is fine.
        assert!(normalize_upstream(&response_with(1, 1, b"\xc0\x00\x02\x63")).is_some());
    }

    #[test]
    fn legacy_rdata_names_are_relayed_literally() {
        // SRV target as a pointer to the question name: RFC 3597 §4 forbids
        // compressing it when sent, so it leaves as a literal name.
        let raw = response_with(33, 1, b"\0\x01\0\x02\x01\xbb\xc0\x0c");
        let out = normalize_upstream(&raw).unwrap();
        assert!(matches!(out, std::borrow::Cow::Owned(_)));
        assert!(out.ends_with(b"\0\x01\0\x02\x01\xbb\x01a\x00"));
        assert!(parse_exact(&out).is_some());
        // A well-known type may keep its compression.
        let ptr = response_with(12, 1, b"\xc0\x0c");
        assert!(matches!(normalize_upstream(&ptr).unwrap(), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn hickory_view_holds_wire_hickory_refuses() {
        // Empty RDATA, a SIG in Answer and an IN-only type under another
        // class are valid relays hickory rejects; the view keeps the count.
        for (rtype, class, rdata) in [(65400u16, 1u16, &b""[..]), (24, 1, &[0u8; 19][..]), (1, 65280, b"\xff")] {
            let mut raw = response_with(rtype, class, rdata);
            raw[17..19].copy_from_slice(&class.to_be_bytes()); // the question class follows
            let kept = normalize_upstream(&raw).unwrap();
            let view = hickory_view(&kept).unwrap_or_else(|| panic!("type {rtype}"));
            assert_eq!(view.answers.len(), 1);
        }
    }

    #[test]
    fn present_for_client_follows_the_client_transaction() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        raw[3] |= 0x40; // reserved Z
        append_record(&mut raw, 41, 1232, DO_BIT, &[]);
        let mut copy = raw.clone();
        // EDNS client without DO: Z cleared, OPT kept, DO cleared.
        assert!(present_for_client(&mut copy, true, false, false, 1232));
        assert_eq!(copy[3] & 0x40, 0);
        let opt = copy.len() - 11;
        assert_eq!(u32::from_be_bytes(copy[opt + 5..opt + 9].try_into().unwrap()) & DO_BIT, 0);
        // EDNS client with DO gets DO even if the upstream did not set it.
        let mut no_do = raw.clone();
        let at = no_do.len() - 6;
        no_do[at..at + 4].copy_from_slice(&0u32.to_be_bytes());
        assert!(present_for_client(&mut no_do, true, true, false, 1232));
        assert_eq!(u32::from_be_bytes(no_do[at..at + 4].try_into().unwrap()) & DO_BIT, DO_BIT);
        // A client without EDNS never sees the OPT.
        assert!(!present_for_client(&mut raw, false, false, false, 1232));
        assert_eq!(header(&raw).unwrap().arcount, 0);
        assert!(parse_exact(&raw).is_some());
    }

    #[test]
    fn rrset_ttls_with_the_top_bit_set_are_capped_not_zeroed() {
        // RFC 8767 §4: positive, capped at 604800.
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        let ttl_at = raw.len() - 4 - 2 - 4;
        raw[ttl_at..ttl_at + 4].copy_from_slice(&0x8000_0001u32.to_be_bytes());
        let message = parse_exact(&raw).unwrap();
        assert!(normalize_rrset_ttls(&message, &mut raw));
        assert_eq!(u32::from_be_bytes(raw[ttl_at..ttl_at + 4].try_into().unwrap()), MAX_TTL);
        assert_eq!(
            (rfc8767_ttl(0x7fff_ffff), rfc8767_ttl(0x8000_0000), rfc8767_ttl(u32::MAX), rfc8767_ttl(300)),
            (MAX_TTL, MAX_TTL, MAX_TTL, 300)
        );
        // The raw walk alone (no parsed message) caps it too, and patch never reads it back as larger.
        raw[ttl_at..ttl_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(cap_ttls(&mut raw));
        assert_eq!(u32::from_be_bytes(raw[ttl_at..ttl_at + 4].try_into().unwrap()), MAX_TTL);
        raw[ttl_at..ttl_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let offsets = ttl_offsets(&raw).unwrap();
        patch(&mut raw, &offsets, 0, false, 1);
        assert_eq!(u32::from_be_bytes(raw[ttl_at..ttl_at + 4].try_into().unwrap()), MAX_TTL);
    }

    #[test]
    fn rrset_ttls_are_capped_at_the_profile_maximum() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        let ttl_at = raw.len() - 4 - 2 - 4;
        raw[ttl_at..ttl_at + 4].copy_from_slice(&1_000_000u32.to_be_bytes());
        let message = parse_exact(&raw).unwrap();
        assert!(normalize_rrset_ttls(&message, &mut raw));
        assert_eq!(u32::from_be_bytes(raw[ttl_at..ttl_at + 4].try_into().unwrap()), MAX_TTL);
    }

    #[test]
    fn malformed_edns_errors_still_carry_a_safe_opt() {
        let q = |extra: &dyn Fn(&mut Vec<u8>)| {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            extra(&mut raw);
            raw
        };
        for raw in [
            q(&|r| {
                append_record(r, 41, 1232, 0, &[]);
                append_record(r, 41, 1232, 0, &[]);
            }),
            q(&|r| append_record(r, 41, 1232, 0, &[0xff])),
            q(&|r| append_record(r, 41, 1232, 0, &[0xff, 0xfe, 0, 2, b'x'])),
        ] {
            let out = minimal_error_response(&raw, 1).unwrap();
            let view = parse_query(&out).unwrap();
            assert!(view.edns_present, "FORMERR carries a safe OPT");
            assert_eq!(view.edns_payload, 1232);
        }
        // No OPT in the request, none in the error.
        assert!(
            !parse_query(&minimal_error_response(&raw_query(&wire_name("a.test"), 1), 1).unwrap())
                .unwrap()
                .edns_present
        );
    }

    #[test]
    fn badvers_copies_the_client_do_bit() {
        let mut raw = raw_query(&wire_name("a.test"), 1);
        append_record(&mut raw, 41, 1232, (1 << 16) | DO_BIT, &[]);
        let out = minimal_error_response(&raw, 16).unwrap();
        let opt = out.len() - 11;
        let ttl = u32::from_be_bytes(out[opt + 5..opt + 9].try_into().unwrap());
        assert_eq!(ttl, (1 << 24) | DO_BIT);
    }

    #[test]
    fn only_sig0_counts_as_a_transaction_signature() {
        let mut sig0 = raw_query(&wire_name("a.test"), 1);
        append_record(&mut sig0, 24, 255, 0, &[0, 0, 1]);
        assert!(parse_query(&sig0).unwrap().signed);
        // A SIG covering type 1 is ordinary RRset data.
        let mut data = raw_query(&wire_name("a.test"), 1);
        append_record(&mut data, 24, 1, 60, &[0, 1, 1]);
        assert!(!parse_query(&data).unwrap().signed);
    }

    #[test]
    fn unfamiliar_header_bits_are_flagged() {
        let mut raw = raw_query(&wire_name("a.test"), 1);
        assert!(!parse_query(&raw).unwrap().unfamiliar_header_flags);
        raw[3] |= 0x40;
        assert!(parse_query(&raw).unwrap().unfamiliar_header_flags);
    }

    #[test]
    fn tcp_keepalive_option_can_be_dropped() {
        let mut raw = raw_query(&wire_name("a.test"), 1);
        append_record(&mut raw, 41, 1232, 0, &[0, 11, 0, 2, 0, 10, 0xff, 0xfe, 0, 1, 9]);
        assert!(drop_edns_option(&mut raw, EDNS_TCP_KEEPALIVE));
        let view = parse_query(&raw).unwrap();
        assert!(view.edns_present && view.edns_options);
        assert!(!drop_edns_option(&mut raw, EDNS_TCP_KEEPALIVE));
    }

    #[test]
    fn the_upstream_opt_is_rebuilt_even_when_it_is_not_last() {
        let mut raw = raw_query(&wire_name("a.test"), 1);
        append_record(&mut raw, 41, 1400, 0x0000_ffff, &[0, 3, 0, 0]);
        append_record(&mut raw, 1, 1, 60, &[192, 0, 2, 1]);
        let out = upstream_query(&raw).unwrap();
        let view = parse_query(&out).unwrap();
        assert!(view.edns_present && view.edns_do && !view.has_non_opt_additional);
        assert_eq!((view.edns_flags, view.edns_payload), (0xc000, 1400), "DO and CO kept, Z cleared");
        assert!(!view.edns_options);
        assert_eq!(header(&out).unwrap().arcount, 1);
        let plain = raw_query(&wire_name("a.test"), 1);
        assert_eq!(upstream_query(&plain).unwrap(), plain, "no OPT is added");
    }

    /// The upstream request is ours: header, question and our own OPT. A
    /// client's Answer, Authority and non-OPT Additional records (here a
    /// 60 KB TXT) and its stray header bits never reach the upstream.
    #[test]
    fn the_upstream_query_carries_only_the_question_and_our_opt() {
        let question = raw_query(&wire_name("a.test"), 1);
        let mut raw = question.clone();
        append_record(&mut raw, 1, 1, 60, &[192, 0, 2, 1]);
        append_record(&mut raw, 2, 1, 60, &wire_name("ns.test"));
        let mut txt = Vec::new();
        for _ in 0..240 {
            txt.push(250);
            txt.extend_from_slice(&[b'x'; 250]);
        }
        append_record(&mut raw, 16, 1, 60, &txt);
        append_record(&mut raw, 41, 1232, 0x0000_8000, &[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        // One record each in Answer and Authority, two in Additional.
        raw[6..12].copy_from_slice(&[0, 1, 0, 1, 0, 2]);
        // AA, TC, Z and a nonzero RCODE beside RD, AD and CD.
        raw[2] |= 0x06;
        raw[3] |= 0x40 | 0x20 | 0x10 | 0x05;
        assert!(parse_query(&raw).unwrap().has_answer_or_authority);

        let out = upstream_query(&raw).unwrap();
        let mut expected = question.clone();
        expected[2] = 0x01; // RD
        expected[3] = 0x30; // AD and CD
        expected[11] = 1; // ARCOUNT: our OPT only
        expected.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        assert_eq!(out, expected);

        // Without an OPT the request is the header and question alone.
        let mut bare = question.clone();
        append_record(&mut bare, 16, 1, 60, &txt);
        assert_eq!(upstream_query(&bare).unwrap(), question);
    }

    #[test]
    fn malformed_upstream_opt_is_invalid() {
        let base = response_with(1, 1, b"\xc0\x00\x02\x01");
        let with = |owner: &[u8], class: u16, ttl: u32, rdata: &[u8]| {
            let mut raw = base.clone();
            raw.extend_from_slice(owner);
            raw.extend_from_slice(&41u16.to_be_bytes());
            raw.extend_from_slice(&class.to_be_bytes());
            raw.extend_from_slice(&ttl.to_be_bytes());
            raw.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            raw.extend_from_slice(rdata);
            raw[11] = 1;
            raw
        };
        assert!(normalize_upstream(&with(&[0], 1232, 0, &[])).is_some());
        assert!(normalize_upstream(&with(&[3, b'o', b'p', b't', 0], 1232, 0, &[])).is_none(), "non-root owner");
        assert!(normalize_upstream(&with(&[0], 1232, 0, &[0xff, 0xfd, 0, 10, b'a'])).is_none(), "option overrun");
        assert!(normalize_upstream(&with(&[0], 1232, 1 << 16, &[])).is_none(), "version 1");
        // OPT in the Answer section is not an OPT at all.
        let mut misplaced = base.clone();
        misplaced.truncate(19);
        misplaced.extend_from_slice(&[0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0]);
        misplaced[7] = 1;
        assert!(normalize_upstream(&misplaced).is_none());
    }

    #[test]
    fn client_opt_is_built_fresh() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        // Upstream OPT: size 4096, flags 0xbfff, ext RCODE 0, option 65001,
        // an EDE without text, an EDE with text and a malformed EDE.
        let rdata = [0xfd, 0xe9, 0, 1, b'x', 0, 15, 0, 2, 0, 9, 0, 15, 0, 4, 0, 6, b'h', b'i', 0, 15, 0, 1, 7];
        append_record(&mut raw, 41, 4096, 0x0000_bfff, &rdata);
        let mut out = raw.clone();
        assert!(present_for_client(&mut out, true, true, false, 1232));
        // RFC 8914 §3: each EDE is re-emitted with its source in EXTRA-TEXT.
        let mut ede = vec![0, 15, 0, 10, 0, 9];
        ede.extend_from_slice(b"upstream");
        ede.extend_from_slice(&[0, 15, 0, 14, 0, 6]);
        ede.extend_from_slice(b"upstream: hi");
        let mut want = vec![0, 0, 41, 4, 0xd0, 0, 0, 0x80, 0, 0, ede.len() as u8];
        want.extend_from_slice(&ede);
        // Root, type 41, size 1232, version 0, DO only, then only the EDEs.
        assert_eq!(&out[out.len() - want.len()..], &want[..]);
        // No OPT upstream, EDNS client: one is added.
        let mut bare = response_with(1, 1, b"\xc0\x00\x02\x01");
        assert!(present_for_client(&mut bare, true, false, false, 1232));
        assert_eq!(&bare[bare.len() - 11..], [0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(header(&bare).unwrap().arcount, 1);
    }

    #[test]
    fn upstream_request_opt_advertises_our_size() {
        let mut raw = raw_query(&wire_name("a.test"), 1);
        append_record(&mut raw, 41, 65535, DO_BIT, &[]);
        assert!(set_opt_payload(&mut raw, 1232));
        assert_eq!(parse_query(&raw).unwrap().edns_payload, 1232);
        assert!(!set_opt_payload(&mut raw_query(&wire_name("a.test"), 1), 1232));
    }

    #[test]
    fn upstream_tsig_is_dropped_and_doh_ignores_the_dns_id() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        append_record(&mut raw, 250, 255, 0, &[0]);
        let out = normalize_upstream(&raw).unwrap();
        assert_eq!(header(&out).unwrap().arcount, 0);
        assert!(parse_exact(&out).is_some());
        // A response ID other than the sent one: rejected unless DoH.
        let mut sent = raw_query(&wire_name("a"), 1);
        sent[0..2].copy_from_slice(&[0, 0]);
        let view = parse_query(&sent).unwrap();
        assert!(!question_matches(&raw, &view));
        assert!(question_matches_any_id(&raw, &view));
    }

    #[test]
    fn response_opt_flags_expose_co() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        assert_eq!(response_opt_flags(&raw), None);
        append_record(&mut raw, 41, 1232, DO_BIT | CO_FLAG as u32, &[]);
        assert_eq!(response_opt_flags(&raw), Some(DO_BIT as u16 | CO_FLAG));
    }

    #[test]
    fn co_flag_is_echoed_only_when_asked_and_honoured() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        append_record(&mut raw, 41, 1232, CO_FLAG as u32, &[]);
        let mut asked = raw.clone();
        assert!(present_for_client(&mut asked, true, false, true, 1232));
        assert_eq!(response_opt_flags(&asked), Some(CO_FLAG));
        assert!(present_for_client(&mut raw, true, false, false, 1232));
        assert_eq!(response_opt_flags(&raw), Some(0));
    }

    #[test]
    fn upstream_extended_rcode_is_relayed_whole_but_not_flags() {
        let mut raw = response_with(1, 1, b"\xc0\x00\x02\x01");
        append_record(&mut raw, 41, 1232, 0x0f00_3fff, &[]);
        let mut out = normalize_upstream(&raw).unwrap().into_owned();
        assert!(present_for_client(&mut out, true, false, false, 1232));
        let ttl = u32::from_be_bytes(out[out.len() - 6..out.len() - 2].try_into().unwrap());
        assert_eq!(ttl, 0x0f00_0000);
    }
    fn scrub_message(build: impl FnOnce(&mut Message)) -> Vec<u8> {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii("a.test.").unwrap(), RecordType::A));
        build(&mut message);
        message.to_vec().unwrap()
    }

    fn rec(owner: &str, data: RData) -> hickory_proto::rr::Record {
        hickory_proto::rr::Record::from_rdata(Name::from_ascii(owner).unwrap(), 60, data)
    }

    fn ns(owner: &str) -> hickory_proto::rr::Record {
        rec(owner, RData::NS(hickory_proto::rr::rdata::NS(Name::from_ascii("ns.evil.test.").unwrap())))
    }

    fn scrub_soa(owner: &str) -> hickory_proto::rr::Record {
        rec(owner, RData::SOA(SOA::new(Name::root(), Name::root(), 1, 2, 3, 4, 60)))
    }

    #[test]
    fn plain_scrub_keeps_a_clean_reply_untouched() {
        let raw = scrub_message(|m| {
            m.add_answer(rec("a.test.", RData::A(A::new(192, 0, 2, 1))));
            m.add_authority(ns("test."));
            m.edns = Some(Edns::new());
        });
        assert_eq!(scrub_plain_reply(&raw), Some(None));
    }

    #[test]
    fn plain_scrub_drops_unrelated_authority_and_additional_data() {
        let raw = scrub_message(|m| {
            m.add_answer(rec("a.test.", RData::A(A::new(192, 0, 2, 1))));
            m.add_authority(ns("test."));
            m.add_authority(ns("victim.test."));
            m.add_authority(rec("victim.test.", RData::A(A::new(203, 0, 113, 9))));
            m.add_authority(scrub_soa("test."));
            m.add_additional(rec("victim.test.", RData::A(A::new(203, 0, 113, 9))));
            m.edns = Some(Edns::new());
        });
        let scrubbed = scrub_plain_reply(&raw).unwrap().expect("something was removed");
        let message = Message::from_vec(&scrubbed).unwrap();
        assert_eq!(message.answers.len(), 1);
        let owners: Vec<_> =
            message.authorities.iter().map(|r| (r.name.to_ascii(), u16::from(r.record_type()))).collect();
        assert_eq!(owners, [("test.".to_string(), 2), ("test.".to_string(), 6)]);
        assert!(message.additionals.is_empty());
        assert!(message.edns.is_some(), "OPT survives");
        assert_eq!(normalize_upstream(&scrubbed).as_deref(), Some(scrubbed.as_slice()), "the rewrite is valid wire");
    }

    #[test]
    fn plain_scrub_follows_cname_chains_and_rejects_off_chain_answers() {
        let cname = |owner: &str, target: &str| rec(owner, RData::CNAME(CNAME(Name::from_ascii(target).unwrap())));
        let chained = scrub_message(|m| {
            m.add_answer(cname("a.test.", "b.test."));
            m.add_answer(cname("b.test.", "c.example."));
            m.add_answer(rec("c.example.", RData::A(A::new(192, 0, 2, 1))));
        });
        assert_eq!(scrub_plain_reply(&chained), Some(None), "every owner is on the chain");
        let injected = scrub_message(|m| {
            m.add_answer(rec("a.test.", RData::A(A::new(192, 0, 2, 1))));
            m.add_answer(rec("victim.test.", RData::A(A::new(203, 0, 113, 9))));
        });
        assert_eq!(scrub_plain_reply(&injected), None, "an off-chain Answer owner invalidates the reply");
        let apex = scrub_message(|m| {
            m.add_answer(rec("test.", RData::A(A::new(203, 0, 113, 9))));
        });
        assert_eq!(scrub_plain_reply(&apex), None, "an ancestor is not on the chain either");
    }

    #[test]
    fn plain_scrub_bounds_the_chain_within_one_pass() {
        // A pass that collects every alias of an in-order chain before the
        // bound is checked does work quadratic in the reply size. The chain
        // stops at MAX_CHAIN_RECORDS, so a longer one leaves its tail off the
        // chain and the reply is invalid.
        let cname = |i: usize| {
            let owner = if i == 0 { "a.test.".to_string() } else { format!("c{i}.test.") };
            rec(&owner, RData::CNAME(CNAME(Name::from_ascii(format!("c{}.test.", i + 1)).unwrap())))
        };
        let chain = |aliases: usize| {
            scrub_message(|m| {
                for i in 0..aliases {
                    m.add_answer(cname(i));
                }
            })
        };
        let within = chain(MAX_CHAIN_RECORDS);
        assert_eq!(scrub_plain_reply(&within), Some(None));
        let beyond = chain(MAX_CHAIN_RECORDS + 10);
        assert_eq!(scrub_plain_reply(&beyond), None);
    }

    // ---- boundary and operator tests (cargo-mutants survivors) ----

    /// A wire name of exactly `total` bytes (root label included) of 'a' labels.
    fn name_of_len(total: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut left = total - 1;
        while left > 0 {
            assert!(left != 1, "no label fits one byte");
            let label = left.min(64) - 1;
            out.push(label as u8);
            out.extend(std::iter::repeat_n(b'a', label));
            left -= label + 1;
        }
        out.push(0);
        assert_eq!(out.len(), total);
        out
    }

    /// One uncompressed class-IN record with a 60 s TTL.
    fn rr(owner: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = wire_name(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn cname_rr(owner: &str, target: &str) -> Vec<u8> {
        rr(owner, 5, &wire_name(target))
    }

    /// A SOA with root MNAME and RNAME.
    fn soa_rr(owner: &str) -> Vec<u8> {
        rr(owner, 6, &[0u8; 22])
    }

    const A_RDATA: [u8; 4] = [192, 0, 2, 1];

    /// A response to "a.test" type A with the given RCODE and sections.
    fn reply(rcode: u8, answers: &[Vec<u8>], authority: &[Vec<u8>]) -> Vec<u8> {
        let mut raw = vec![0x12, 0x34, 0x81, 0x80 | rcode, 0, 1];
        raw.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        raw.extend_from_slice(&(authority.len() as u16).to_be_bytes());
        raw.extend_from_slice(&[0, 0]);
        raw.extend_from_slice(&wire_name("a.test"));
        raw.extend_from_slice(&[0, 1, 0, 1]);
        for record in answers.iter().chain(authority) {
            raw.extend_from_slice(record);
        }
        raw
    }

    #[test]
    fn rd_bit_is_read_alone() {
        let rd = |flags: u16| {
            let mut raw = [0u8; 12];
            raw[2..4].copy_from_slice(&flags.to_be_bytes());
            header(&raw).unwrap().recursion_desired()
        };
        assert!(!rd(0));
        assert!(!rd(!RD_BIT));
        assert!(rd(RD_BIT));
        assert!(rd(0xffff));
    }

    #[test]
    fn the_longest_legal_label_and_name_are_accepted_and_one_more_is_not() {
        let mut max_label = vec![63];
        max_label.extend_from_slice(&[b'a'; 63]);
        max_label.push(0);
        let raw = raw_query(&max_label, 1);
        let view = parse_query(&raw).unwrap();
        let mut dotted = [0u8; MAX_NAME_LEN];
        assert_eq!(dotted_name(&view, &mut dotted), Some(63));

        // 255 bytes is the longest name; the key buffer is exactly big enough.
        let longest = raw_query(&name_of_len(255), 1);
        let view = parse_query(&longest).unwrap();
        assert_eq!(view.qname_len, 255);
        assert_eq!(canonical_key(&view, &mut [0u8; MIN_CANONICAL_BUFFER]), Some(MIN_CANONICAL_BUFFER));
        assert!(parse_query(&raw_query(&name_of_len(256), 1)).is_none());
        let mut out = [0u8; MAX_NAME_LEN];
        assert!(read_name(&longest, 12, &mut out).is_some());
        assert!(read_name(&raw_query(&name_of_len(256), 1), 12, &mut out).is_none());

        // `dotted_target` reads unvalidated wire: 64 is not a label length.
        let label = |len: usize| {
            let mut wire = vec![len as u8];
            wire.extend(std::iter::repeat_n(b'a', len));
            wire.push(0);
            wire
        };
        assert_eq!(dotted_target(&label(63), &mut out), Some(63));
        assert_eq!(dotted_target(&label(64), &mut out), None);
    }

    #[test]
    fn a_name_may_follow_128_pointers_and_no_more() {
        // A root label at 12, then pointers at 14, 16, ... each to the one
        // before; later targets exceed 255, so the 14-bit offset matters.
        let chain = |jumps: usize| {
            let mut raw = vec![0u8; 14];
            for i in 1..=jumps {
                let target = 12 + 2 * (i - 1);
                raw.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
            }
            raw
        };
        let mut out = [0u8; MAX_NAME_LEN];
        let ok = chain(128);
        let info = read_name(&ok, ok.len() - 2, &mut out).unwrap();
        assert_eq!((info.len, info.compressed), (1, true));
        let too_long = chain(129);
        assert!(read_name(&too_long, too_long.len() - 2, &mut out).is_none());
    }

    fn query_with_opt(rdata: &[u8]) -> Vec<u8> {
        let mut raw = raw_query(&wire_name("a.test"), 1);
        append_record(&mut raw, 41, 1232, 0, rdata);
        raw
    }

    fn edns_option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut out = code.to_be_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn every_edns_option_is_examined_in_turn() {
        let kinds = |options: &[Vec<u8>]| {
            let raw = query_with_opt(&options.concat());
            let view = parse_query(&raw)?;
            Some((view.edns_options, view.edns_hop_options, view.edns_bad_ecs))
        };
        let padding = edns_option(12, &[0, 0]);
        let unknown = edns_option(65001, &[]);
        let good_ecs = edns_option(8, &[0, 1, 0, 0]);
        let bad_ecs = edns_option(8, &[0, 3, 0, 0]);
        assert_eq!(kinds(&[edns_option(12, &[])]), Some((false, true, false)), "a final option without data");
        assert_eq!(kinds(&[padding.clone(), unknown.clone()]), Some((true, true, false)));
        assert_eq!(kinds(&[unknown.clone(), padding.clone()]), Some((true, true, false)));
        assert_eq!(kinds(&[good_ecs.clone(), padding.clone(), bad_ecs.clone()]), Some((false, true, true)));
        assert_eq!(kinds(&[good_ecs, padding.clone()]), Some((false, true, false)));

        // A truncated option header or body is malformed, even when more
        // records follow the OPT.
        assert_eq!(kinds(&[vec![0, 12, 0, 5, 1, 1, 1, 1]]), None, "length past the RDATA");
        let mut raw = query_with_opt(&[0, 12, 0]);
        append_record(&mut raw, 1, 1, 60, &A_RDATA);
        assert!(parse_query(&raw).is_none(), "3 stray bytes");
        assert!(parse_query(&query_with_opt(&[padding, vec![0, 12, 0]].concat())).is_none());
    }

    #[test]
    fn query_flags_and_counts_are_read_exactly() {
        for (byte, bit) in [(2usize, 0x04u8), (2, 0x02), (3, 0x40)] {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            raw[byte] |= bit;
            assert!(parse_query(&raw).unwrap().unfamiliar_header_flags, "byte {byte} bit {bit:#x}");
        }
        let mut no_rd = raw_query(&wire_name("a.test"), 1);
        no_rd[2] = 0;
        let view = parse_query(&no_rd).unwrap();
        assert!(!view.rd && !view.cd && !view.unfamiliar_header_flags);
        for count_at in [7usize, 9] {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            raw[count_at] = 1;
            raw.extend_from_slice(&rr("a.test", 1, &A_RDATA));
            assert!(parse_query(&raw).unwrap().has_answer_or_authority, "count at {count_at}");
        }
    }

    #[test]
    fn suffix_offset_walks_a_maximum_label() {
        let mut name = vec![63];
        name.extend_from_slice(&[b'a'; 63]);
        name.extend_from_slice(&wire_name("com"));
        assert_eq!(suffix_offset(&wire_name("com"), &name), Some(64));
        assert_eq!(suffix_offset(&wire_name("net"), &name), None);
        // A label over 63 bytes is not skipped, even when the parent follows it.
        let mut bad = vec![64];
        bad.extend_from_slice(&[b'a'; 64]);
        bad.extend_from_slice(&wire_name("com"));
        assert_eq!(suffix_offset(&wire_name("com"), &bad), None);
    }

    #[test]
    fn edns_version_and_flags_come_from_the_opt_ttl() {
        let flags = |ttl: u32| {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            append_record(&mut raw, 41, 1232, ttl, &[]);
            let view = parse_query(&raw).unwrap();
            (view.edns_version, view.edns_do, view.edns_other_flags, view.edns_flags)
        };
        assert_eq!(flags(0), (0, false, false, 0));
        assert_eq!(flags(0x0001_0000), (1, false, false, 0));
        assert_eq!(flags(0x0000_8000), (0, true, false, 0x8000));
        assert_eq!(flags(0x0000_4000), (0, false, true, 0x4000), "CO is another flag");
        assert_eq!(flags(0x0200_c001), (0, true, true, 0xc001));
    }

    #[test]
    fn contradictions_are_judged_per_owner_and_covered_type() {
        let qname = wire_name("a.test");
        let rrsig = |owner: &str, covered: u16| rr(owner, 46, &[&covered.to_be_bytes()[..], &[0; 16]].concat());
        let alias = cname_rr("a.test", "b.test");
        let verdict =
            |rcode: u8, answers: &[Vec<u8>]| terminal_answer(&reply(rcode, answers, &[soa_rr("")]), &qname, 1);

        // NXDOMAIN: aliases and signatures over them are no data; anything else
        // at the name or along the chain contradicts it, but not elsewhere.
        assert_eq!(verdict(3, &[alias.clone(), rrsig("a.test", 5)]), Some(true));
        assert_eq!(verdict(3, &[alias.clone(), rrsig("a.test", 1)]), None);
        assert_eq!(verdict(3, &[alias.clone(), rr("b.test", 1, &A_RDATA)]), None);
        assert_eq!(verdict(3, &[alias.clone(), rr("other.test", 1, &A_RDATA)]), Some(true));
        let dname = rr("test", 39, &wire_name("t.example"));
        assert_eq!(
            verdict(3, &[dname.clone(), rr("a.t.example", 1, &A_RDATA)]),
            None,
            "the DNAME's rewrite is on the chain"
        );
        assert_eq!(verdict(3, &[dname]), Some(true));

        // NOERROR whose chain ends at a name holding only other types.
        assert_eq!(verdict(0, std::slice::from_ref(&alias)), Some(true), "an alias to nothing is NODATA");
        assert_eq!(verdict(0, &[alias.clone(), rr("b.test", 16, b"\x01x")]), None);
        assert_eq!(verdict(0, &[alias.clone(), rr("other.test", 16, b"\x01x")]), Some(true), "off the chain");
        assert_eq!(verdict(0, &[alias.clone(), rrsig("b.test", 1)]), Some(true), "a signature over the queried type");
        assert_eq!(verdict(0, &[alias.clone(), rrsig("b.test", 5)]), Some(true), "over an alias");
        assert_eq!(verdict(0, &[alias.clone(), rrsig("b.test", 39)]), Some(true), "over a DNAME");
        assert_eq!(verdict(0, &[alias, rrsig("b.test", 16)]), None, "over another type");
    }

    fn dname_record(owner: &str, target: &[u8]) -> ChainRecord {
        ChainRecord { name: wire_name(owner).into(), rtype: DNAME_TYPE, target: Some(target.into()) }
    }

    #[test]
    fn dname_next_takes_the_shortest_owner_and_refuses_a_tie() {
        let current = wire_name("x.sub.example.com");
        let sub_to_b = dname_record("sub.example.com", &wire_name("b.net"));
        let example_to_a = dname_record("example.com", &wire_name("a.net"));
        let expect = |next: ChainNext, name: &str| match next {
            ChainNext::Next(next) => assert_eq!(&*next, wire_name(name).as_slice()),
            _ => panic!("expected {name}"),
        };
        // The DNAME nearest the root applies first, whatever the record order.
        expect(dname_next(&[sub_to_b, example_to_a], &current), "x.sub.a.net");
        let sub_to_b = dname_record("sub.example.com", &wire_name("b.net"));
        let example_to_a = dname_record("example.com", &wire_name("a.net"));
        expect(dname_next(&[example_to_a, sub_to_b], &current), "x.sub.a.net");
        // Two targets at one owner are ambiguous; a repeated one is not.
        let one = dname_record("example.com", &wire_name("a.net"));
        let other = dname_record("example.com", &wire_name("c.net"));
        let again = dname_record("example.com", &wire_name("a.net"));
        assert!(matches!(dname_next(&[one, other], &current), ChainNext::Ambiguous));
        let one = dname_record("example.com", &wire_name("a.net"));
        expect(dname_next(&[one, again], &current), "x.sub.a.net");
        // The rewritten name may be 255 bytes, not 256.
        let current = wire_name("x.o");
        for (target_len, fits) in [(253, true), (254, false)] {
            let chain = [dname_record("o", &name_of_len(target_len))];
            assert_eq!(matches!(dname_next(&chain, &current), ChainNext::Next(_)), fits, "target {target_len}");
        }
    }

    #[test]
    fn terminal_answer_checks_the_question_and_bounds_alias_records() {
        let qname = wire_name("a.test");
        let answer = reply(0, &[rr("a.test", 1, &A_RDATA)], &[soa_rr("")]);
        assert_eq!(terminal_answer(&answer, &qname, 1), Some(true));
        assert_eq!(terminal_answer(&answer, &qname, 28), Some(false), "another type");
        assert_eq!(terminal_answer(&answer, &wire_name("b.test"), 1), Some(false), "another name");

        // The 64-record alias bound counts CNAME and DNAME records, not the
        // chain: 64 unrelated aliases still pass, 65 do not.
        let with_aliases = |n: usize| {
            let mut answers = vec![rr("a.test", 1, &A_RDATA)];
            answers.extend((0..n).map(|i| cname_rr(&format!("junk{i}.test"), "t.test")));
            reply(0, &answers, &[])
        };
        assert_eq!(terminal_answer(&with_aliases(64), &qname, 1), Some(true));
        assert_eq!(terminal_answer(&with_aliases(65), &qname, 1), Some(false));

        // Two different CNAME targets at one owner conflict; a repeat does not.
        let b = rr("b.test", 1, &A_RDATA);
        let conflict = reply(0, &[cname_rr("a.test", "b.test"), cname_rr("a.test", "c.test"), b.clone()], &[]);
        assert_eq!(terminal_answer(&conflict, &qname, 1), Some(false));
        let repeated = reply(0, &[cname_rr("a.test", "b.test"), cname_rr("a.test", "b.test"), b], &[]);
        assert_eq!(terminal_answer(&repeated, &qname, 1), Some(true));
    }

    #[test]
    fn plain_scrub_applies_a_dname_below_its_owner_only() {
        // A DNAME puts its target on the chain for a name below the owner...
        let below = reply(0, &[rr("test", 39, &wire_name("t.example"))], &[soa_rr("example")]);
        assert_eq!(scrub_plain_reply(&below), Some(None), "the target's SOA is kept");
        // ...but not for the owner itself (RFC 6672 §2.4).
        let own = reply(0, &[rr("a.test", 39, &wire_name("t.example"))], &[soa_rr("example")]);
        assert!(scrub_plain_reply(&own).unwrap().is_some(), "the target's SOA is dropped");
    }

    #[test]
    fn plain_scrub_trusts_denial_proofs_only_under_a_kept_zone() {
        // An NSEC below the question name, with no SOA or NS above it, proves
        // nothing the reply may carry.
        let stray = reply(0, &[rr("a.test", 1, &A_RDATA)], &[rr("x.a.test", 47, &[0, 1, 2])]);
        let scrubbed = scrub_plain_reply(&stray).unwrap().expect("dropped");
        assert_eq!(&scrubbed[8..10], &[0, 0], "no authority record is left");
        let stray = reply(3, &[], &[rr("x.a.test", 47, &[0, 1, 2])]);
        assert_eq!(&scrub_plain_reply(&stray).unwrap().unwrap()[8..10], &[0, 0]);
        // Under a kept SOA zone it stays.
        let proof = reply(3, &[], &[soa_rr("test"), rr("x.a.test", 47, &[0, 1, 2])]);
        assert_eq!(scrub_plain_reply(&proof), Some(None));
    }

    #[test]
    fn plain_scrub_checks_denial_owners_against_many_zones_quickly() {
        // 2300 NS records at `test` and 2300 NSEC records whose 120-label
        // owner is under no zone, all compressed into one 62 KB reply. Each
        // owner is checked by its ancestors, not against every zone.
        let mut m = vec![0, 7, 0x81, 0x80, 0, 1, 0, 0];
        m.extend_from_slice(&4600u16.to_be_bytes());
        m.extend_from_slice(&[0, 0]);
        m.extend_from_slice(b"\x01a\x04test\x00\x00\x01\x00\x01");
        let long_at = m.len();
        for _ in 0..120 {
            m.extend_from_slice(b"\x01x");
        }
        m.push(0);
        m.extend_from_slice(&[0, 47, 0, 1, 0, 0, 0, 60, 0, 1, 0]);
        for _ in 0..2300 {
            m.extend_from_slice(&[0xc0, 14, 0, 2, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 14]);
        }
        for _ in 1..2300 {
            m.extend_from_slice(&[0xc0 | (long_at >> 8) as u8, long_at as u8]);
            m.extend_from_slice(&[0, 47, 0, 1, 0, 0, 0, 60, 0, 1, 0]);
        }
        let started = std::time::Instant::now();
        // The NSEC records are dropped; the rewrite, with names expanded,
        // would not fit a message, so the reply is refused.
        assert_eq!(scrub_plain_reply(&m), None);
        let limit = if cfg!(debug_assertions) { 1000 } else { 50 };
        assert!(started.elapsed().as_millis() < limit, "{:?}", started.elapsed());
    }

    #[test]
    fn plain_scrub_stops_growing_the_chain_past_64_names() {
        // `t0 -> u` precedes the records that put t0 on the chain, so u joins
        // on the second pass; the bound stops that pass once the chain holds
        // more than 64 names.
        let reply_with = |targets: usize| {
            let mut answers = vec![cname_rr("t0.test", "u.test"), rr("u.test", 1, &A_RDATA)];
            answers.extend((0..targets).map(|i| cname_rr("a.test", &format!("t{i}.test"))));
            scrub_plain_reply(&reply(0, &answers, &[]))
        };
        assert_eq!(reply_with(62), Some(None), "63 names");
        assert_eq!(reply_with(63), Some(None), "64 names still grow");
        assert_eq!(reply_with(64), None, "65 names stop");
        assert_eq!(reply_with(70), None, "71 names stop");
    }

    #[test]
    fn set_do_bit_and_opt_version_look_only_in_the_additional_section() {
        // Type-41 records in Answer and Authority are not the OPT.
        let mut raw = raw_query(&wire_name("a.test"), 1);
        raw[7] = 1;
        raw[9] = 1;
        raw[11] = 1;
        raw.extend_from_slice(&rr("", 41, &[]));
        raw.extend_from_slice(&rr("", 41, &[]));
        raw.extend_from_slice(&rr("", 1, &A_RDATA));
        assert_eq!(opt_version(&raw), None);
        let out = set_do_bit(&raw).unwrap();
        assert_eq!(out.len(), raw.len() + 11, "a new OPT is appended");
        assert_eq!(&out[10..12], &[0, 2]);
        assert_eq!(&out[12..raw.len()], &raw[12..], "the lookalikes are untouched");

        // A non-OPT additional record is not the OPT either.
        let mut raw = raw_query(&wire_name("a.test"), 1);
        raw[11] = 2;
        let mut odd = rr("", 1, &A_RDATA);
        odd[5..9].copy_from_slice(&0x0007_0000u32.to_be_bytes());
        raw.extend_from_slice(&odd);
        assert_eq!(opt_version(&raw), None);
        let mut opt = rr("", 41, &[]);
        opt[5..9].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        raw.extend_from_slice(&opt);
        assert_eq!(opt_version(&raw), Some(2));
    }

    #[test]
    fn set_do_bit_refuses_trailing_bytes_and_an_oversize_result() {
        let mut trailing = raw_query(&wire_name("a.test"), 1);
        trailing.push(0);
        assert_eq!(set_do_bit(&trailing), None);

        // 35 bytes of message plus the TXT data; +11 for the OPT must fit 65535.
        let sized = |total: usize| {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            raw[11] = 1;
            let data = vec![0u8; total - 35];
            raw.extend_from_slice(&rr("", 16, &data));
            assert_eq!(raw.len(), total);
            raw
        };
        let fits = set_do_bit(&sized(65_524)).unwrap();
        assert_eq!(fits.len(), 65_535);
        assert_eq!(&fits[10..12], &[0, 2]);
        assert_eq!(set_do_bit(&sized(65_525)), None);
    }

    #[test]
    fn set_do_bit_patches_an_existing_opt_in_a_maximum_size_message() {
        let with_opt = |ttl: u32, total: usize| {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            append_record(&mut raw, 41, 1232, ttl, &vec![0u8; total - 35]);
            assert_eq!(raw.len(), total);
            raw
        };
        // Nothing is appended, so a 65535-byte message is fine; 65536 is not a message.
        let out = set_do_bit(&with_opt(0, 65_535)).unwrap();
        assert_eq!(&out[out.len() - 65_500 - 6..out.len() - 65_500 - 2], &0x8000u32.to_be_bytes());
        assert_eq!(set_do_bit(&with_opt(0, 65_536)), None);
        // An OPT that already has DO keeps it.
        let out = set_do_bit(&with_opt(0x8000, 100)).unwrap();
        assert_eq!(&out[out.len() - 65 - 6..out.len() - 65 - 2], &0x8000u32.to_be_bytes());
    }

    #[test]
    fn a_plain_additional_record_does_not_force_a_rewrite() {
        let mut raw = reply(0, &[rr("a.test", 1, &A_RDATA)], &[]);
        raw[11] = 1;
        raw.extend_from_slice(&rr("a.test", 1, &A_RDATA));
        assert!(matches!(normalize_upstream(&raw).unwrap(), std::borrow::Cow::Borrowed(_)));
        // A TSIG in Additional does: it is dropped from the relay.
        raw[11] = 2;
        raw.extend_from_slice(&rr("k", 250, &[0; 22]));
        let relayed = normalize_upstream(&raw).unwrap();
        assert!(matches!(relayed, std::borrow::Cow::Owned(_)));
        assert_eq!(&relayed[10..12], &[0, 1]);
    }

    #[test]
    fn minimal_error_response_builds_the_exact_header() {
        let request = |flags: u16| {
            let mut raw = raw_query(&wire_name("a.test"), 1);
            raw[2..4].copy_from_slice(&flags.to_be_bytes());
            raw
        };
        let flags = |reply: &[u8]| u16::from_be_bytes([reply[2], reply[3]]);
        // QR, RA, the client's RD and CD, its opcode (NOTIFY) and the RCODE;
        // AD, AA and Z are not echoed.
        let reply = minimal_error_response(&request(0x2110), 5).unwrap();
        assert_eq!(flags(&reply), 0x8000 | 0x0080 | 0x0100 | 0x0010 | 0x2000 | 5);
        let reply = minimal_error_response(&request(0x0100 | 0x0020 | 0x0400 | 0x0040), 2).unwrap();
        assert_eq!(flags(&reply), 0x8080 | 0x0100 | 2);
        let reply = minimal_error_response(&request(0), 5).unwrap();
        assert_eq!(flags(&reply), 0x8080 | 5);
        // No OPT for a client without EDNS, unless the RCODE needs its high bits.
        assert_eq!(&reply[10..12], &[0, 0]);
        let badvers = minimal_error_response(&request(0), 16).unwrap();
        assert_eq!(&badvers[10..12], &[0, 1]);
        assert_eq!(flags(&badvers) & 0xf, 0);
        assert_eq!(&badvers[badvers.len() - 6..badvers.len() - 2], &[1, 0, 0, 0], "extended RCODE 1, no DO");
    }

    #[test]
    fn truncated_replies_carry_the_exact_header_and_both_builders_agree() {
        let mut query = hickory_query("a.test.", RecordType::A);
        query.metadata.checking_disabled = true;
        query.metadata.op_code = OpCode::Notify;
        query.edns.get_or_insert_with(Edns::new).set_dnssec_ok(true);
        let query = query.to_vec().unwrap();
        let view = parse_query(&query).unwrap();
        let nx = reply(3, &[], &[]);

        let built = truncated_response(&view, &nx, 1232).unwrap();
        let mut into = vec![9; 5];
        truncated_response_into(&view, &nx, 1232, &mut into).unwrap();
        assert_eq!(built, into);
        let flags = u16::from_be_bytes([built[2], built[3]]);
        assert_eq!(flags, QR_BIT | TC_BIT | RA_BIT | RD_BIT | CD_BIT | (4 << 11) | 3);
        assert_eq!(&built[..2], &[0x12, 0x34]);
        assert_eq!(&built[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
        assert!(truncated_response(&view, &[0; 11], 1232).is_none());
    }

    #[test]
    fn ttl_fields_finds_the_authority_soa_by_section_and_type() {
        let negative =
            ttl_fields(&reply(3, &[cname_rr("a.test", "b.test")], &[soa_rr("test"), soa_rr("a.test")])).unwrap();
        assert_eq!(negative.offsets.len(), 3);
        assert_eq!(negative.soa, Some(negative.offsets[1]), "the first SOA, not the CNAME");
        let positive =
            ttl_fields(&reply(0, &[rr("a.test", 1, &A_RDATA)], &[rr("test", 2, &wire_name("ns.test"))])).unwrap();
        assert_eq!(positive.soa, None);
        let answer_soa = ttl_fields(&reply(0, &[soa_rr("a.test")], &[])).unwrap();
        assert_eq!(answer_soa.soa, None, "an SOA in Answer is not the negative SOA");
    }

    #[test]
    fn validated_rdata_layouts_cover_their_types() {
        for rtype in [6u16, 13, 15, 16, 18, 21, 24, 26, 30, 35, 36] {
            assert!(rdata_layout(rtype, 1).is_some(), "type {rtype}");
        }
        assert!(rdata_layout(11, 1).is_some() && rdata_layout(11, 3).is_none(), "WKS is IN-only");
        assert!(rdata_layout(28, 1).is_some() && rdata_layout(28, 3).is_none(), "AAAA layout is IN-only");

        for (rtype, rdata) in [
            (13u16, &b"\x03abc\x02de"[..]),
            (15, b"\x00\x0a\x01b\x00"),
            (16, b"\x03abc\x01d"),
            (30, b"\x01b\x00\x01\x02"),
            (35, b"\x00\x01\x00\x02\x01U\x03sip\x00\x00"),
            (6, &[0; 22]),
            (26, b"\x00\x01\x00\x00"),
            (24, &[0; 19]),
        ] {
            let raw = response_with(rtype, 1, rdata);
            assert_eq!(normalize_upstream(&raw).as_deref(), Some(raw.as_slice()), "valid type {rtype}");
        }
        for (rtype, rdata) in [
            (13u16, &b"\x03abc"[..]),
            (15, b"\x00"),
            (16, b"\x05ab"),
            (16, b""),
            (30, b"\x03bad"),
            (35, b"\x00\x01\x00\x02\x05U"),
            (28, &[0; 15]),
            (6, &[0; 21]),
            (26, b"\x00\x01\x00"),
            (24, &[0; 17]),
        ] {
            assert!(normalize_upstream(&response_with(rtype, 1, rdata)).is_none(), "invalid type {rtype}");
        }
    }

    #[test]
    fn upstream_opt_rules_and_a_question_only_reply() {
        let a = rr("a.test", 1, &A_RDATA);
        let with_additional = |records: &[Vec<u8>]| {
            let mut raw = reply(0, std::slice::from_ref(&a), &[]);
            raw[11] = records.len() as u8;
            records.iter().for_each(|record| raw.extend_from_slice(record));
            normalize_upstream(&raw).is_some()
        };
        let opt = rr("", 41, &[]);
        assert!(with_additional(std::slice::from_ref(&opt)));
        assert!(with_additional(&[a.clone(), opt.clone()]), "an OPT after another additional record");
        assert!(!with_additional(&[opt.clone(), opt]), "one OPT only");
        // Header and question alone are a whole message.
        assert!(normalize_upstream(&reply(0, &[], &[])).is_some());
    }

    #[test]
    fn hickory_view_places_each_record_in_its_own_section() {
        let sig = rr("a.test", 24, &[0u8; 19]);
        // A SIG is only legal in Additional: in Answer it becomes a placeholder.
        let mut raw = reply(0, std::slice::from_ref(&sig), &[soa_rr("")]);
        raw[11] = 1;
        raw.extend_from_slice(&rr("a.test", 1, &A_RDATA));
        let view = hickory_view(&normalize_upstream(&raw).unwrap()).unwrap();
        assert_eq!((view.answers.len(), view.authorities.len(), view.additionals.len()), (1, 1, 1));
        assert_eq!(u16::from(view.answers[0].record_type()), VIEW_PLACEHOLDER_TYPE);
        // As the first Additional record it is kept as it is (an empty-RDATA
        // answer forces the per-record path).
        let mut raw = reply(0, &[rr("a.test", 1, &A_RDATA), rr("a.test", 65400, &[])], &[]);
        raw[11] = 1;
        raw.extend_from_slice(&sig);
        let view = hickory_view(&normalize_upstream(&raw).unwrap()).unwrap();
        assert_eq!(u16::from(view.additionals[0].record_type()), 24);
    }

    #[test]
    fn hickory_view_remaps_a_question_type_it_replaced_in_the_answer() {
        let mut raw = response_with(65400, 1, b"");
        raw[15..17].copy_from_slice(&65400u16.to_be_bytes());
        let kept = normalize_upstream(&raw).unwrap();
        let view = hickory_view(&kept).unwrap();
        assert_eq!(u16::from(view.queries[0].query_type()), VIEW_PLACEHOLDER_TYPE);
        assert_eq!(u16::from(view.answers[0].record_type()), VIEW_PLACEHOLDER_TYPE);
    }
}
