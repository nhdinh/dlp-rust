//! Mock AD LDAP server — sends pre-encoded BER responses for test data.
//!
//! Run: `cargo run -p mock_ad` (binds 127.0.0.1:3389)
//!
//! Test entries (pre-encoded in BER):
//!   jsmith  → memberOf: Domain Users, Finance
//!   admin   → memberOf: Domain Admins, dlp-editors
//!   WORKSTATION1 → dlpDeviceTrust=Managed, dlpNetworkLocation=Corporate
//!   LAPTOP-42    → dlpDeviceTrust=Compliant, dlpNetworkLocation=CorporateVpn
//!
//! ## Manual BER encoding notes
//!
//! BER length encoding: <0x80 = short form (1 byte); >=0x80 = long form (count byte | 0x80, then count bytes).
//! LDAPMessage: SEQUENCE { INTEGER (messageID), ApplicationN { ... } }
//!
//! This server speaks LDAPv3 over TCP (no TLS) on port 3389.

use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

fn main() -> std::io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(3389);

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr)?;
    eprintln!("Mock AD LDAP server listening on {addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = serve(&mut s) {
                    eprintln!("connection error: {e}");
                }
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn serve(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let mut closed = false;

    while !closed {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        let mut pos = 0;
        while pos < n {
            let (response, consumed, conn_close) = dispatch(&buf[pos..n]);
            closed = conn_close;
            if !response.is_empty() {
                stream.write_all(&response)?;
            }
            if consumed == 0 {
                break;
            }
            pos += consumed;
        }
    }
    Ok(())
}

/// Returns (response_bytes, bytes_consumed, connection_closed).
fn dispatch(buf: &[u8]) -> (Vec<u8>, usize, bool) {
    // Must have at least: SEQUENCE header + length + messageID INTEGER + op tag
    if buf.len() < 6 {
        return (vec![], 0, false);
    }

    // Read outer SEQUENCE length
    let (_, hdr_len) = match read_len(&buf[1..]) {
        Some((l, n)) => (l, n),
        None => return (vec![], 0, false),
    };

    let total_len = 2
        + hdr_len
        + match read_len(&buf[1..]) {
            Some((l, _)) => l,
            None => return (vec![], 0, false),
        };

    if buf.len() < total_len {
        return (vec![], 0, false);
    }

    // Skip outer SEQUENCE + length
    let inner = &buf[2 + hdr_len..total_len];

    // Get op tag
    if inner.len() < 3 {
        return (vec![], total_len, false);
    }

    // Read messageID (INTEGER at start of inner)
    let (_, id_len) = match read_int(&inner) {
        Some((_, l)) => ((), l),
        None => ((), 0),
    };
    let after_id = id_len;
    if inner.len() < after_id + 1 {
        return (vec![], total_len, false);
    }
    let op_tag = inner[after_id];

    let (response, conn_close) = match op_tag {
        // BIND_REQUEST
        0x60 => (BIND_RESPONSE.to_vec(), false),
        // SEARCH_REQUEST
        0x63 => {
            // Extract base DN string from search request
            let base_dn = extract_base_dn(inner);
            let responses = build_search_response(&base_dn);
            (responses, false)
        }
        // UNBIND_REQUEST
        0x42 => (vec![], true),
        _ => (vec![], false),
    };

    (response, total_len, conn_close)
}

// ─── Pre-encoded responses ─────────────────────────────────────────────────────

// BindResponse: success (resultCode=0), no matched DN, no diagnostic message
const BIND_RESPONSE: &[u8] = &[
    // LDAPMessage: SEQUENCE { messageID=1, bindResponse }
    0x30, 0x0F, // SEQUENCE, length=15
    0x02, 0x01, 0x01, // INTEGER messageID = 1
    0x61, 0x0A, // [APPLICATION 1] BindResponse, length=10
    0x0A, 0x01, 0x00, // ENUMERATED resultCode = success (0)
    0x04, 0x01, 0x00, // OCTET STRING matchedDN = ""
    0x04, 0x00, // OCTET STRING diagnosticMessage = ""
];

// SearchResultEntry for jsmith (memberOf attribute only)
fn jsmith_entry() -> Vec<u8> {
    let dn = b"CN=jsmith,CN=Users,DC=mock,DC=local";
    let g1 = b"CN=Domain Users,SID=S-1-5-21-10,CN=Users,DC=mock,DC=local";
    let g2 = b"CN=Finance,SID=S-1-5-21-11,CN=Users,DC=mock,DC=local";

    // memberOf SET { OCTET STRING (g1), OCTET STRING (g2) }
    let mut groups_inner = ber_octet_string(g1);
    groups_inner.extend_from_slice(&ber_octet_string(g2));
    let groups = ber_set(&groups_inner);

    // Attribute: { OCTET STRING ("memberOf"), SET { groups } }
    let mut attr_inner = ber_octet_string(b"memberOf");
    attr_inner.extend_from_slice(&groups);
    let attr = ber_sequence(&attr_inner);

    // Attributes SET { attr }
    let attrs_inner = attr;
    let attrs = ber_set(&attrs_inner);

    // Entry: { DN, attrs }
    let mut entry_body = ber_octet_string(dn);
    entry_body.extend_from_slice(&attrs);

    ldap_msg(0x64, &entry_body)
}

// SearchResultEntry for admin
fn admin_entry() -> Vec<u8> {
    let dn = b"CN=admin,CN=Users,DC=mock,DC=local";
    let g1 = b"CN=Domain Admins,SID=S-1-5-21-20,CN=Users,DC=mock,DC=local";
    let g2 = b"CN=dlp-editors,SID=S-1-5-21-21,CN=Users,DC=mock,DC=local";

    let mut groups_inner = ber_octet_string(g1);
    groups_inner.extend_from_slice(&ber_octet_string(g2));
    let groups = ber_set(&groups_inner);

    let mut attr_inner = ber_octet_string(b"memberOf");
    attr_inner.extend_from_slice(&groups);
    let attr = ber_sequence(&attr_inner);

    let attrs_inner = attr;
    let attrs = ber_set(&attrs_inner);

    let mut entry_body = ber_octet_string(dn);
    entry_body.extend_from_slice(&attrs);

    ldap_msg(0x64, &entry_body)
}

// SearchResultEntry for WORKSTATION1 (device trust)
fn workstation1_entry() -> Vec<u8> {
    let dn = b"CN=WORKSTATION1,CN=Computers,DC=mock,DC=local";

    // dlpDeviceTrust attribute
    let trust_val = ber_set(&ber_octet_string(b"Managed"));
    let mut trust_attr_body = ber_octet_string(b"dlpDeviceTrust");
    trust_attr_body.extend_from_slice(&trust_val);
    let trust_attr = ber_sequence(&trust_attr_body);

    // dlpNetworkLocation attribute
    let loc_val = ber_set(&ber_octet_string(b"Corporate"));
    let mut loc_attr_body = ber_octet_string(b"dlpNetworkLocation");
    loc_attr_body.extend_from_slice(&loc_val);
    let loc_attr = ber_sequence(&loc_attr_body);

    // Attributes SET { trust, location }
    let mut attrs_inner = trust_attr;
    attrs_inner.extend_from_slice(&loc_attr);
    let attrs = ber_set(&attrs_inner);

    // Entry: { DN, attrs }
    let mut entry_body = ber_octet_string(dn);
    entry_body.extend_from_slice(&attrs);

    ldap_msg(0x64, &entry_body)
}

// SearchResultEntry for LAPTOP-42
fn laptop42_entry() -> Vec<u8> {
    let dn = b"CN=LAPTOP-42,CN=Computers,DC=mock,DC=local";

    // dlpDeviceTrust attribute
    let trust_val = ber_set(&ber_octet_string(b"Compliant"));
    let mut trust_attr_body = ber_octet_string(b"dlpDeviceTrust");
    trust_attr_body.extend_from_slice(&trust_val);
    let trust_attr = ber_sequence(&trust_attr_body);

    // dlpNetworkLocation attribute
    let loc_val = ber_set(&ber_octet_string(b"CorporateVpn"));
    let mut loc_attr_body = ber_octet_string(b"dlpNetworkLocation");
    loc_attr_body.extend_from_slice(&loc_val);
    let loc_attr = ber_sequence(&loc_attr_body);

    // Attributes SET { trust, location }
    let mut attrs_inner = trust_attr;
    attrs_inner.extend_from_slice(&loc_attr);
    let attrs = ber_set(&attrs_inner);

    // Entry: { DN, attrs }
    let mut entry_body = ber_octet_string(dn);
    entry_body.extend_from_slice(&attrs);

    ldap_msg(0x64, &entry_body)
}

// SearchResultDone: success
fn search_done() -> Vec<u8> {
    let result = [
        ber_enumerated(0),     // resultCode = success
        ber_octet_string(&[]), // matchedDN = ""
        ber_octet_string(&[]), // diagnosticMessage = ""
    ]
    .concat();

    ldap_msg(0x65, &result) // 0x65 = SEARCH_RESULT_DONE
}

// ─── Response builder ──────────────────────────────────────────────────────────

fn build_search_response(base_dn: &str) -> Vec<u8> {
    let up = base_dn.to_uppercase();

    let mut out = Vec::new();

    let jsmith_match = up.contains("JSMITH")
        || up.contains("S-1-5-21-100")
        || (up.contains("MOCK") && up.contains("USERS"));
    let admin_match = up.contains("ADMIN")
        || up.contains("S-1-5-21-200")
        || (up.contains("MOCK") && up.contains("USERS"));
    let ws1_match =
        up.contains("WORKSTATION1") || (up.contains("MOCK") && up.contains("COMPUTERS"));
    let laptop_match =
        up.contains("LAPTOP-42") || (up.contains("MOCK") && up.contains("COMPUTERS"));

    if jsmith_match {
        out.extend(jsmith_entry());
    }
    if admin_match {
        out.extend(admin_entry());
    }
    if ws1_match {
        out.extend(workstation1_entry());
    }
    if laptop_match {
        out.extend(laptop42_entry());
    }

    out.extend(search_done());
    out
}

// ─── BER encoding helpers ──────────────────────────────────────────────────────

fn ldap_msg(app_tag: u8, body: &[u8]) -> Vec<u8> {
    // LDAPMessage = SEQUENCE { INTEGER messageID=1, APPLICATION tag body }
    let inner = [ber_integer(1).as_slice(), &[app_tag], body].concat();
    ber_sequence(&inner)
}

fn ber_integer(val: i32) -> Vec<u8> {
    let bytes = val.to_le_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let relevant = &bytes[first_nonzero..];
    std::iter::once(0x02u8)
        .chain(ber_len(relevant.len()))
        .chain(relevant.iter().copied())
        .collect()
}

fn ber_enumerated(val: i32) -> Vec<u8> {
    // ENUMERATED is INTEGER with tag 0x0A
    let bytes = val.to_le_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let relevant = &bytes[first_nonzero..];
    std::iter::once(0x0Au8)
        .chain(ber_len(relevant.len()))
        .chain(relevant.iter().copied())
        .collect()
}

fn ber_octet_string(s: &[u8]) -> Vec<u8> {
    std::iter::once(0x04)
        .chain(ber_len(s.len()))
        .chain(s.iter().copied())
        .collect()
}

fn ber_sequence(body: impl AsRef<[u8]>) -> Vec<u8> {
    let body = body.as_ref();
    std::iter::once(0x30)
        .chain(ber_len(body.len()))
        .chain(body.iter().copied())
        .collect()
}

fn ber_set(body: impl AsRef<[u8]>) -> Vec<u8> {
    let body = body.as_ref();
    std::iter::once(0x31)
        .chain(ber_len(body.len()))
        .chain(body.iter().copied())
        .collect()
}

fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut octets = Vec::new();
        let mut n = len;
        while n > 0 {
            octets.push((n & 0xFF) as u8);
            n >>= 8;
        }
        octets.reverse();
        std::iter::once(octets.len() as u8 | 0x80)
            .chain(octets.into_iter())
            .collect()
    }
}

// ─── BER parsing helpers ───────────────────────────────────────────────────────

fn read_len(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let cnt = (first & 0x7F) as usize;
        if buf.len() < 1 + cnt {
            return None;
        }
        let mut len = 0usize;
        for &b in &buf[1..1 + cnt] {
            len = len * 256 + (b as usize);
        }
        Some((len, 1 + cnt))
    }
}

fn read_int(buf: &[u8]) -> Option<(i32, usize)> {
    if buf.first()? != &0x02 {
        return None;
    }
    let (len, len_len) = read_len(&buf[1..])?;
    let end = 1 + len_len + len;
    if buf.len() < end {
        return None;
    }
    let bytes = &buf[1 + len_len..end];
    let mut val: i32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        val |= (b as i32) << (i * 8);
    }
    Some((val, end))
}

/// Extracts the base DN (first OCTET STRING in the search request body after op tag).
fn extract_base_dn(buf: &[u8]) -> String {
    let mut depth = 0usize;
    let mut i = 0usize;

    while i < buf.len() {
        let tag = buf[i];
        match tag {
            0x30 | 0x31 => {
                depth += 1;
                i += 1;
                if let Some((_, len)) = read_len(&buf[i..]) {
                    i += len;
                }
            }
            0x04 if depth > 0 => {
                // First OCTET STRING at depth > 0 after op tag is the base DN
                if let Some((len, len_len)) = read_len(&buf[i + 1..]) {
                    let start = i + 1 + len_len;
                    if start + len <= buf.len() {
                        if let Ok(s) = std::str::from_utf8(&buf[start..start + len]) {
                            return s.to_string();
                        }
                    }
                }
                break;
            }
            _ => {
                i += 1;
                if let Some((len, len_len)) = read_len(&buf[i..]) {
                    i += len_len + len;
                }
            }
        }
    }
    String::new()
}
