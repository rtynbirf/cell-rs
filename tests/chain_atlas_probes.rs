//! Негативный атлас хеш-цепи · Rust std-only (ПРЕДЛОЖЕНИЕ-08, issue #1, W3-A2).
//!
//! Дополняет tests/chain_golden_probes.rs (волна ×3 W3-A): там негативы зашиты
//! кодом проб, здесь атлас ожиданий — КОНСТАНТНЫМИ ДАННЫМИ (те же литералы,
//! что в wave3/chain_atlas.py: ожидания посчитаны Python-стороной, не выдуманы).
//! Rust обязана повторить каждый вердикт своей реализацией — двойная запись:
//! один алгоритм, два независимых вычислителя. Файл tests/golden/atlas.tsv
//! (заводится `python3 wave3/chain_atlas.py --emit`) — редактируемый канон; до
//! его появления пробы читают канон-минимум из константы ATLAS ниже.
//!
//! Спецификация вердиктов — та же, что в chain_golden_probes.rs:
//! OK / HASH / SEQ / JSON, GENESIS, prev-сцепка с каскадом rec: подмена
//! одного байта в середине ломает вердикты ВСЕХ конвертов после раны
//! (fail-closed, как у Trillian). Мутации-DSL: flip:<i>:<off> — xor 1 байта,
//! seq:<i>:<v> — неверный seq, torn:<i> — рваный JSON, foreign:<i> — конверт
//! без prev, pristine — позитивный контроль. Границы ADR-0005 честные:
//! Rust верифицирует, не творит; writer остаётся в Python.

const GENESIS: &str = "GENESIS";
const PREV_PAT: &[u8] = b"\"prev\":\"";

/// Канон-минимум атласа: (кейс, мутация, first: индекс первой раны или None,
/// reason, число не-OK). Те же литералы — в wave3/chain_atlas.py (EXPECTED).
const ATLAS: &[(&str, &str, Option<usize>, &str, usize)] = &[
    ("pristine", "pristine", None, "OK", 0),
    ("mid-byte-3", "flip:3:10", Some(3), "HASH", 7),
    ("mid-byte-5", "flip:5:10", Some(5), "HASH", 5),
    ("tail-byte-9", "flip:9:10", Some(9), "HASH", 1),
    ("genesis-byte-0", "flip:0:4", Some(0), "HASH", 10),
    ("wrong-seq-7", "seq:7:9", Some(7), "SEQ", 1),
    ("torn-json-4", "torn:4", Some(4), "JSON", 6),
    ("foreign-prev-6", "foreign:6", Some(6), "JSON", 4),
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let bits = (data.len() as u64) * 8;
    let mut m = data.to_vec(); m.push(0x80);
    while m.len() % 64 != 56 { m.push(0); }
    m.extend_from_slice(&bits.to_be_bytes());
    for c in m.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes([c[4 * i], c[4 * i + 1], c[4 * i + 2], c[4 * i + 3]]); }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let ch = (e & f) ^ ((!e) & g);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let t2 = s0.wrapping_add(mj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1); d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        for i in 0..8 { h[i] = h[i].wrapping_add([a, b, c, d, e, f, g, hh][i]); }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

fn to_hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

struct Row { seq: u64, input: Vec<u8>, hash: [u8; 32] }

/// индекс начала значения поля "prev":"<…>" — ровно 64 hex-байта значения
fn find_prev(input: &[u8]) -> Option<usize> {
    if input.len() < PREV_PAT.len() + 64 { return None; }
    (0..=input.len() - PREV_PAT.len() - 64)
        .find(|&w| &input[w..w + PREV_PAT.len()] == PREV_PAT)
}

/// Спецификация вердиктов — как в tests/chain_golden_probes.rs (OK/HASH/SEQ/JSON).
fn verify(rows: &[Row]) -> (Option<usize>, &'static str, Vec<&'static str>) {
    let mut rec: Vec<[u8; 32]> = Vec::with_capacity(rows.len());
    let mut verdicts: Vec<&'static str> = Vec::with_capacity(rows.len());
    let (mut first, mut reason) = (None, "OK");
    for (i, r) in rows.iter().enumerate() {
        let mut v = "OK";
        let eff: Vec<u8>;
        if r.seq != i as u64 {
            v = "SEQ"; eff = r.input.clone();
        } else if i == 0 {
            eff = r.input.clone();
            if sha256(&eff) != r.hash { v = "HASH"; }
        } else {
            match find_prev(&r.input) {
                None => { v = "JSON"; eff = r.input.clone(); }
                Some(at) => {
                    let lo = at + PREV_PAT.len();
                    let stored = String::from_utf8_lossy(&r.input[lo..lo + 64]).into_owned();
                    let recomputed = to_hex(&rec[i - 1]);
                    let mut e = r.input.clone();
                    e[lo..lo + 64].copy_from_slice(recomputed.as_bytes());
                    eff = e;
                    if stored != recomputed || sha256(&eff) != r.hash { v = "HASH"; }
                }
            }
        }
        rec.push(sha256(&eff)); // каскад: раненый конверт ломает хеши всех последующих
        verdicts.push(v);
        if v != "OK" && first.is_none() { first = Some(i); reason = v; }
    }
    (first, reason, verdicts)
}

/// синтетическая цепь — та же, что в chain_golden_probes.rs и wave3_golden.py
fn synthetic_chain(n: usize) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    let mut prev: Vec<u8> = GENESIS.as_bytes().to_vec();
    for i in 0..n {
        let mut input = format!("{{\"i\":{},\"payload\":\"p{}\",\"prev\":\"", i, i).into_bytes();
        input.extend_from_slice(&prev);
        input.extend_from_slice(b"\"}");
        let hash = sha256(&input);
        rows.push(Row { seq: i as u64, hash, input });
        prev = to_hex(&hash).into_bytes();
    }
    rows
}

/// мутации-DSL атласа (та же семантика, что в wave3/chain_atlas.py)
fn mutate(rows: &mut [Row], spec: &str) -> Result<(), String> {
    let p: Vec<&str> = spec.split(':').collect();
    if p[0] == "pristine" { return Ok(()); }
    let idx: usize = p[1].parse().map_err(|_| format!("{}: индекс не число", spec))?;
    if idx >= rows.len() { return Err(format!("{}: мутация вне цепи", spec)); }
    match p[0] {
        "flip" => {
            let off: usize = p[2].parse().map_err(|_| format!("{}: смещение не число", spec))?;
            if off >= rows[idx].input.len() { return Err(format!("{}: flip вне конверта", spec)); }
            rows[idx].input[off] ^= 0x01;
            Ok(())
        }
        "seq" => { rows[idx].seq = p[2].parse().map_err(|_| format!("{}: seq не число", spec))?; Ok(()) }
        "torn" => { let half = rows[idx].input.len() / 2; rows[idx].input.truncate(half); Ok(()) }
        "foreign" => {
            rows[idx].input = format!("{{\"i\":{},\"payload\":\"p{}\"}}", idx, idx).into_bytes();
            Ok(())
        }
        other => Err(format!("неизвестная мутация: {}", other)),
    }
}

fn run_case(case: &str, spec: &str, want_first: Option<usize>, want_reason: &str, want_notok: usize) {
    let mut rows = synthetic_chain(10);
    mutate(&mut rows, spec).unwrap_or_else(|e| panic!("кейс {}: {}", case, e));
    let (first, reason, verdicts) = verify(&rows);
    let notok = verdicts.iter().filter(|v| **v != "OK").count();
    assert_eq!(first, want_first, "кейс {}: индекс первой раны", case);
    assert_eq!(reason, want_reason, "кейс {}: reason", case);
    assert_eq!(notok, want_notok, "кейс {}: число не-OK", case);
    if let Some(w) = first {
        assert!(verdicts[..w].iter().all(|v| *v == "OK"), "кейс {}: до раны всё OK", case);
        if reason == "HASH" { assert!(verdicts[w..].iter().all(|v| *v != "OK"), "кейс {}: fail-closed после раны", case); }
    }
}

#[test]
fn sha256_known_vectors() {
    assert_eq!(to_hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(to_hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn positive_pristine_10of10() {
    let rows = synthetic_chain(10);
    let (first, reason, verdicts) = verify(&rows);
    assert!(first.is_none() && reason == "OK" && verdicts.len() == 10
            && verdicts.iter().all(|v| *v == "OK"));
}

#[test]
fn atlas_double_entry() {
    for &(case, spec, want_first, want_reason, want_notok) in ATLAS {
        run_case(case, spec, want_first, want_reason, want_notok);
    }
}

#[test]
fn mutation_dsl_errors() {
    let mut rows = synthetic_chain(3);
    assert!(mutate(&mut rows, "flip:1:999").is_err(), "flip вне конверта обязан дать ошибку");
    assert!(mutate(&mut rows, "unknown:1").is_err(), "чужая мутация обязана дать ошибку");
}
