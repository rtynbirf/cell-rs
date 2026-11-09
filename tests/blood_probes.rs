//! Золотые пробы Rust-гейта крови (волна ×9).
//!
//! Пробы — ЖИВЫЕ строки клеточной летописи cell-swarm/blood/CELLS-LEDGER.jsonl
//! (снимок 2026-11-09, 6 конвертов, валидированы Python-ядром: chain OK).
//! Только stdlib, офлайн.

use cell_rs::blood::{
    blood_verdict, envelope_sealed_in_ledger, expected_sha_for_cell, ledger_verify, Verdict,
};

const GOLDEN: &str = include_str!("golden/blood_cells_ledger.jsonl");

fn golden_lines() -> Vec<&'static str> {
    GOLDEN.lines().filter(|l| !l.trim().is_empty()).collect()
}

#[test]
fn golden_chain_is_whole() {
    let lines = golden_lines();
    let n = ledger_verify(&lines).expect("золотая цепь обязана быть целой");
    assert_eq!(n, 6, "в снимке 6 конвертов");
}

#[test]
fn genesis_is_64_zeros() {
    let lines = golden_lines();
    // первая строка: prev_hash = генезис — вынимаем и сверяем
    let first = lines[0];
    let pos = first.find("\"prev_hash\":\"").expect("prev_hash есть") + "\"prev_hash\":\"".len();
    let prev = &first[pos..pos + 64];
    assert_eq!(prev, &"0".repeat(64), "генезис = 64 нуля");
}

#[test]
fn tampered_payload_is_caught_as_forged() {
    let mut lines = golden_lines();
    let last = lines.len() - 1;
    // подмена одного символа ключа payload ломает байты тела, хеш ловит
    let tampered = lines[last].replacen("\"src\":", "\"srs\":", 1);
    assert_ne!(tampered, lines[last], "подмена обязана изменить байты");
    lines[last] = &tampered;
    let err = ledger_verify(&lines).expect_err("подделка обязана быть поймана");
    assert!(
        matches!(err.0, cell_rs::blood::BloodError::Forged { .. }),
        "рана = FORGED, получили: {err:?}"
    );
}

#[test]
fn broken_chain_is_caught() {
    let mut lines = golden_lines();
    // Атакующий переписывает ВТОРУЮ строку (меняет prev_hash на нули) и
    // ЧЕСТНО пересчитывает её хеш — строка самосогласованна, но её
    // prev_hash != хеш первой строки (той уже не изменить без перезалива).
    let second = lines[1];
    let pos = second.find("\"prev_hash\":\"").expect("prev_hash есть");
    let start = pos + "\"prev_hash\":\"".len();
    let zeroed_prev = format!(
        "{}{}{}",
        &second[..start],
        "0".repeat(64),
        &second[start + 64..]
    );
    // пересчитать hash как честный писарь: body = строка без поля hash
    let old_hash = cell_rs::blood::envelope_hash_field(&zeroed_prev).expect("hash есть");
    let needle = format!(",\"hash\":\"{old_hash}\"");
    let body = zeroed_prev.replacen(&needle, "", 1);
    let new_hash = cell_rs::sha256_hex(body.as_bytes());
    let rewritten = zeroed_prev.replacen(&old_hash, &new_hash, 1);
    assert_ne!(rewritten, second, "перепись обязана изменить байты");
    lines[1] = &rewritten;
    let err = ledger_verify(&lines).expect_err("разрыв цепи обязан быть пойман");
    assert!(
        matches!(err.0, cell_rs::blood::BloodError::ChainBroken { .. }),
        "рана = CHAIN_BROKEN, получили: {err:?}"
    );
}

#[test]
fn verdict_is_exact_per_genome_kernel() {
    let envelope = golden_lines()[0]; // геномный пульс: payload.cells с ожиданиями
    let expected = expected_sha_for_cell(envelope, "runtime-protocol")
        .expect("в геномном пульсе нет ожидания для runtime-protocol");
    // точное совпадение = VERIFIED, расхождение = DRIFT
    assert_eq!(blood_verdict(envelope, "runtime-protocol", expected), Verdict::Verified);
    assert_eq!(
        blood_verdict(envelope, "runtime-protocol", &"f".repeat(40)),
        Verdict::Drift
    );
    // клетки нет в конверте — честное OBSERVED (не вслепую)
    assert_eq!(
        blood_verdict(envelope, "voice-atlas-llm", &"f".repeat(40)),
        Verdict::Observed
    );
}

#[test]
fn envelope_of_ledger_line_is_sealed_in_ledger() {
    let lines = golden_lines();
    assert!(envelope_sealed_in_ledger(lines[1], GOLDEN));
    let stranger = r#"{"hash":"1111111111111111111111111111111111111111111111111111111111111111"}"#;
    assert!(!envelope_sealed_in_ledger(stranger, GOLDEN));
}
