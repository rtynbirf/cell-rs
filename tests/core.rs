//! Приёмки Rust-клетки: векторы NIST для sha256, тампер-очевидность цепи,
//! совместимость семантики допуска с Python-ядром (test_blood.py).

use cell_rs::{seal_line, verify_chain, ChainError, Phase, Tolerance, reconcile, pins_match, sha256_hex};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn sha256_nist_vectors() {
    // FIPS 180-4 / NIST CAVP: пустая строка, "abc", двухблочный вектор
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn chain_build_verify_and_tamper() {
    let l1 = seal_line(1, "pulse-1:cell-a", GENESIS);
    let l2 = seal_line(2, "echo:cell-a", &l1[l1.rfind('|').unwrap() + 1..]);
    let tail = &l2[l2.rfind('|').unwrap() + 1..];
    let l3 = seal_line(3, "echo:cell-b", tail);
    let lines = vec![l1.as_str(), l2.as_str(), l3.as_str()];
    assert_eq!(verify_chain(&lines), Ok(3));

    // подмена середины ловится (payload второй строки переписан)
    let mut forged: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    let parts: Vec<&str> = forged[1].split('|').collect();
    forged[1] = format!("2|ПОДДЕЛКА|{}|{}", parts[2], parts[3]);
    let refs: Vec<&str> = forged.iter().map(|s| s.as_str()).collect();
    assert_eq!(verify_chain(&refs), Err(ChainError::Forged));

    // удаление середины ловится (цепь разорвана)
    let shortened = vec![lines[0], lines[2]];
    assert_eq!(verify_chain(&shortened), Err(ChainError::Broken));

    // остановка seq ловится
    let stagnant = vec![lines[0], lines[0]];
    assert_eq!(verify_chain(&stagnant), Err(ChainError::Stagnant));
}

#[test]
fn empty_chain_is_valid() {
    assert_eq!(verify_chain(&[]), Ok(0));
}

#[test]
fn reconciliation_semantics_match_python() {
    let tol = Tolerance::new(0.05, 0.02).unwrap();
    assert_eq!(reconcile(0.505, 0.50, &tol), Phase::Nominal);
    assert_eq!(reconcile(0.53, 0.50, &tol), Phase::Nominal);
    assert_eq!(reconcile(0.60, 0.50, &tol), Phase::Drift);
    assert!(pins_match("137eb62", "137eb62"));
    assert!(!pins_match("137eb62", "c5517ef"));
}
