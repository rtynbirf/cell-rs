//! Rust-гейт крови: конверт сверяется вторым языком ДО эха в летопись
//! (волна ×9 «рой из модели в кровь», ADR-0005 «тропа роя»).
//!
//! Exit-коды:
//!   0 — летопись цела, вердикт вынесен (VERIFIED / DRIFT / OBSERVED — все
//!       три статуса суть факты крови, кровь течёт);
//!   1 — рана: летопись STRUCTURE/FORGED/CHAIN_BROKEN или конверт не
//!       запечатан в летописи — кровь остановлена честно.
//!
//! Использование:
//!   blood_gate --ledger <file> --envelope <file> --cell <name> --cell-sha <sha>
//!   blood_gate --self-test          (золотые пробы, офлайн)

use cell_rs::blood::{blood_verdict, envelope_sealed_in_ledger, ledger_verify, Verdict};
use std::process::ExitCode;

const GOLDEN_LEDGER: &str = include_str!("../../tests/golden/blood_cells_ledger.jsonl");

fn fail(msg: &str) -> ExitCode {
    println!("РАНА: {msg}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--self-test") {
        println!("ФАКТ: золотые пробы Rust-гейта — цепь летописи по байтам");
        let lines: Vec<&str> = GOLDEN_LEDGER
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        match ledger_verify(&lines) {
            Ok(n) => println!("ФАКТ: золотая цепь цела, конвертов {n}"),
            Err((e, _)) => return fail(&format!("золотая цепь сломана: {e}")),
        }
        // тампер-проба: подмена одного байта payload ловится хешем
        let tampered = lines[lines.len() - 1].replacen("\"src\":", "\"srs\":", 1);
        let mut suspect: Vec<&str> = lines.clone();
        let last = suspect.len() - 1;
        suspect[last] = &tampered;
        match ledger_verify(&suspect) {
            Err((e, _)) => println!("ФАКТ: тампер-проба поймана: {e}"),
            Ok(_) => return fail("тампер-проба ПРОШЛА — гейт слеп, кровь не доверяет"),
        }
        println!("ФАКТ: самотест Rust-гейта пройден (цепь цела, подделка ловится)");
        return ExitCode::SUCCESS;
    }

    let get = |flag: &str| -> Option<&str> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
    };
    let Some(ledger_path) = get("--ledger") else {
        return fail("--ledger не задан — гейт не работает вслепую");
    };
    let Some(envelope_path) = get("--envelope") else {
        return fail("--envelope не задан — гейт не работает вслепую");
    };
    let Some(cell) = get("--cell") else {
        return fail("--cell не задан");
    };
    let Some(cell_sha) = get("--cell-sha") else {
        return fail("--cell-sha не задан");
    };

    let ledger_raw = match std::fs::read_to_string(ledger_path) {
        Ok(s) => s,
        Err(e) => return fail(&format!("летопись не прочитана ({ledger_path}): {e}")),
    };
    let envelope_raw = match std::fs::read_to_string(envelope_path) {
        Ok(s) => s,
        Err(e) => return fail(&format!("конверт не прочитан ({envelope_path}): {e}")),
    };

    // 1. Цепь летописи по байтам — тампер-очевидность вторым языком.
    let lines: Vec<&str> = ledger_raw.lines().filter(|l| !l.trim().is_empty()).collect();
    let n = match ledger_verify(&lines) {
        Ok(n) => n,
        Err((e, _)) => return fail(&format!("летопись: {e} — кровь остановлена")),
    };
    println!("ФАКТ: Rust-гейт: летопись цела, конвертов {n} (sha256 по байтам каждой строки)");

    // 2. Конверт обязан быть запечатан в летописи ДО dispatch (геном пишет, потом стреляет).
    if !envelope_sealed_in_ledger(envelope_raw.trim(), &ledger_raw) {
        return fail("конверт не найден в летописи — dispatch без печати не бывает");
    }
    println!("ФАКТ: конверт запечатан в летописи (хеш найден в байтах)");

    // 2b. Геномное ожидание из летописи: геномный пульс (src=cell-swarm)
    // запечатан в байтах и несёт payload.cells с ожиданием каждого тела
    // цепи. Эхо-конверт (его несёт dispatch) ожиданий не имеет по канону —
    // поэтому точную сверку клетки с геномом делает ЗДЕСЬ второй язык.
    if let Some(genome_expectation) = cell_rs::blood::latest_expected_sha_in_ledger(&ledger_raw, cell) {
        if genome_expectation == cell_sha {
            println!("ФАКТ: Rust-гейт: геномное ожидание (из летописи) = живой github.sha — сверка вторым языком: VERIFIED");
        } else {
            println!("ФАКТ: Rust-гейт: геномное ожидание {genome_expectation} != тело {cell_sha} — DRIFT (честный факт дрейфа, не подделка)");
        }
    } else {
        println!("ФАКТ: геномное ожидание для {cell} в летописи не найдено — клетка вне текущего пульса генома");
    }

    // 3. Вердикт клетки над входящим конвертом (канон ядра: эхо не несёт payload.cells)
    match blood_verdict(envelope_raw.trim(), cell, cell_sha) {
        Verdict::Verified => {
            println!("ФАКТ: Rust-гейт: {cell} VERIFIED — ожидание генома = живой github.sha");
            ExitCode::SUCCESS
        }
        Verdict::Drift => {
            println!("ФАКТ: Rust-гейт: {cell} DRIFT — тело клетки ушло от ожидания генома (честный факт дрейфа)");
            ExitCode::SUCCESS
        }
        Verdict::Observed => {
            println!("ФАКТ: Rust-гейт: {cell} OBSERVED — ожидания нет, клетка не сверяется вслепую");
            ExitCode::SUCCESS
        }
    }
}
