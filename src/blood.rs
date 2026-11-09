//! Кровь в Rust (волна ×9 «рой из модели в кровь»): тампер-очевидность
//! клеточной летописи вторым языком, std-only.
//!
//! Границы честности (как в lib.rs): Rust-гейт сверяет ЦЕПОЧКУ ЛЕТОПИСИ
//! по байтам и выносит вердикт ожидания клетки (VERIFIED/DRIFT/OBSERVED).
//! Полная проверка конверта (каноническая пересборка, ttl) остаётся за
//! Python-ядром (blood.py) — гейт ловит подделку ДО эха, не дублирует ядро.
//!
//! Почему байты, а не пересборка: строки летописи уже каноничны
//! (`canonical_json`, сортировка ключей). Для канонической строки удаление
//! поля `"hash"` из сырых байтов даёт ровно те байты, над которыми хеш
//! считался. Пересборка JSON в Rust потребовала бы байт-в-байт повторить
//! сериализацию Python (floats, escaping) — лишняя хрупкость там, где
//! канон уже запечатан в байтах файла.

use crate::sha256_hex;

/// Раны Rust-гейта крови (fail-closed: любой вариант останавливает кровь).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloodError {
    /// В строке нет поля `"hash":"<64 hex>"` или оно не единственно.
    Structure { line: usize },
    /// sha256(body) != hash — строка подделана.
    Forged { line: usize },
    /// prev_hash строки != хеш предыдущей (или генезис не из 64 нулей).
    ChainBroken { line: usize },
}

impl std::fmt::Display for BloodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BloodError::Structure { line } => write!(f, "STRUCTURE: строка {line}: поле hash отсутствует или неединственно"),
            BloodError::Forged { line } => write!(f, "FORGED: строка {line}: sha256(body) != hash — подделка"),
            BloodError::ChainBroken { line } => write!(f, "CHAIN_BROKEN: строка {line}: prev_hash != хеш предыдущей записи"),
        }
    }
}

/// Вердикт клетки над конвертом (те же статусы, что у Python-ядра).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Ожидание в payload.cells совпало с телом клетки байт-в-байт.
    Verified,
    /// Ожидание есть, но не совпало — честный факт дрейфа.
    Drift,
    /// Ожидания для этой клетки в конверте нет — клетка не сверяется вслепую.
    Observed,
}

/// Извлечь значение hex-поля `"field":"<hexlen hex>"` из сырой JSON-строки.
/// Форматы: компакт (`"hash":"..."`) и GitHub toJson (pretty-print 2 пробела,
/// `"hash": "..."`) — волна ×9: dispatch payload приходит pretty-печатанным
/// (423 байта против 359 компактных — диагноз живого красного 42644309437).
/// Паттерн строг: длина значения ровно hexlen, дальше — кавычка.
/// Возвращает ПЕРВОЕ вхождение.
fn extract_hex_field<'a>(raw: &'a str, field: &str, hexlen: usize) -> Option<&'a str> {
    for needle in [format!("\"{field}\":\""), format!("\"{field}\": \"")] {
        let mut start = 0usize;
        while let Some(pos) = raw[start..].find(&needle) {
            let abs = start + pos + needle.len();
            let rest = &raw[abs..];
            let chars: Vec<char> = rest.chars().collect();
            if chars.len() >= hexlen
                && chars[..hexlen].iter().all(|c| c.is_ascii_hexdigit())
                && chars.get(hexlen) == Some(&'"')
            {
                // первые hexlen символов — hex (по байту каждый), дальше кавычка
                return Some(&rest[..hexlen]);
            }
            start = start + pos + needle.len();
        }
    }
    None
}

/// Публичная обёртка: ожидание клетки из payload.cells конверта (40 hex).
pub fn expected_sha_for_cell<'a>(envelope_raw: &'a str, _cell: &str) -> Option<&'a str> {
    extract_hex_field(envelope_raw, _cell, 40)
}

/// Актуальное ожидание клетки из ЛЕТОПИСИ: летопись append-only, геномные
/// пульсы накапливаются — актуально ПОСЛЕДНЕЕ совпадение (волна ×9: гейт
/// брал первое и ловил старый пульс №1 вместо свежего — вердикт DRIFT
/// рождался из артефакта чтения, не из дрейфа тела).
pub fn latest_expected_sha_in_ledger<'a>(ledger_raw: &'a str, cell: &str) -> Option<&'a str> {
    let needle = format!("\"{cell}\":\"");
    let mut last: Option<&'a str> = None;
    let mut start = 0usize;
    while let Some(pos) = ledger_raw[start..].find(&needle) {
        let abs = start + pos + needle.len();
        let rest = &ledger_raw[abs..];
        let chars: Vec<char> = rest.chars().collect();
        if chars.len() >= 40
            && chars[..40].iter().all(|c| c.is_ascii_hexdigit())
            && chars.get(40) == Some(&'"')
        {
            last = Some(&rest[..40]);
        }
        start = start + pos + needle.len();
    }
    last
}

/// Публичная обёртка: хеш конверта из его сырой строки (64 hex).
pub fn envelope_hash_field(envelope_raw: &str) -> Option<&str> {
    extract_hex_field(envelope_raw, "hash", 64)
}

/// Верификация клеточной летописи по байтам: хеш-цепь конвертов крови.
///
/// Для каждой строки: body = строка без `,"hash":"<64hex>"`; sha256(body)
/// обязан совпасть с полем hash; prev_hash строки — хеш предыдущей;
/// у первой строки prev_hash = генезис (64 нуля).
/// Возвращает число конвертов или рану с номером строки (с 1).
pub fn ledger_verify(lines: &[&str]) -> Result<usize, (BloodError, usize)> {
    const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut running: String = GENESIS.to_string();
    let mut count = 0usize;
    for (idx, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let n = idx + 1;
        let Some(hash_field) = extract_hex_field(line, "hash", 64) else {
            return Err((BloodError::Structure { line: n }, count));
        };
        // каноническое тело = сырые байты строки без поля hash (с запятой)
        let needle = format!(",\"hash\":\"{hash_field}\"");
        let body = match line.find(&needle) {
            Some(pos) if line.matches(&needle).count() == 1 => {
                let mut b = String::with_capacity(line.len());
                b.push_str(&line[..pos]);
                b.push_str(&line[pos + needle.len()..]);
                b
            }
            _ => {
                return Err((BloodError::Structure { line: n }, count));
            }
        };
        if sha256_hex(body.as_bytes()) != hash_field {
            return Err((BloodError::Forged { line: n }, count));
        }
        let Some(prev_field) = extract_hex_field(line, "prev_hash", 64) else {
            return Err((BloodError::Structure { line: n }, count));
        };
        if prev_field != running {
            return Err((BloodError::ChainBroken { line: n }, count));
        }
        running = hash_field.to_string();
        count += 1;
    }
    Ok(count)
}

/// Вердикт клетки над конвертом: ожидание ↔ тело (по генофонду ядра
/// runtime-protocol: eps=0 — точное сравнение SHA, `pins_match`).
/// Летопись проверяется РЯДОМ (не здесь) — см. `ledger_verify`.
pub fn blood_verdict(envelope_raw: &str, cell: &str, cell_sha: &str) -> Verdict {
    match expected_sha_for_cell(envelope_raw, cell) {
        Some(expected) => {
            if expected == cell_sha {
                Verdict::Verified
            } else {
                Verdict::Drift
            }
        }
        None => Verdict::Observed,
    }
}

/// Конверт должен быть запечатан в летописи ДО dispatch (геном пишет,
/// потом стреляет): хеш конверта обязан найтись в байтах летописи.
pub fn envelope_sealed_in_ledger(envelope_raw: &str, ledger_raw: &str) -> bool {
    match envelope_hash_field(envelope_raw) {
        Some(h) => ledger_raw.contains(h),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_finds_hash_field() {
        let raw = r#"{"dst":"cell-swarm","hash":"abc123","payload":{}}"#;
        assert_eq!(extract_hex_field(raw, "hash", 6), Some("abc123"));
    }

    #[test]
    fn extract_rejects_short_or_open_value() {
        let raw = r#"{"hash":"abc12"}"#; // короче заявленной длины
        assert_eq!(extract_hex_field(raw, "hash", 6), None);
        let raw2 = r#"{"hash":"abc12g"}"#; // g — не hex
        assert_eq!(extract_hex_field(raw2, "hash", 6), None);
    }

    #[test]
    fn extract_accepts_pretty_print_github_tojson() {
        // GitHub toJson = pretty-print 2 пробела: "hash": "..." (после двоеточия пробел)
        let pretty = "{\n  \"dst\": \"cell-swarm\",\n  \"hash\": \"aabbccddeeff\",\n  \"payload\": {\n    \"pulse\": 4\n  }\n}";
        assert_eq!(extract_hex_field(pretty, "hash", 12), Some("aabbccddeeff"));
        // и ожидание клетки из payload.cells тоже читается
        let cells = "{\n    \"cells\": {\n      \"cell-rs\": \"71431de7f0123456789abcdef0123456789abcde\"\n    }\n}";
        assert_eq!(
            expected_sha_for_cell(cells, "cell-rs"),
            Some("71431de7f0123456789abcdef0123456789abcde")
        );
    }
}
