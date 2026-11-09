//! Первая Rust-клетка роя: ядро контура сверки.
//!
//! Сверка вшита в структуру, не в обещание (как в ядре runtime-protocol):
//! - [`Tolerance`] — двухступенчатый допуск (deadband = мёртвая зона,
//!   eps = граница допуска); за eps — [`Phase::Drift`], факт дрейфа, не ложь;
//! - [`sha256`] — с нуля, без зависимостей, на векторах NIST;
//! - [`verify_chain`] — тампер-очевидная байт-цепь: подмена середины
//!   ловится, генезис = 64 нуля.
//!
//! Честные границы v0.1: JSON-конверт крови (blood.py, канон с сортировкой
//! ключей) придёт, когда клетка вырастет в serde; сегодня клетка сверяет
//! семантику допуска и цепь — те же векторы, что приёмки Python-ядра.

pub mod blood;

/// Двухступенчатый допуск сверки: |нарушение| <= deadband — не дёргаемся,
/// deadband < |нарушение| <= eps — в допуске, больше — [`Phase::Drift`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tolerance {
    pub eps: f64,
    pub deadband: f64,
}

impl Tolerance {
    /// Допуск валиден, если 0 <= deadband <= eps. Иначе клетка не собирается.
    pub fn new(eps: f64, deadband: f64) -> Result<Self, String> {
        if !(eps >= 0.0) || !(deadband >= 0.0) || deadband > eps {
            return Err(format!(
                "допуск не собирается: eps={eps}, deadband={deadband} (нужно 0<=deadband<=eps)"
            ));
        }
        Ok(Self { eps, deadband })
    }
}

/// Фаза клетки после сверки ЖЕЛАЕМОЕ ↔ НАБЛЮДАЕМОЕ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Наблюдаемое внутри допуска — клетка не дёргается.
    Nominal,
    /// Наблюдаемое вышло за eps — честный факт дрейфа, кровь его несёт.
    Drift,
}

/// Сверка: пока нарушение в допуске — [`Phase::Nominal`], за границей — [`Phase::Drift`].
pub fn reconcile(observed: f64, desired: f64, tol: &Tolerance) -> Phase {
    let violation = (observed - desired).abs();
    if violation <= tol.deadband || violation <= tol.eps {
        Phase::Nominal
    } else {
        Phase::Drift
    }
}

/// Дискретное (SHA, имя, флаг) сверяется точно: совпадение байтов или дрейф.
pub fn pins_match(expected: &str, observed: &str) -> bool {
    expected == observed
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// sha256 с нуля (FIPS 180-4), без единой зависимости: клетка сама себе хеш.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// hex-строка хеша (нижний регистр) — валюта цепей роя.
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Рана байт-цепи: подделана, разорвана, стоит на месте или пуста по форме.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// Хеш строки не сходится — подделка.
    Forged,
    /// prev_hash строки не равен хешу предыдущей — цепь разорвана.
    Broken,
    /// seq не растёт по цепи — кровь стоит на месте.
    Stagnant,
    /// Строка не той формы (нет 4 полей).
    Malformed,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Строка байт-цепи: `seq|payload|prev_hash|hash`,
/// где `hash = sha256_hex(prev_hash_как_байты || "seq|payload|prev_hash|")`.
/// Генезис: первая строка ссылается на 64 нуля.
pub fn seal_line(seq: u64, payload: &str, prev_hash: &str) -> String {
    let body = format!("{seq}|{payload}|{prev_hash}|");
    let mut input = prev_hash.as_bytes().to_vec();
    input.extend_from_slice(body.as_bytes());
    format!("{body}{}", sha256_hex(&input))
}

/// Проверка байт-цепи целиком: форма, рост seq, сцепка хешей.
/// Возвращает число проверенных строк или рану.
pub fn verify_chain(lines: &[&str]) -> Result<usize, ChainError> {
    let mut prev = GENESIS.to_string();
    let mut last_seq: Option<u64> = None;
    for (idx, raw) in lines.iter().map(|l| l.trim()).enumerate() {
        let parts: Vec<&str> = raw.split('|').collect();
        if parts.len() != 4 {
            return Err(ChainError::Malformed);
        }
        let seq: u64 = parts[0].parse().map_err(|_| ChainError::Malformed)?;
        if let Some(s) = last_seq {
            if seq <= s {
                return Err(ChainError::Stagnant);
            }
        }
        if parts[2] != prev {
            return Err(ChainError::Broken);
        }
        // hash = sha256_hex(prev_hash_байты || "seq|payload|prev_hash|")
        let mut input = prev.as_bytes().to_vec();
        input.extend_from_slice(format!("{}|{}|{}|", seq, parts[1], parts[2]).as_bytes());
        let expected = sha256_hex(&input);
        if expected != parts[3] {
            return Err(ChainError::Forged);
        }
        prev = parts[3].to_string();
        last_seq = Some(seq);
        let _ = idx;
    }
    Ok(lines.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerance_bounds() {
        assert!(Tolerance::new(0.05, 0.02).is_ok());
        assert!(Tolerance::new(0.0, 0.0).is_ok());
        assert!(Tolerance::new(-0.1, 0.0).is_err());
        assert!(Tolerance::new(0.01, 0.02).is_err()); // deadband > eps — не собирается
    }

    #[test]
    fn reconcile_matches_python_kernel() {
        // те же векторы, что в test_blood.py ядра runtime-protocol
        let tol = Tolerance::new(0.05, 0.02).unwrap();
        assert_eq!(reconcile(0.505, 0.50, &tol), Phase::Nominal); // мёртвая зона
        assert_eq!(reconcile(0.53, 0.50, &tol), Phase::Nominal);  // в допуске
        assert_eq!(reconcile(0.60, 0.50, &tol), Phase::Drift);    // за eps
    }

    #[test]
    fn pins_are_exact() {
        assert!(pins_match("137eb62", "137eb62"));
        assert!(!pins_match("137eb62", "c5517ef"));
    }
}
