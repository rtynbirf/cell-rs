#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chain_atlas.py — Python-сторона негативного атласа хеш-цепи (ПРЕДЛОЖЕНИЕ-08,
issue #1 репо cell-rs, волна ×3 W3-A2). Дополняет золотые пробы волны ×3 W3-A
(tests/chain_golden_probes.rs + scripts/wave3_golden.py): там негативы зашиты
кодом проб, здесь атлас ожиданий живёт ДАННЫМИ — tests/golden/atlas.tsv
(заводится --emit, до этого канон-минимум вшит в обе стороны). Rust-пробы
tests/chain_atlas_probes.rs обязаны повторить каждый вердикт своей std-only
реализацией — двойная запись: один алгоритм, два независимых вычислителя.
Атлас: база — синтетическая цепь из 10 конвертов (та же, что --synthetic в
wave3_golden.py: canonical-байты {"i":N,"payload":"pN","prev":"<hex|GENESIS>"}).
Мутации-DSL: pristine — без раны (позитивный контроль); flip:<i>:<off> — xor
0x01 по байту off (подмена ровно 1 байта); seq:<i>:<v> — неверный seq;
torn:<i> — рваный JSON (обрезка середины); foreign:<i> — конверт без prev.
Столбцы: case<TAB>mutation<TAB>first<TAB>reason<TAB>notok, где first — индекс
первой раны или «-», reason ∈ OK/HASH/SEQ/JSON, notok — число не-OK вердиктов.
Спецификация вердиктов — ровно tests/chain_golden_probes.rs: GENESIS,
prev-сцепка с каскадом rec: подмена середины ломает все конверты после раны
(fail-closed, как у Trillian). Режимы: --emit заводит atlas.tsv (канон,
append-only: существующий файл не переписывается, только дописывается);
--check — храповик: пересчитанные строки обязаны быть в файле (дрейф — код 2);
--selftest — Python-вердикты обязаны совпасть с константными ожиданиями (те же
литералы, что в chain_atlas_probes.rs) + инварианты. Границы ADR-0005 честные:
Rust верифицирует, не творит; writer остаётся в Python. stdlib-only, Python 3.11.
"""

import hashlib
import os
import sys

GENESIS = b"GENESIS"
PREV_KEY = b'"prev":"'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATLAS = os.path.join(ROOT, "tests", "golden", "atlas.tsv")

# Канон-минимум атласа: те же литералы вшиты в tests/chain_atlas_probes.rs.
EXPECTED = [
    ("pristine", "pristine", "-", "OK", "0"),
    ("mid-byte-3", "flip:3:10", "3", "HASH", "7"),
    ("mid-byte-5", "flip:5:10", "5", "HASH", "5"),
    ("tail-byte-9", "flip:9:10", "9", "HASH", "1"),
    ("genesis-byte-0", "flip:0:4", "0", "HASH", "10"),
    ("wrong-seq-7", "seq:7:9", "7", "SEQ", "1"),
    ("torn-json-4", "torn:4", "4", "JSON", "6"),
    ("foreign-prev-6", "foreign:6", "6", "JSON", "4"),
]


def sha(b):
    return hashlib.sha256(b).digest()


def synthetic(n=10):
    rows, prev = [], GENESIS
    for i in range(n):
        inp = ('{"i":%d,"payload":"p%d","prev":"' % (i, i)).encode() + prev + b'"}'
        h = sha(inp)
        rows.append({"seq": i, "input": inp, "hash": h})
        prev = h.hex().encode()
    return rows


def mutate(rows, spec):
    p = spec.split(":")
    if p[0] == "pristine":
        return
    r = rows[int(p[1])]
    if p[0] == "flip":
        off = int(p[2])
        assert 0 <= off < len(r["input"]), "flip вне конверта: %s" % spec
        r["input"] = r["input"][:off] + bytes([r["input"][off] ^ 0x01]) + r["input"][off + 1:]
    elif p[0] == "seq":
        r["seq"] = int(p[2])
    elif p[0] == "torn":
        r["input"] = r["input"][:len(r["input"]) // 2]
    elif p[0] == "foreign":
        r["input"] = ('{"i":%d,"payload":"p%d"}' % (int(p[1]), int(p[1]))).encode()
    else:
        raise ValueError("неизвестная мутация: %s" % spec)


def verify(rows):
    """Зеркало спецификации tests/chain_golden_probes.rs: OK/HASH/SEQ/JSON."""
    rec, verdicts, first, reason = [], [], None, "OK"
    for i, r in enumerate(rows):
        seq, inp, h = r["seq"], r["input"], r["hash"]
        v = "OK"
        if seq != i:
            eff, v = inp, "SEQ"
        elif i == 0:
            eff = inp
            if sha(eff) != h:
                v = "HASH"
        else:
            at = inp.find(PREV_KEY)
            if at < 0 or at + len(PREV_KEY) + 64 > len(inp):
                eff, v = inp, "JSON"
            else:
                stored = inp[at + len(PREV_KEY):at + len(PREV_KEY) + 64].decode("ascii", "replace")
                recomputed = rec[i - 1].hex()
                eff = inp[:at + len(PREV_KEY)] + recomputed.encode() + inp[at + len(PREV_KEY) + 64:]
                if stored != recomputed or sha(eff) != h:
                    v = "HASH"
        rec.append(sha(eff))  # каскад: раненый конверт ломает хеши всех последующих
        verdicts.append(v)
        if v != "OK" and first is None:
            first, reason = i, v
    return first, reason, verdicts


def atlas_rows():
    out = []
    for case, spec, _, _, _ in EXPECTED:
        rows = synthetic(10)
        mutate(rows, spec)
        first, reason, verdicts = verify(rows)
        out.append((case, spec, "-" if first is None else str(first), reason,
                    str(sum(1 for v in verdicts if v != "OK"))))
    return out


def emit_text():
    head = ["# Негативный атлас хеш-цепи · канон (ПРЕДЛОЖЕНИЕ-08, issue #1, волна ×3 W3-A2).",
            "# case<TAB>mutation<TAB>first<TAB>reason<TAB>notok · first — индекс первой раны или «-».",
            "# База — синтетическая цепь 10 конвертов (та же, что tests/chain_golden_probes.rs и",
            "# wave3_golden.py --synthetic). Мутации: flip:<i>:<off> xor 1 байта, seq:<i>:<v>,",
            "# torn:<i> рваный JSON, foreign:<i> конверт без prev; pristine — позитивный контроль.",
            "# Ожидания посчитаны Python-стороной (wave3/chain_atlas.py); Rust-пробы обязаны",
            "# повторить каждый вердикт (двойная запись: один алгоритм — два вычислителя).",
            "# Правки строк — только дополнением; --check ловит дрейф ожиданий."]
    return "\n".join(head) + "\n" + "\n".join("\t".join(r) for r in atlas_rows()) + "\n"


def selftest():
    ok = []

    def ck(name, cond):
        ok.append(bool(cond))
        print("САМОПРОБА %s %s" % (name, "✓" if cond else "✗ ПРОВАЛ"))

    first, reason, verdicts = verify(synthetic(10))
    ck("1 (позитивный контроль 10/10 OK)", first is None and len(verdicts) == 10
       and all(v == "OK" for v in verdicts))
    ck("2 (атлас совпал с константными ожиданиями — литералы Rust)", atlas_rows() == list(EXPECTED))
    rows = synthetic(10)
    mutate(rows, "flip:3:10")
    first, reason, verdicts = verify(rows)
    ck("3 (кейс критерия: 1 байт в середине → HASH, fail-closed)",
       first == 3 and reason == "HASH" and all(v == "OK" for v in verdicts[:3])
       and all(v != "OK" for v in verdicts[3:]))
    data = [tuple(l.split("\t")) for l in data_rows(emit_text())]
    ck("4 (emit-текст соответствует атласу)", data == atlas_rows())
    print("САМОПРОБА: %d/%d ✓" % (sum(ok), len(ok)))
    sys.exit(0 if all(ok) else 1)


def data_rows(text):
    return [l for l in text.splitlines() if l and not l.startswith("#")]


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        selftest()
        return
    if "--emit" in args:
        if not os.path.exists(ATLAS):
            os.makedirs(os.path.dirname(ATLAS), exist_ok=True)
            open(ATLAS, "w", encoding="utf-8").write(emit_text())
            print("АТЛАС: заведён %s · кейсов %d" % (os.path.relpath(ATLAS, ROOT), len(atlas_rows())))
            return
        missing = [l for l in data_rows(emit_text()) if l not in set(open(ATLAS, encoding="utf-8").read().splitlines())]
        if not missing:
            print("АТЛАС: %s уже каноничен — не тронут (append-only)." % os.path.relpath(ATLAS, ROOT))
            return
        print("АТЛАС: в %s нет строк — канон не переписывается, допиши вручную:" % os.path.relpath(ATLAS, ROOT))
        for l in missing:
            print("  ДОПИСАТЬ: %s" % l)
        sys.exit(2)
    if "--check" in args:
        if not os.path.exists(ATLAS):
            print("АТЛАС: файла нет (заводится --emit); канон-минимум живёт в константах обеих сторон.")
            return
        reg = data_rows(emit_text())
        have = set(open(ATLAS, encoding="utf-8").read().splitlines())
        drift = [l for l in reg if l not in have]
        if drift:
            print("ХРАПОВИК: дрейф ожиданий — строк нет в %s:" % os.path.relpath(ATLAS, ROOT))
            for l in drift:
                print("  ДРЕЙФ: %s" % l)
            sys.exit(2)
        print("ХРАПОВИК: атлас сходится · кейсов %d · файл %s (дополнения разрешены)"
              % (len(reg), os.path.relpath(ATLAS, ROOT)))
        return
    print("Режимы: --emit | --check | --selftest")
    sys.exit(2)


if __name__ == "__main__":
    main()
