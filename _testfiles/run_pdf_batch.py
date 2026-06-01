"""Escaneia em lote todos os PDFs de uma ou mais pastas via FileScan.

Uso:
    python run_pdf_batch.py <pasta1> [pasta2 ...]

A URL do endpoint vem da env var FILESCAN_URL (default http://localhost:5099/scan).
"""
import os, subprocess, json, sys
from collections import Counter

URL = os.environ.get("FILESCAN_URL", "http://localhost:5099/scan")
dirs = sys.argv[1:]
if not dirs:
    print(__doc__)
    raise SystemExit(1)

results = []
for d in dirs:
    if not os.path.isdir(d):
        print(f"(pasta nao encontrada: {d})")
        continue
    for root, _, files in os.walk(d):
        for fn in sorted(files):
            if not fn.lower().endswith(".pdf"):
                continue
            path = os.path.join(root, fn)
            try:
                out = subprocess.run(
                    ["curl", "-s", "-F", "file=@" + path, URL],
                    capture_output=True, text=True, timeout=60).stdout
                j = json.loads(out)
                results.append((os.path.basename(d), fn, j.get("verdict"), j.get("reason")))
            except Exception as e:
                results.append((os.path.basename(d), fn, "ERRO", str(e)[:80]))

clean = [r for r in results if r[2] == "Clean"]
rej = [r for r in results if r[2] == "Rejected"]
other = [r for r in results if r[2] not in ("Clean", "Rejected")]

print(f"TOTAL: {len(results)}  |  Clean: {len(clean)}  |  Rejected: {len(rej)}  |  Outros: {len(other)}")

if rej:
    print("\n===== REJEITADOS (potenciais falso-positivos) =====")
    for d, fn, v, reason in rej:
        print(f"[{d}] {fn}\n     -> {reason}")
    print("\n===== MOTIVOS (contagem) =====")
    for reason, c in Counter(r[3] for r in rej).most_common():
        print(f"{c}x  {reason}")

if other:
    print("\n===== OUTROS (erro/parse) =====")
    for d, fn, v, reason in other:
        print(f"[{d}] {fn} -> {v} {reason}")
