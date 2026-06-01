"""Inspeciona os arquivos embutidos (/EmbeddedFile) de um PDF (diagnóstico).

Uso:
    python inspect_embedded.py <arquivo.pdf>

Mostra os nomes dos anexos e o início do conteúdo de cada um (descomprimindo FlateDecode).
"""
import re, zlib, sys
from collections import Counter

if len(sys.argv) < 2:
    print(__doc__)
    raise SystemExit(1)

path = sys.argv[1]
data = open(path, "rb").read()
txt = data.decode("latin-1")

names = sorted(set(re.findall(r'/U?F\s*\(([^)]{1,80})\)', txt)))
print("Nomes de arquivo (/F /UF):", "  |  ".join(names) if names else "(nenhum)")
print("Subtypes no doc:", dict(Counter(re.findall(r'/Subtype\s*/([A-Za-z0-9#.\-]+)', txt))))

idx = 0
cnt = 0
while cnt < 6:
    i = txt.find("/EmbeddedFile", idx)
    if i < 0:
        break
    cnt += 1
    s = txt.find("stream", i)
    if s < 0:
        break
    ds = s + 6
    if ds < len(data) and data[ds] == 13:
        ds += 1
    if ds < len(data) and data[ds] == 10:
        ds += 1
    e = txt.find("endstream", ds)
    raw = data[ds:e]
    print(f"\n#{cnt} EmbeddedFile stream len~{len(raw)}  raw[:16]={raw[:16].hex(' ')}")
    inf = None
    for arg in (None, -15):
        try:
            inf = zlib.decompress(raw) if arg is None else zlib.decompress(raw, arg)
            break
        except Exception:
            pass
    if inf is not None:
        print(f"   inflado: {len(inf)} bytes | inicio: {inf[:80].decode('latin-1')!r}")
    else:
        print(f"   raw inicio: {raw[:80].decode('latin-1')!r}")
    idx = e + 9

print(f"\nTotal de /EmbeddedFile encontrados (ate 6): {cnt}")
