# --- UTF-8 stdout/stderr fix for GitHub Actions / Windows ---
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
# --- END UTF-8 FIX ---
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoCF Finalizer
璇诲彇 real_results.csv + real_usable_nodes.txt
鐢熸垚锛?  output/FINAL_nodes.txt
  output/FINAL_subscription.txt
  output/regions/JP.txt / US.txt / SG.txt ...
  output/regions_summary.txt

瑙勫垯锛?- 鍙娇鐢ㄧ湡瀹?VLESS 娴嬭瘯閫氳繃鐨勮妭鐐?- 姣忎釜鍑哄彛鍦板尯鏈€澶?TOP_PER_REGION 涓?- 浼樺厛 score 楂橈紝鍏舵寤惰繜浣?- 鍚嶇О缁熶竴涓?REGION-01 / REGION-02 / REGION-03
"""

from pathlib import Path
import csv
import base64
import re

BASE = Path(__file__).resolve().parent
OUT = BASE / "output"
REGIONS = OUT / "regions"
TOP_PER_REGION = 3

OUT.mkdir(exist_ok=True)
REGIONS.mkdir(exist_ok=True)

RESULTS = BASE / "real_results.csv"
NODES = BASE / "real_usable_nodes.txt"

def parse_name(line):
    m = re.search(r"#([^#]+)\s*$", line.strip())
    return m.group(1).strip() if m else ""

def parse_endpoint(line):
    m = re.search(r"@(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
    return (m.group(1), int(m.group(2))) if m else ("", 0)

if not RESULTS.exists():
    raise FileNotFoundError(f"鎵句笉鍒?{RESULTS}")
if not NODES.exists():
    raise FileNotFoundError(f"鎵句笉鍒?{NODES}")

with RESULTS.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

# real_results.csv 鍙兘鍖呭惈澶辫触鑺傜偣锛屽彧鍙栫湡瀹炴垚鍔熻妭鐐?usable = []
for r in rows:
    ok = str(r.get("ok", "")).lower() in ("true", "1", "yes")
    if not ok:
        continue
    region = (r.get("region") or "??").upper()
    try:
        latency = int(float(r.get("latency_ms") or 999999))
    except Exception:
        latency = 999999
    try:
        score = float(r.get("score") or 0)
    except Exception:
        score = 0
    r["_region"] = region
    r["_latency"] = latency
    r["_score"] = score
    usable.append(r)

# 寤虹珛 endpoint -> 鍘熷 VLESS
vless_map = {}
for line in NODES.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = line.strip()
    if not line.startswith("vless://"):
        continue
    ip, port = parse_endpoint(line)
    if ip:
        vless_map[(ip, port)] = line

# 姣忓湴鍖洪€?Top 3
selected = []
for region in sorted(set(r["_region"] for r in usable)):
    candidates = [r for r in usable if r["_region"] == region]
    candidates.sort(key=lambda r: (-r["_score"], r["_latency"]))
    selected.extend(candidates[:TOP_PER_REGION])

# 鏈€缁堟寜 score / latency 鎺掑簭
selected.sort(key=lambda r: (-r["_score"], r["_latency"]))

# 閲嶆柊缂栧彿锛屽苟鐢熸垚 VLESS
counters = {}
final_lines = []
final_records = []

for r in selected:
    region = r["_region"]
    counters[region] = counters.get(region, 0) + 1
    name = f"{region}-{counters[region]:02d}"

    ip = r.get("ip", "")
    port = int(r.get("port") or 0)
    src = vless_map.get((ip, port))

    # 濡傛灉 real_usable_nodes 閲屽凡鏈夊搴?endpoint锛屽氨浼樺厛浣跨敤瀹冿紱
    # 鍚﹀垯璺宠繃锛岄伩鍏嶅嚟绌烘瀯閫?VLESS 鍙傛暟銆?    if not src:
        continue

    if "#" in src:
        src = src.split("#", 1)[0]
    line = src + "#" + name

    r["name"] = name
    r["_vless"] = line
    final_lines.append(line)
    final_records.append(r)

# 鎬昏妭鐐规枃浠?(OUT / "FINAL_nodes.txt").write_text(
    "\n".join(final_lines) + ("\n" if final_lines else ""),
    encoding="utf-8"
)

# Base64 璁㈤槄
raw = "\n".join(final_lines) + ("\n" if final_lines else "")
encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
(OUT / "FINAL_subscription.txt").write_text(encoded + "\n", encoding="ascii")

# 姣忓湴鍖哄崟鐙枃浠?for p in REGIONS.glob("*.txt"):
    p.unlink()

by_region = {}
for r in final_records:
    by_region.setdefault(r["_region"], []).append(r["_vless"])

for region, lines in sorted(by_region.items()):
    (REGIONS / f"{region}.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

# 姹囨€?summary = []
summary.append("AutoCF FINAL RESULT")
summary.append("=" * 78)
summary.append(f"鐪熷疄 VLESS 鍙敤杈撳叆: {len(usable)}")
summary.append(f"鏈€缁堣妭鐐?            {len(final_records)}")
summary.append(f"姣忓湴鍖轰笂闄?          {TOP_PER_REGION}")
summary.append("")
summary.append("鍦板尯缁熻")
summary.append("-" * 78)

for region in sorted(by_region):
    summary.append(f"{region:4} {len(by_region[region]):2} nodes")

summary.append("")
summary.append("鏈€缁堣妭鐐?)
summary.append("-" * 78)

for i, r in enumerate(final_records, 1):
    summary.append(
        f"{i:02d}. {r['name']:6} "
        f"鍏ュ彛={r.get('ip','')}:{r.get('port','')} "
        f"鍑哄彛={r.get('exit_ip','')} "
        f"{r['_region']:4} "
        f"{r['_latency']}ms "
        f"绋冲畾={float(r.get('success_rate') or 0):.0%} "
        f"Score={r['_score']:.0f}"
    )

(OUT / "FINAL_summary.txt").write_text(
    "\n".join(summary) + "\n",
    encoding="utf-8"
)

print("=" * 78)
print("AutoCF FINALIZER")
print("=" * 78)
print(f"鐪熷疄 VLESS 鍙敤杈撳叆: {len(usable)}")
print(f"鏈€缁堣妭鐐?            {len(final_records)}")
print("")
for region in sorted(by_region):
    print(f"{region:4} {len(by_region[region]):2} nodes")
print("")
print("杈撳嚭锛?)
print(f"  {OUT / 'FINAL_nodes.txt'}")
print(f"  {OUT / 'FINAL_subscription.txt'}")
print(f"  {OUT / 'FINAL_summary.txt'}")
print(f"  {REGIONS}")

