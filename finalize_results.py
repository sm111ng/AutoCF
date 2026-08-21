#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoCF Finalizer
读取 real_results.csv + real_usable_nodes.txt
生成：
  output/FINAL_nodes.txt
  output/FINAL_subscription.txt
  output/regions/JP.txt / US.txt / SG.txt ...
  output/regions_summary.txt

规则：
- 只使用真实 VLESS 测试通过的节点
- 每个出口地区最多 TOP_PER_REGION 个
- 优先 score 高，其次延迟低
- 名称统一为 REGION-01 / REGION-02 / REGION-03
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
    raise FileNotFoundError(f"找不到 {RESULTS}")
if not NODES.exists():
    raise FileNotFoundError(f"找不到 {NODES}")

with RESULTS.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

# real_results.csv 可能包含失败节点，只取真实成功节点
usable = []
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

# 建立 endpoint -> 原始 VLESS
vless_map = {}
for line in NODES.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = line.strip()
    if not line.startswith("vless://"):
        continue
    ip, port = parse_endpoint(line)
    if ip:
        vless_map[(ip, port)] = line

# 每地区选 Top 3
selected = []
for region in sorted(set(r["_region"] for r in usable)):
    candidates = [r for r in usable if r["_region"] == region]
    candidates.sort(key=lambda r: (-r["_score"], r["_latency"]))
    selected.extend(candidates[:TOP_PER_REGION])

# 最终按 score / latency 排序
selected.sort(key=lambda r: (-r["_score"], r["_latency"]))

# 重新编号，并生成 VLESS
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

    # 如果 real_usable_nodes 里已有对应 endpoint，就优先使用它；
    # 否则跳过，避免凭空构造 VLESS 参数。
    if not src:
        continue

    if "#" in src:
        src = src.split("#", 1)[0]
    line = src + "#" + name

    r["name"] = name
    r["_vless"] = line
    final_lines.append(line)
    final_records.append(r)

# 总节点文件
(OUT / "FINAL_nodes.txt").write_text(
    "\n".join(final_lines) + ("\n" if final_lines else ""),
    encoding="utf-8"
)

# Base64 订阅
raw = "\n".join(final_lines) + ("\n" if final_lines else "")
encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
(OUT / "FINAL_subscription.txt").write_text(encoded + "\n", encoding="ascii")

# 每地区单独文件
for p in REGIONS.glob("*.txt"):
    p.unlink()

by_region = {}
for r in final_records:
    by_region.setdefault(r["_region"], []).append(r["_vless"])

for region, lines in sorted(by_region.items()):
    (REGIONS / f"{region}.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

# 汇总
summary = []
summary.append("AutoCF FINAL RESULT")
summary.append("=" * 78)
summary.append(f"真实 VLESS 可用输入: {len(usable)}")
summary.append(f"最终节点:            {len(final_records)}")
summary.append(f"每地区上限:          {TOP_PER_REGION}")
summary.append("")
summary.append("地区统计")
summary.append("-" * 78)

for region in sorted(by_region):
    summary.append(f"{region:4} {len(by_region[region]):2} nodes")

summary.append("")
summary.append("最终节点")
summary.append("-" * 78)

for i, r in enumerate(final_records, 1):
    summary.append(
        f"{i:02d}. {r['name']:6} "
        f"入口={r.get('ip','')}:{r.get('port','')} "
        f"出口={r.get('exit_ip','')} "
        f"{r['_region']:4} "
        f"{r['_latency']}ms "
        f"稳定={float(r.get('success_rate') or 0):.0%} "
        f"Score={r['_score']:.0f}"
    )

(OUT / "FINAL_summary.txt").write_text(
    "\n".join(summary) + "\n",
    encoding="utf-8"
)

print("=" * 78)
print("AutoCF FINALIZER")
print("=" * 78)
print(f"真实 VLESS 可用输入: {len(usable)}")
print(f"最终节点:            {len(final_records)}")
print("")
for region in sorted(by_region):
    print(f"{region:4} {len(by_region[region]):2} nodes")
print("")
print("输出：")
print(f"  {OUT / 'FINAL_nodes.txt'}")
print(f"  {OUT / 'FINAL_subscription.txt'}")
print(f"  {OUT / 'FINAL_summary.txt'}")
print(f"  {REGIONS}")
