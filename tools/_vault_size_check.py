from pathlib import Path

items = [
    ("origin", "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7", 5232656),
    ("oracle", "fe92f992bcf07e630c82ff3a1cfc138a8c2463e3e03f862da171e8781119268f", 1696768),
    ("lunlun", "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07", 4976144),
    ("gto", "4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8", 8583680),
    ("gto_ref", "dcc411afaafed6bf3fbc52c0c72eddf79f56fc9aea1516b911d49f59c94af379", 15497216),
    ("dali", "e4f48d5a13589bd7232268d4836f1b7581983536f3310cc066f04d463873165d", 6129664),
    ("plain", "5ae16f20b1131e0e030a5f364340fe20d5425be4684bb1b2514ed4ebbb137df3", 1024),
]
root = Path(r"D:\MidaVault\objects\sha256")
for name, sha, exp in items:
    p = root / sha[:2] / sha
    if p.is_file():
        sz = p.stat().st_size
        print(f"{name}: PRESENT size={sz} expect={exp} match={sz == exp}")
    else:
        print(f"{name}: MISSING")
