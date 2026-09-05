#!/usr/bin/env python3
"""校验 pip-licenses CSV 中无传染性 license。

裸 grep "GPL" 会误伤 LGPL (psycopg 等动态链接依赖是允许的),所以按行分类:
阻断 AGPL / SSPL / GPL-2 / GPL-3,放行 LGPL / MPL / Apache / MIT / BSD。
"""
from __future__ import annotations

import csv
import re
import sys

BLOCKED = re.compile(r"\bAGPL|\bSSPL|(?<!L)GPL-?[23]|GNU General Public License", re.I)
ALLOWED = re.compile(r"LGPL|Lesser General Public", re.I)


def main(path: str) -> int:
    violations: list[tuple[str, str, str]] = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            license_text = row.get("License", "")
            if ALLOWED.search(license_text):
                continue
            if BLOCKED.search(license_text):
                violations.append((row["Name"], row["Version"], license_text))

    if violations:
        print("[FAIL] 发现传染性 license 依赖 (违反 license 隔离约束):")
        for name, version, license_text in violations:
            print(f"  {name}=={version} -> {license_text}")
        return 1

    print("[OK] 依赖 license 全部合规 (无 AGPL/GPL/SSPL)")
    return 0


if __name__ == "__main__":
    # Windows 默认 GBK 控制台无法输出部分字符,统一按 UTF-8 输出
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "python-licenses.csv"))
