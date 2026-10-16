"""Hola mundo · corre los tres smoke tests en orden.

    python scripts/hello_all.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def run(script: str) -> int:
    print(f"\n{'=' * 60}\n>>> {script}\n{'=' * 60}")
    r = subprocess.run([sys.executable, str(HERE / script)])
    return r.returncode


def main() -> int:
    scripts = ["hello_mongo.py", "hello_redis.py", "hello_sqlite.py"]
    failed = []
    for s in scripts:
        if run(s) != 0:
            failed.append(s)
    print("\n" + "=" * 60)
    if failed:
        print(f"[FAIL] {len(failed)} script(s) fallaron: {failed}")
        return 1
    print("[OK] los tres motores respondieron — Seguimiento 1 listo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
