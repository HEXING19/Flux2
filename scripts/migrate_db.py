#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Flux SQLite schema migration (idempotent).")
    parser.add_argument(
        "--db-path",
        default=None,
        help="Override DB path. Defaults to DB_PATH env or settings default.",
    )
    args = parser.parse_args()

    if args.db_path:
        os.environ["DB_PATH"] = args.db_path

    from app.core.db import init_db
    from app.core.settings import settings

    db_path = Path(settings.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[migrate] using sqlite file: {db_path}")
    init_db()
    print("[migrate] schema ensured successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

