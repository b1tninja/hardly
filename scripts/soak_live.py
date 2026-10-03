"""Thin wrapper: python scripts/soak_live.py → python -m hardly.soak_live."""

from hardly.soak_live import main

if __name__ == "__main__":
    raise SystemExit(main())
