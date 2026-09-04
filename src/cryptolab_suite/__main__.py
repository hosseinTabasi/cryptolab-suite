"""Allow ``python -m cryptolab_suite``."""

from __future__ import annotations

from cryptolab_suite.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
