"""Command line entry point."""

from __future__ import annotations

import argparse
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    raise NotImplementedError


def main(argv: Sequence[str] | None = None) -> int:
    raise NotImplementedError
