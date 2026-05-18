#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Transport plugin entrypoint for optional `soenc transport` command."""

from typing import Optional
from typing import Sequence

from enc2sop.transport import cli as transport_cli

import qrcode_helper


def main(argv: Optional[Sequence[str]] = None) -> int:
    return int(transport_cli.run_cli(argv=list(argv) if argv is not None else None, transport_cls=qrcode_helper.AirgapTransportLayer))


__all__ = ["main"]
