#!/usr/bin/env python3
"""Python Debug MCP Server — remote Python debugging via debugpy/DAP."""

import logging
import sys

logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from server import mcp  # noqa: E402

if __name__ == "__main__":
    mcp.run(transport="stdio")
