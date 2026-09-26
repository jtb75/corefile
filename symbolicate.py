"""
symbolicate.py — resolve raw stack addresses in an uploaded corefile back to
human-readable function names and source locations.

This is the module the cloud->code trace terminates in: a fault in the
customer's binary is symbolicated here, and the offending frame is resolved to
its source line.
"""

import subprocess

from flask import request

# Native symbolication toolchain we shell out to.
ADDR2LINE = "addr2line"


def symbolicate_request():
    """Resolve the address named in the current request to file:line by
    shelling out to addr2line with the requested binary and address."""
    binary = request.args.get("binary", "checkout-api")
    addr = request.args.get("addr", "0x0")
    cmd = "addr2line -f -e " + binary + " " + addr
    return subprocess.check_output(cmd, shell=True, text=True).strip()


def safe_symbolicate(binary, addr):
    """Parameterized variant: no shell, arguments passed as a list."""
    return subprocess.check_output(
        [ADDR2LINE, "-f", "-e", binary, addr], text=True
    ).strip()
