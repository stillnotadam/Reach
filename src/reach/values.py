"""Typed condition keys and parsing of their literal values.

Most condition keys are strings, but IAM has three other families that
the engine models with their own Z3 sorts:

* IP keys (aws:SourceIp, aws:VpcSourceIp): a 32-bit bitvector plus an
  "is IPv4" flag, so CIDR matching is exact bit masking;
* time keys: integer epoch seconds. aws:CurrentTime and aws:EpochTime are
  two spellings of the same instant and share one variable;
* numeric operators work on ordinary string keys whose value is a digit
  string (anything else is left opaque, never guessed).

Typed keys are only used with their own operator family; a string
operator on an IP or time key is treated as unmodelled.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re

IP_KEYS = frozenset({"aws:sourceip", "aws:vpcsourceip"})

# key -> (group, rendering). Keys in one group denote the same instant.
TIME_KEYS = {
    "aws:currenttime": ("now", "iso"),
    "aws:epochtime": ("now", "epoch"),
    "aws:tokenissuetime": ("tokenissuetime", "iso"),
}
# Groups always present in a real request context.
ALWAYS_PRESENT_TIME_GROUPS = frozenset({"now"})

# String keys AWS sets on every request, so "absent" is not a real request.
# Found by differential testing against the IAM policy simulator: treating
# aws:RequestedRegion as optional made an `...IfExists` Deny apply to a
# region-less request that cannot exist.
ALWAYS_PRESENT_KEYS = frozenset({"aws:requestedregion", "aws:userid", "aws:resourceaccount", "aws:principaltype"})


def principal_type(arn: str) -> str:
    """aws:PrincipalType for an IAM user, or for a session of an IAM role."""
    return "User" if ":user/" in arn else "AssumedRole"


MAX_EPOCH = 253_402_300_799  # 9999-12-31T23:59:59Z

# Representative address used when a witness needs "some IPv6 source".
IPV6_WITNESS = "2001:db8::1"

_INT = re.compile(r"[0-9]+")
_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%MZ", "%Y-%m-%d")


def parse_int(text: str) -> int | None:
    """Non-negative integer literals only; decimals and signs are left unmodelled."""
    return int(text) if _INT.fullmatch(text) else None


def parse_time(text: str) -> int | None:
    """ISO 8601 (UTC) or epoch seconds, to epoch seconds."""
    if _INT.fullmatch(text):
        return int(text)
    for fmt in _DATE_FORMATS:
        try:
            moment = dt.datetime.strptime(text, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
        return int(moment.timestamp())
    return None


def render_time(epoch: int, style: str) -> str:
    if style == "epoch":
        return str(epoch)
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ipv4_network(text: str) -> tuple[int, int] | None:
    """An IPv4 address or CIDR as (network, mask) integers; None for IPv6 or malformed input."""
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    return int(net.network_address), int(net.netmask)


def parse_ip(text: str) -> tuple[bool, int] | None:
    """(is_ipv4, value) for a request's source address; value is 0 for IPv6."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return (True, int(addr)) if addr.version == 4 else (False, 0)


def render_ipv4(value: int) -> str:
    return str(ipaddress.IPv4Address(value))
