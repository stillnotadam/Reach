"""Typed condition keys and parsing of their literal values.

Most condition keys are strings, but IAM has three other families that
the engine models with their own Z3 sorts:

* IP keys (aws:SourceIp, aws:VpcSourceIp): a 128-bit bitvector plus an
  "is IPv4" flag (an IPv4 address in the low 32 bits), so CIDR matching is
  exact bit masking for both families. An IPv4 network only ever matches
  IPv4 sources and an IPv6 network IPv6 sources. AWS reports an IPv4 client
  as IPv4, so a source address is never IPv4-mapped IPv6 (::ffff:a.b.c.d):
  a mapped value is read as the IPv4 address it carries, and a policy
  network inside ::ffff:0:0/96 is left unmodelled;
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
from decimal import Decimal
from fractions import Fraction

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


# Global keys whose value is always "true" or "false" in a real request.
BOOLEAN_KEYS = frozenset({"aws:multifactorauthpresent", "aws:securetransport", "aws:viaawsservice",
                          "aws:principalisawsservice"})  # fmt: skip


# Services whose resources resource control policies (RCPs) apply to (AWS Organizations user guide, "List of AWS
# services that support RCPs"). Only actions of these services are subject to an RCP.
_RCP_SERVICE_LIST = """
appstream dsql clouddirectory cloudfront cloudsearch logs networkmonitor cognito-identity cognito-idp comprehend
comprehendmedical firehose dynamodb dax autoscaling ecr ecr-public gamelift inspector-scan kendra kinesisvideo
memorydb aoss personalize polly s3 swf sqs textract timestream-influxdb transcribe translate workspaces appconfig
autoscaling-plans budgets servicediscovery cloudtrail-data codeartifact codebuild codecommit codepipeline
compute-optimizer cost-optimization-hub events fms fis health rolesanywhere kms opensearch pricing pca-connector-ad
resource-groups secretsmanager sts signin support transfer notifications wafv2 xray
"""
RCP_SERVICES = frozenset(_RCP_SERVICE_LIST.split())
RCP_EXEMPT_ACTIONS = frozenset({"kms:retiregrant"})


def parse_bool(text: str) -> bool:
    """How the Bool operator reads a value, on either side: "true" in any case is true, anything else false.

    Measured against AWS's policy simulator (validation/FINDINGS.md, finding 6), for boolean and other keys alike.
    """
    return text.lower() == "true"


def username(arn: str) -> str | None:
    """aws:username: an IAM user's name; not present for role sessions (IAM User Guide, policy variables)."""
    return arn.rsplit("/", 1)[-1] if ":user/" in arn else None


MAX_EPOCH = 253_402_300_799  # 9999-12-31T23:59:59Z


_INT = re.compile(r"[0-9]+")
_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%MZ", "%Y-%m-%d")


def parse_int(text: str) -> int | None:
    """Non-negative integer literals (epoch seconds; the simulator harness's numeric context type)."""
    return int(text) if _INT.fullmatch(text) else None


# --- numbers (Numeric* operators) ----------------------------------------------------------------------------
#
# Measured on AWS (validation/FINDINGS.md, finding 9): numbers are read with Java BigDecimal syntax and compared
# exactly. A sign, a leading or trailing point, an exponent and leading zeros are fine; whitespace, hex, `1d`,
# `Infinity` and `1_000` are not. A request value may use any Unicode decimal digit (`١٠` is 10). An invalid
# request value makes every Numeric operator false, negated or not; an invalid policy value never matches.
#
# Reach decides plain decimals exactly (`-12.50`): CANONICAL. Other valid spellings of a request value (`+5`,
# `1e1`, `.5`, Unicode digits) are left unmodelled rather than parsed symbolically.

# In a str pattern \d is any Unicode decimal digit, which is what BigDecimal accepts.
NUMBER = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")
CANONICAL_NUMBER = re.compile(r"-?[0-9]+(\.[0-9]+)?")
MAX_EXPONENT = 1000  # larger exponents are valid for AWS but not worth an exact model here
UNMODELLED = object()


def parse_number(text: str) -> Fraction | object | None:
    """A policy value for a Numeric operator: its exact value, None if AWS rejects it (it never matches), or
    UNMODELLED (non-ASCII digits, which IAM cannot store in a policy anyway, or a huge exponent)."""
    if not NUMBER.fullmatch(text):
        return None
    if not text.isascii():
        return UNMODELLED
    _, _, exponent = text.lower().partition("e")
    if exponent and abs(int(exponent)) > MAX_EXPONENT:
        return UNMODELLED
    return Fraction(Decimal(text))


# NUMBER with any non-ASCII character standing in for a digit: a superset of the valid numbers that a solver
# handles far faster than Unicode's ~70 digit ranges. Strings it adds are rejected by AWS but only ever made
# UNKNOWN here, never decided.
LOOSE_NUMBER = re.compile(r"[+-]?(D+(\.D*)?|\.D+)([eE][+-]?D+)?".replace("D", "[0-9\u0080-\U0010ffff]"))


def request_number(text: str) -> Fraction | object | None:
    """A request value under a Numeric operator: exact for plain decimals, None if AWS rejects it (every
    Numeric operator is then false), UNMODELLED for other spellings that may be valid (LOOSE_NUMBER)."""
    if CANONICAL_NUMBER.fullmatch(text):
        return Fraction(Decimal(text))
    return UNMODELLED if LOOSE_NUMBER.fullmatch(text) else None


def decimal_places(value: Fraction) -> int:
    """Digits after the point a decimal needs: 0.25 -> 2, 10 -> 0, 1e-3 -> 3."""
    places = 0
    while (value * 10**places).denominator != 1:
        places += 1
    return places


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


IP_BITS = 128
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def parse_ip_network(text: str) -> tuple[bool, int, int] | None:
    """An address or CIDR as (is_ipv4, network, mask); None if malformed or IPv4-mapped IPv6.

    Both families share one 128-bit space: an IPv4 network sits in the low 32 bits, and is_ipv4 keeps the
    families apart, so 10.0.0.0/8 never matches the IPv6 address ::a00:1.
    """
    if "%" in text:  # an IPv6 zone index (fe80::1%eth0): Python takes it, a policy value cannot mean it
        return None
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if net.version == 6 and net.subnet_of(_MAPPED):  # type: ignore[arg-type]
        return None
    return net.version == 4, int(net.network_address), int(net.netmask)


def parse_ip(text: str) -> tuple[bool, int] | None:
    """(is_ipv4, value) for a request's source address. An IPv4-mapped IPv6 address is the IPv4 it carries."""
    if "%" in text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.version == 4, int(addr)


def is_mapped(value: int) -> bool:
    """Is a 128-bit value in ::ffff:0:0/96? A free IPv6 source never is (see the module docstring)."""
    return int(_MAPPED.network_address) <= value <= int(_MAPPED.broadcast_address)


def render_ip(is_v4: bool, value: int) -> str:
    return str(ipaddress.IPv4Address(value) if is_v4 else ipaddress.IPv6Address(value))


# --- case-insensitive strings (StringEqualsIgnoreCase) --------------------------------------------------------
#
# Measured on AWS (validation/FINDINGS.md, finding 8): two strings are equal ignoring case when their full Unicode
# lowercase forms are equal. The Kelvin sign K matches "k" and capital sharp s matches "ß"; but long s, dotless i,
# dotted capital I and the micro sign match nothing new, which rules out ASCII-only folding and Java's
# equalsIgnoreCase. IAM accepts only Latin-1 text in a policy, so a policy value's lowercase is Latin-1, and the
# request characters that lowercase to a Latin-1 character are Latin-1 itself plus these four.
_LOWERS_INTO_LATIN_1 = {"K": "k", "Å": "å", "ẞ": "ß", "Ÿ": "ÿ"}


def ignore_case_equal(a: str, b: str) -> bool:
    return a.lower() == b.lower()


def ignore_case_classes(text: str) -> list[tuple[str, ...]] | None:
    """For each character of text's lowercase, every character whose lowercase it is.

    None when text has a character outside Latin-1: IAM rejects such a policy, and its lowercase forms are not
    covered here.
    """
    if any(ord(c) > 0xFF for c in text):
        return None
    classes = []
    for c in text.lower():
        members = [chr(x) for x in range(0x100) if chr(x).lower() == c]
        members += [k for k, v in _LOWERS_INTO_LATIN_1.items() if v == c]
        classes.append(tuple(members))
    return classes
