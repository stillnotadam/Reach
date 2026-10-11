"""The authorization decision, encoded for Z3, and the three-valued verdict.

A query asks: can `principal` perform an action matching `query.action`
on a resource matching `query.resource`, in *some* request context?

The decision follows AWS's documented evaluation logic (RCPs are not
modelled yet; see ROADMAP.md):

    allowed = no explicit Deny in any policy that applies
              and every SCP layer (root -> OU -> account) allows it
              and some grant path allows it

    identity path = an identity-based policy allows it
                    and the permissions boundary allows it (if any)
                    and the session policy allows it (if any)

The grant paths depend on the resource-based policy, if the resource has one:

* none: the identity path.
* same account: the identity path, or a resource-policy grant that names
  the principal directly (user ARN, session ARN: unlimited; role ARN:
  still capped by boundary and session policy). A grant to the account
  principal only delegates, so it adds nothing beyond the identity path.
  Verified on live S3 (validation/live_account_grant.py), where AWS's own
  policy simulator gets it wrong (validation/FINDINGS.md, finding 4).
* same account, policy required (role trust policies, KMS key policies):
  a direct grant, or an account grant together with the identity path.
* cross-account: the identity path and a resource-policy grant.

Whether a `Principal: "*"` grant is capped by a boundary or session policy
is not verified against AWS yet; when it matters the verdict is UNKNOWN.
See validation/FINDINGS.md for how these rules were checked.

Verdicts:

* DENIED  - the formula is unsatisfiable: no request, no context value
            and no interpretation of the unmodelled conditions allows
            it. This is a proof, not a scan result.
* ALLOWED - still satisfiable after every unmodelled condition is pinned
            to its worst case (Allow conditions false, Deny conditions
            true), so the answer does not depend on anything we skipped.
            Comes with a concrete witness request.
* UNKNOWN - allowed only if some unmodelled condition goes our way. We
            report which assumptions the optimistic witness relies on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import Enum

import z3

from .catalog import Catalog, bundled, iam_glob_regex
from .conditions import STRING_OPS, Context, ContextValue, encode_conditions, is_multivalued, key_kind, wrap_presence
from .patterns import PRINTABLE, ArnVar, glob, has_wildcard, matches_any, sval
from .policy import Policy, Statement
from .principals import Match, classify
from .values import (
    RCP_EXEMPT_ACTIONS,
    RCP_SERVICES,
    TIME_KEYS,
    principal_type,
    render_ip,
    render_time,
    username,
)
from .variables import FREE, Pattern, SymbolicCondition, Var, resolve_statement

SOLVER_TIMEOUT_MS = 30_000
PREFERENCE_TIMEOUT_MS = 2_000  # per witness preference (see _model)
RECENT_EPOCH = 1_577_836_800  # 2020-01-01: witnesses prefer plausible clock values


class InconsistencyError(RuntimeError):
    """The solver and the reference evaluator disagree about a witness. Always a Reach bug."""


WITNESS_REGION = "us-east-1"
WITNESS_ACCOUNT = "111122223333"


class Verdict(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"


@dataclass
class Principal:
    arn: str
    identity_policies: list[Policy]
    boundary: Policy | None = None
    tags: dict[str, str] = field(default_factory=dict)
    # Attached policies we could not load. Any of them might allow or deny,
    # so no verdict about this principal can be proven while this is non-empty.
    unresolved: list[str] = field(default_factory=list)

    @property
    def account(self) -> str:
        parts = self.arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    @property
    def is_service_linked(self) -> bool:
        return ":role/aws-service-role/" in self.arn


@dataclass
class Environment:
    # Ordered root -> OU(s) -> account. Each layer must allow the request.
    scp_layers: list[tuple[str, list[Policy]]] = field(default_factory=list)
    session_policies: list[Policy] = field(default_factory=list)
    # The organization's management account is not affected by SCPs.
    management_account: bool = False
    # Resource control policies of the account that owns the resource, every level from root to account.
    # Empty when there are none, or when the resource is in the management account (RCPs never apply there).
    rcps: list[Policy] = field(default_factory=list)
    # Context the organization fixes: aws:PrincipalOrgID, aws:PrincipalOrgPaths, aws:ResourceOrgID, ...
    # (None pins a key as absent, e.g. aws:PrincipalOrgID for a caller outside any organization).
    org_context: dict[str, ContextValue] = field(default_factory=dict)


@dataclass
class ResourcePolicy:
    policy: Policy
    account: str  # the account that owns the resource
    # Role trust policies and KMS key policies: identity permissions alone
    # never suffice, the resource policy must grant (or delegate) access.
    required: bool = False


@dataclass
class Query:
    action: str
    resource: str
    # Pinned context keys; None pins a key as absent from the request.
    context: dict[str, ContextValue] = field(default_factory=dict)
    resource_policy: ResourcePolicy | None = None


@dataclass
class Witness:
    action: str
    resource: str
    context: dict[str, ContextValue]  # None = key absent from the request; a list for a multi-valued key


@dataclass
class Result:
    verdict: Verdict
    principal: str
    query: Query
    witness: Witness | None = None
    reasons: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class _Gate:
    name: str
    expr: z3.BoolRef


def set_bounds(principal: Principal, query: Query, env: Environment) -> dict[str, int]:
    """How many elements a multi-valued key's set needs, per key: its set conditions, plus one.

    Small-model argument: take any request that satisfies the constraints. Keep, for every set condition on
    the key, one element witnessing it (a matching element if it is a true ForAnyValue, a failing one if it
    is a false ForAllValues), plus one element if the set is non-empty. Every set condition keeps its truth
    value on this subset: existential ones keep their witness, universal ones only lose elements. So if any
    request satisfies the constraints, one with at most this many elements does, and a DENIED proof over
    the bounded sets is a proof over all requests.
    """
    policies = [*principal.identity_policies, *env.session_policies, *(p for _, ps in env.scp_layers for p in ps)]
    policies += [principal.boundary] if principal.boundary else []
    policies += [query.resource_policy.policy] if query.resource_policy else []
    counts: dict[str, int] = {}
    for p in policies:
        for st in p.statements:
            for c in st.conditions:
                if ":" in c.operator:
                    counts[c.key.lower()] = counts.get(c.key.lower(), 0) + 1
    return {k: n + 1 for k, n in counts.items()}


class _Encoding:
    """All symbolic pieces of one query, built once and reused by every solver call."""

    def __init__(
        self,
        principal: Principal,
        query: Query,
        env: Environment,
        catalog: Catalog | None,
        action: str | None,
        resource_types: tuple[str, ...] | None = None,
    ):
        fixed: dict[str, ContextValue] = {
            "aws:PrincipalArn": principal.arn,
            "aws:PrincipalAccount": principal.account,
            "aws:PrincipalType": principal_type(principal.arn),
            # Reach's principals are IAM users and role sessions, never AWS service principals.
            "aws:PrincipalIsAWSService": "false",
            "aws:username": username(principal.arn),
        }
        fixed.update({f"aws:PrincipalTag/{k}": v for k, v in principal.tags.items()})
        fixed.update(env.org_context)
        fixed.update(query.context)
        self.ctx = Context(fixed, closed_prefixes=("aws:PrincipalTag/",), set_bounds=set_bounds(principal, query, env))
        self.action = z3.String("action")
        self.arn = ArnVar("resource")
        self.resource = self.arn.full
        self.denies: list[tuple[Statement, z3.BoolRef]] = []
        self.notes: list[str] = []
        self.catalog = catalog
        # One concrete action standing for its whole action class (see _action_classes),
        # or None: the action is then a free string, constrained only by the query.
        self.rep = action

        if action is not None:
            # Each action applies only to its own resource types (FINDINGS.md, finding 2).
            # resource_types narrows the action to some of its resource types (see _units).
            globs = resource_types if resource_types is not None else catalog.resource_globs(action) if catalog else ()
            action_term = z3.And(
                self.action == sval(action), self.arn.matches_any(globs) if globs else z3.BoolVal(True)
            )
        else:
            action_term = matches_any(self.action, (query.action.lower(),), arn=False)
        self.request = z3.And(action_term, self.arn.matches(query.resource), *self.arn.well_formed)
        if query.resource.count(":") < 5 and query.resource != "*":
            self.notes.append(f"{query.resource!r} is not an ARN; AWS resources are always six-segment ARNs.")

        scps_apply = not env.management_account and not principal.is_service_linked
        self.scps = (
            [_Gate(f"SCPs at {layer}", self._allows(pols)) for layer, pols in env.scp_layers] if scps_apply else []
        )
        self.identity = _Gate("identity-based policies", self._allows(principal.identity_policies))
        # Boundary and session policies cap the identity path and role-ARN grants.
        self.caps: list[_Gate] = []
        if principal.boundary is not None:
            self.caps.append(
                _Gate(f"permissions boundary {principal.boundary.name}", self._allows([principal.boundary]))
            )
        for sp in env.session_policies:
            self.caps.append(_Gate(f"session policy {sp.name}", self._allows([sp])))
        capped = z3.And(*[g.expr for g in self.caps]) if self.caps else z3.BoolVal(True)
        self.identity_path = z3.And(self.identity.expr, capped)
        self.grant = self._grant(principal, query.resource_policy, capped)

        # Explicit denies count from every policy that applies, including ones
        # whose Allow statements are irrelevant (e.g. a Deny inside a boundary).
        for p in principal.identity_policies + ([principal.boundary] if principal.boundary else []):
            self._collect_denies(p)
        if scps_apply:
            for _, policies in env.scp_layers:
                for p in policies:
                    self._collect_denies(p)
        for sp in env.session_policies:
            self._collect_denies(sp)
        if env.rcps and not principal.is_service_linked:  # RCPs never restrict service-linked roles
            for rcp in env.rcps:
                for st in rcp.statements:
                    if st.effect == "Deny" and classify(st, principal.arn):
                        self.denies.append((st, z3.And(self._statement(st), self._rcp_scope(st))))
        if query.resource_policy is not None:
            for st in query.resource_policy.policy.statements:
                if st.effect == "Deny" and classify(st, principal.arn):
                    self.denies.append((st, self._statement(st)))

        # Domain facts are only known once every condition has been encoded.
        self.request = z3.And(self.request, *self.ctx.domain, *self._key_support())
        any_deny = z3.Or([e for _, e in self.denies]) if self.denies else z3.BoolVal(False)
        self.not_denied = z3.Not(any_deny)
        self.allowed = z3.And(self.request, self.not_denied, *[g.expr for g in self.scps], self.grant)

    def _grant(self, principal: Principal, rp: ResourcePolicy | None, capped: z3.BoolRef) -> z3.BoolRef:
        self.rp = rp
        self.rp_any = z3.BoolVal(False)  # the resource policy grants this principal in any way
        if rp is None:
            return self.identity_path
        by_kind: dict[Match, list[z3.BoolRef]] = {m: [] for m in Match}
        for st in rp.policy.statements:
            if st.effect != "Allow":
                continue
            kinds = classify(st, principal.arn)
            if kinds:
                expr = self._statement(st)
                for kind in kinds:
                    by_kind[kind].append(expr)

        def anyof(kind: Match) -> z3.BoolRef:
            return z3.Or(by_kind[kind]) if by_kind[kind] else z3.BoolVal(False)

        self.rp_any = z3.Or([anyof(m) for m in Match])
        if rp.account != principal.account:
            return z3.And(self.identity_path, self.rp_any)

        wildcard = anyof(Match.WILDCARD)
        if self.caps and by_kind[Match.WILDCARD]:
            unverified = self.ctx.assumption(
                "Allow",
                'a Principal "*" grant is not limited by the boundary or session policy (not yet verified against AWS)',
                rp.policy.name,
            )
            wildcard = z3.And(wildcard, z3.Or(capped, unverified))
        direct = z3.Or(anyof(Match.USER), anyof(Match.SESSION), z3.And(anyof(Match.ROLE), capped), wildcard)
        if rp.required:
            return z3.Or(direct, z3.And(anyof(Match.ACCOUNT), self.identity_path))
        # An account grant only delegates: it adds nothing beyond the identity path.
        return z3.Or(self.identity_path, direct)

    def _key_support(self) -> list[z3.BoolRef]:
        """Service-specific keys exist only on actions that support them (FINDINGS.md, finding 3)."""
        if self.rep is None or self.catalog is None:
            return []
        return [
            z3.Not(self.ctx.presence[k])
            for k, key in self.ctx.keys.items()
            if not k.startswith("aws:")
            and key.kind in ("string", "set")
            and not self.catalog.supports_key(self.rep, key.name)
        ]

    def _lookup(self, key: str) -> str | None | object:
        """A policy variable's value: pinned or principal-derived, None if absent, FREE if the request decides it."""
        if is_multivalued(key):
            return FREE  # never reached: variables over multi-valued keys are left undecided before lookup
        if key in self.ctx.fixed:
            return self.ctx.fixed[key]
        if any(key.startswith(p) for p in self.ctx.closed_prefixes):
            return None
        return FREE

    def _statement(self, original: Statement) -> z3.BoolRef:
        resolved = resolve_statement(original, self._lookup)
        if resolved.statement is None:
            return z3.BoolVal(False)  # a variable with no value leaves nothing to match
        stmt = resolved.statement
        if self.rep is not None:
            if not _action_matches(stmt, self.rep):
                return z3.BoolVal(False)
            action: z3.BoolRef = z3.BoolVal(True)
        else:
            action = matches_any(self.action, tuple(a.lower() for a in stmt.actions), arn=False)
            if stmt.not_actions:
                action = z3.Not(action)
        # Entries whose variables the request decides are matched symbolically, against the key's own
        # solver variable, so they stay exact.
        matched = [
            self.arn.matches_any(stmt.resources),
            *(self._symbolic_resource(p) for p in resolved.symbolic_resources),
        ]
        resource = z3.Or(matched)
        # Entries the model leaves undecided are opaques, placed so they occur positively
        # (for NotResource, "does not match it" is the unknown).
        undecided = [self.ctx.opaque(stmt, f"policy variable in Resource {r}") for r in resolved.undecided_resources]
        if stmt.not_resources:
            resource = z3.And(z3.Not(resource), *undecided)
        elif undecided:
            resource = z3.Or(resource, *undecided)
        conditions = [encode_conditions(stmt, self.ctx)]
        conditions += [self._symbolic_condition(c, stmt) for c in resolved.symbolic_conditions]
        conditions += [
            self.ctx.opaque(stmt, f"policy variable in {c.operator} {c.key}") for c in resolved.undecided_conditions
        ]
        return z3.And(action, resource, *conditions)

    # --- policy variables the request decides ----------------------------------------

    def _var_value(self, var: Var) -> tuple[z3.BoolRef, z3.SeqRef]:
        """(the variable has a value, that value): the key's own value, else its default."""
        name = var.name or var.key
        present, value = self.ctx.present(name), self.ctx.string(name)
        if var.default is None:
            return present, value
        return z3.BoolVal(True), z3.If(present, value, sval(var.default))

    def _var_regex(self, pattern: Pattern) -> tuple[z3.BoolRef, z3.ReRef]:
        """(every variable has a value, the pattern as a regex with variable values literal)."""
        defined: list[z3.BoolRef] = []
        parts: list[z3.ReRef] = []
        for t in pattern:
            if isinstance(t, str):
                parts.append(glob(t))
            else:
                ok, value = self._var_value(t)
                defined.append(ok)
                parts.append(z3.Re(value))
        regex = parts[0] if len(parts) == 1 else z3.Concat(*parts)
        return z3.And(defined) if defined else z3.BoolVal(True), regex

    def _symbolic_resource(self, pattern: Pattern) -> z3.BoolRef:
        """A Resource entry with free variables, all in the resource part (segment 6)."""
        head = pattern[0]
        assert isinstance(head, str)  # variables come only after the fifth colon
        segments = head.split(":", 5)
        prefix = ":".join(segments[:5]) + ":*"
        defined, regex = self._var_regex((segments[5], *pattern[1:]) if segments[5] else pattern[1:])
        return z3.And(self.arn.matches(prefix), defined, z3.InRe(self.arn.segments[5], regex))

    def _symbolic_condition(self, cond: SymbolicCondition, stmt: Statement) -> z3.BoolRef:
        base = cond.operator.removesuffix("IfExists")
        kind = STRING_OPS.get(base)
        if kind not in ("eq", "like") or key_kind(cond.key) != "string":
            return self.ctx.opaque(stmt, f"policy variable in {cond.operator} {cond.key}")
        present, value = self.ctx.present(cond.key), self.ctx.string(cond.key)
        terms = []
        for pattern in cond.values:
            if kind == "like":
                defined, regex = self._var_regex(pattern)
                terms.append(z3.And(defined, z3.InRe(value, regex)))
                continue
            defined_parts: list[z3.BoolRef] = []
            pieces: list[z3.SeqRef] = []
            for t in pattern:
                if isinstance(t, str):
                    pieces.append(sval(t))
                else:
                    ok, v = self._var_value(t)
                    defined_parts.append(ok)
                    pieces.append(v)
            whole = pieces[0] if len(pieces) == 1 else z3.Concat(*pieces)
            terms.append(z3.And(*defined_parts, value == whole))
        matched = z3.Or(terms) if len(terms) > 1 else terms[0]
        return wrap_presence(base, cond.operator.endswith("IfExists"), present, matched)

    def _allows(self, policies: list[Policy]) -> z3.BoolRef:
        terms = [self._statement(s) for p in policies for s in p.statements if s.effect == "Allow"]
        return z3.Or(terms) if terms else z3.BoolVal(False)

    def _rcp_scope(self, st: Statement) -> z3.BoolRef:
        """An RCP restricts only actions of the services that support RCPs, minus documented exemptions.

        AWS managed KMS keys are exempt too, but nothing in a key's ARN says whether AWS manages it: for kms
        actions the Deny is an opaque, so it can block a witness yet never makes a DENIED proof on its own.
        """
        if self.rep is not None:
            service = self.rep.split(":", 1)[0].lower()
            if service not in RCP_SERVICES or self.rep.lower() in RCP_EXEMPT_ACTIONS:
                return z3.BoolVal(False)
            if service == "kms":
                return self.ctx.opaque(st, "RCP on KMS: does not apply to AWS managed keys")
            return z3.BoolVal(True)
        # A free action string. The statement only matches actions of the services its own Action patterns
        # name (RCPs must name a service), so only those need checking: usually one, often none. A 62-way
        # disjunction over every RCP service made the fuzzer's free-action cases take 90 s.
        if st.not_actions or any(":" not in a or has_wildcard(a.split(":", 1)[0]) for a in st.actions):
            services = set(RCP_SERVICES)  # the patterns do not pin the service: check them all
        else:
            services = {a.split(":", 1)[0].lower() for a in st.actions}
        covered = sorted(services & RCP_SERVICES)
        if not covered:
            return z3.BoolVal(False)
        if len(covered) == len(services) and "kms" not in services:
            return z3.BoolVal(True)  # every action the statement matches is in scope already
        terms = []
        for svc in covered:
            term = z3.PrefixOf(sval(f"{svc}:"), self.action)
            if svc == "kms":
                exempt = z3.Or([self.action == sval(a) for a in sorted(RCP_EXEMPT_ACTIONS)])
                term = z3.And(
                    term, z3.Not(exempt), self.ctx.opaque(st, "RCP on KMS: does not apply to AWS managed keys")
                )
            terms.append(term)
        return z3.Or(terms) if len(terms) > 1 else terms[0]

    def _collect_denies(self, policy: Policy) -> None:
        for s in policy.statements:
            if s.effect == "Deny":
                self.denies.append((s, self._statement(s)))

    def pessimistic(self) -> list[z3.BoolRef]:
        return [o.var == z3.BoolVal(o.effect == "Deny") for o in self.ctx.opaques]

    def preferences(self) -> list[list[z3.BoolRef]]:
        """Witness niceties, strongest first. They only shape which example we show, never a verdict."""
        elements = [v for slots in self.ctx.sets.values() for _, v in slots]
        strings = [self.action, *self.arn.segments, *self.ctx.strings.values(), *elements]
        printable = [z3.InRe(s, PRINTABLE) for s in strings]
        arn_shaped = [self.arn.segments[0] == sval("arn"), self.arn.segments[1] == sval("aws")]
        recent = [t >= RECENT_EPOCH for t in self.ctx.times.values()]
        return [printable + arn_shaped + recent, printable, []]


def _solver() -> z3.Solver:
    s = z3.Solver()
    s.set("timeout", SOLVER_TIMEOUT_MS)
    return s


def _check(*constraints: z3.BoolRef) -> z3.CheckSatResult:
    s = _solver()
    s.add(*constraints)
    return s.check()


def _model(enc: _Encoding, *constraints: z3.BoolRef) -> tuple[z3.CheckSatResult, z3.ModelRef | None]:
    """Find a model, preferring readable witnesses (printable strings, ARN-shaped resources)."""
    s = _solver()
    s.add(*constraints)
    preferences = enc.preferences()
    for i, preference in enumerate(preferences):
        # A preference only picks a nicer example, so it gets a short budget; the last, empty one (the actual
        # question) gets the full timeout. Fuzz seed 62, case 175: the first preference ran 30 s to "unknown"
        # while the unconstrained check took 1.3 s.
        s.set("timeout", SOLVER_TIMEOUT_MS if i == len(preferences) - 1 else PREFERENCE_TIMEOUT_MS)
        s.push()
        s.add(*preference)
        result = s.check()
        if result == z3.sat:
            return result, s.model()
        s.pop()
    # The last preference is empty, so `result` is the unconstrained answer.
    return result, None


def _witness(enc: _Encoding, model: z3.ModelRef) -> Witness:
    def text(e: z3.SeqRef) -> str:
        # Read character codes rather than as_string(), which escapes
        # non-printable characters and so cannot be parsed back unambiguously.
        length = model.eval(z3.Length(e), model_completion=True).as_long()
        chars = (z3.StrToCode(z3.SubString(e, i, 1)) for i in range(length))
        codes = (model.eval(c, model_completion=True).as_long() for c in chars)
        return "".join(chr(c) for c in codes)

    def value(e: z3.ExprRef) -> int:
        return model.eval(e, model_completion=True).as_long()

    ctx = enc.ctx
    context: dict[str, ContextValue] = {}
    for k, key in ctx.keys.items():
        slot = TIME_KEYS[k][0] if key.kind == "time" else k
        if not z3.is_true(model.eval(ctx.presence[slot], model_completion=True)):
            context[key.name] = None
        elif key.kind == "set":
            members = [text(v) for a, v in ctx.sets[k] if z3.is_true(model.eval(a, model_completion=True))]
            context[key.name] = sorted(set(members))
        elif key.kind == "string":
            context[key.name] = text(ctx.strings[k])
        elif key.kind == "ip":
            is_v4, address = ctx.ips[k]
            v4 = z3.is_true(model.eval(is_v4, model_completion=True))
            context[key.name] = render_ip(v4, value(address))
        else:
            context[key.name] = render_time(value(ctx.times[slot]), TIME_KEYS[k][1])
    action = text(enc.action)
    if enc.catalog is not None:
        action = enc.catalog.canonical(action)
    return Witness(action, text(enc.resource), context)


def _explain_denial(enc: _Encoding, principal: Principal) -> list[str]:
    for g in enc.scps:
        if _check(enc.request, g.expr) == z3.unsat:
            return [f"Implicitly denied by {g.name}: it allows no matching request."]
    scps = [g.expr for g in enc.scps]
    if _check(enc.request, *scps, enc.grant) == z3.unsat:
        return _explain_grant(enc, principal, scps)

    gates = [*scps, enc.grant]
    covering = [s.label for s, e in enc.denies if _check(enc.request, *gates, z3.Not(e)) == z3.unsat]
    if covering:
        return [
            f"Explicit Deny in {label} covers every request the policies would otherwise allow." for label in covering
        ]
    involved = [s.label for s, e in enc.denies if _check(enc.request, *gates, e) == z3.sat]
    return [f"Explicit Deny statements together cover every otherwise-allowed request: {', '.join(involved)}."]


def _explain_identity(enc: _Encoding, principal: Principal, scps: list[z3.BoolRef]) -> list[str]:
    if not principal.identity_policies:
        return ["The principal has no identity-based policies."]
    if _check(enc.request, *scps, enc.identity.expr) == z3.unsat:
        return ["No identity-based policy allows any matching request."]
    blocked = [
        f"Implicitly denied by {g.name}: it allows no request the identity policies allow."
        for g in enc.caps
        if _check(enc.request, *scps, enc.identity.expr, g.expr) == z3.unsat
    ]
    if blocked:
        return blocked
    if _check(enc.request, *scps, enc.identity_path) == z3.unsat:
        return ["The identity policies, boundary and session policy each allow something, but never the same request."]
    return []


def _explain_grant(enc: _Encoding, principal: Principal, scps: list[z3.BoolRef]) -> list[str]:
    identity = _explain_identity(enc, principal, scps)
    rp = enc.rp
    if rp is None:
        return identity or ["The policy layers allow no single matching request together."]
    grants = _check(enc.request, *scps, enc.rp_any) == z3.sat
    resource = [] if grants else [f"The resource policy {rp.policy.name} grants this principal nothing matching."]
    if rp.account != principal.account:
        rule = "Cross-account access needs both an identity-based grant and a resource-policy grant."
    elif rp.required:
        rule = (
            f"{rp.policy.name} must grant the principal directly, or grant its account while an identity policy "
            "also allows it."
        )
    else:
        rule = "Neither the identity path nor a direct resource-policy grant allows it."
    return [*identity, *resource, rule]


def _needed_assumptions(enc: _Encoding, model: z3.ModelRef) -> list:
    """The unmodelled conditions this witness actually depends on.

    Start from every opaque the model set in the attacker's favour, then
    greedily pin each back to its worst case; if the witness request is
    still allowed, that assumption was not needed. Pure model evaluation,
    no extra solving.
    """
    formula = enc.allowed
    needed = []
    for o in enc.ctx.opaques:
        worst = z3.BoolVal(o.effect == "Deny")
        if z3.is_true(model.eval(o.var, model_completion=True)) == z3.is_true(worst):
            continue  # already at its worst case
        pinned = z3.substitute(formula, (o.var, worst))
        if z3.is_true(model.eval(pinned, model_completion=True)):
            formula = pinned
        else:
            needed.append(o)
    return needed


def _action_matches(stmt: Statement, action: str) -> bool:
    return any(iam_glob_regex(a).fullmatch(action) for a in stmt.actions) != stmt.not_actions


def _action_classes(
    principal: Principal, query: Query, env: Environment, catalog: Catalog | None
) -> tuple[list[str] | None, list[str]]:
    """Split the real actions matching the query into classes that every policy treats alike.

    Two actions share a class when they match exactly the same statements,
    apply to the same resource types and support the same service-specific
    condition keys: every formula Reach builds is then identical for both,
    so one representative per class decides the class. This turns a `*`
    query over ~22,000 actions from one huge string disjunction (which made
    Z3 give up) into a handful of small, concrete problems.

    Returns (representatives, notes); representatives is None when the
    action must stay a free string (no catalogue, or a literal action the
    catalogue does not know).
    """
    notes: list[str] = []
    if catalog is None:
        if has_wildcard(query.action):
            notes.append("No action catalogue loaded: witnesses may name actions that do not exist.")
        return None, notes
    candidates = catalog.matching(query.action)
    if not candidates:
        if has_wildcard(query.action):
            notes.append(f"{query.action} matches no action in the catalogue ({catalog.generated}).")
            return [], notes
        notes.append(f"{query.action} is not in the action catalogue ({catalog.generated}); evaluated as written.")
        return None, notes

    # Sound pruning: an action no Allow statement that could grant it mentions is never allowed.
    granting = list(principal.identity_policies)
    if query.resource_policy is not None:
        granting.append(query.resource_policy.policy)  # resource policies can grant on their own
    grants = [st for p in granting for st in p.statements if st.effect == "Allow"]
    kept = [a for a in candidates if any(_action_matches(st, a) for st in grants)]

    policies = list(principal.identity_policies) + list(env.session_policies)
    if principal.boundary is not None:
        policies.append(principal.boundary)
    if not env.management_account and not principal.is_service_linked:
        policies.extend(p for _, layer in env.scp_layers for p in layer)
    if query.resource_policy is not None:
        policies.append(query.resource_policy.policy)
    # RCPs deny too, and whether one applies depends on the action's service and exemptions (_rcp_scope).
    # Leaving them out merged s3:GetObject and s3:PutObject into one class, and an RCP Deny on GetObject
    # then "proved" PutObject denied (fuzz seed 13, case 133).
    rcps = env.rcps if not principal.is_service_linked else []
    policies.extend(rcps)
    statements = [st for p in policies for st in p.statements]
    keys = sorted({c.key for st in statements for c in st.conditions if not c.key.lower().startswith("aws:")})

    def rcp_scope(action: str) -> tuple[bool, ...]:
        service = action.split(":", 1)[0].lower()
        return (service in RCP_SERVICES, action.lower() in RCP_EXEMPT_ACTIONS, service == "kms") if rcps else ()

    classes: dict[tuple, str] = {}
    for action in kept:
        signature = (
            tuple(_action_matches(st, action) for st in statements),
            catalog.resource_globs(action),
            tuple(catalog.supports_key(action, k) for k in keys),
            rcp_scope(action),
        )
        classes.setdefault(signature, action.lower())
    return list(classes.values()), notes


def _units(actions: list[str | None], catalog: Catalog | None) -> list[tuple[str | None, tuple[str, ...] | None]]:
    """One solver problem per (action class, resource type).

    An action that applies to several resource types makes the resource one big disjunction of ARN patterns,
    which Z3's string solver handles erratically: ec2:RunInstances (18 resource types) on "*" took 2 to 60 s
    across runs, while each type alone takes milliseconds. Splitting is exact: the request is allowed if it
    is allowed for some type, and denied only if it is denied for every type.
    """
    units: list[tuple[str | None, tuple[str, ...] | None]] = []
    for action in actions:
        globs = catalog.resource_globs(action) if action is not None and catalog is not None else ()
        if len(globs) > 1:
            units.extend((action, (g,)) for g in globs)
        else:
            units.append((action, None))
    return units


def _explain_classes(denied: list[_Encoding], principal: Principal, query: Query) -> list[str]:
    if not denied:
        return [f"No identity-based or resource policy grants any action matching {query.action}."]
    by_action: dict[str | None, list[str]] = {}
    for enc in denied:
        reasons = by_action.setdefault(enc.rep, [])
        reasons.extend(r for r in _explain_denial(enc, principal) if r not in reasons)
    if len(by_action) == 1:
        return next(iter(by_action.values()))
    shown = 3
    out: list[str] = []
    for rep, reasons in list(by_action.items())[:shown]:
        name = denied[0].catalog.canonical(rep) if denied[0].catalog is not None and rep else rep
        out.extend(f"{name}: {r}" for r in reasons)
    if len(by_action) > shown:
        out.append(f"... and {len(by_action) - shown} more action groups, each also proven denied.")
    return out


_BUNDLED = object()


def decide(
    principal: Principal,
    query: Query,
    env: Environment | None = None,
    catalog: Catalog | None | object = _BUNDLED,
) -> Result:
    """Decide a query.

    `catalog` defaults to the bundled action catalogue; pass None to treat actions as free strings.
    """
    cat = bundled() if catalog is _BUNDLED else catalog
    assert cat is None or isinstance(cat, Catalog)
    env = env or Environment()
    reps, notes = _action_classes(principal, query, env, cat)
    result = Result(Verdict.UNKNOWN, principal.arn, query, notes=list(notes))
    actions: list[str | None] = list(reps) if reps is not None else [None]

    pending = None  # first class that is allowed only under assumptions
    gave_up = False
    denied: list[_Encoding] = []
    for action, types in _units(actions, cat):
        enc = _Encoding(principal, query, env, cat, action, types)
        result.notes.extend(n for n in enc.notes if n not in result.notes)
        optimistic, opt_model = _model(enc, enc.allowed)
        if optimistic == z3.unsat:
            denied.append(enc)
            continue
        if optimistic == z3.unknown or opt_model is None:
            gave_up = True
            continue
        proven, model = _model(enc, enc.allowed, *enc.pessimistic())
        if proven == z3.sat and model is not None:
            result.verdict = Verdict.ALLOWED
            result.witness = _witness(enc, model)
            break
        if pending is None:
            pending = (enc, opt_model, proven)

    if result.verdict is not Verdict.ALLOWED:
        if pending is not None:
            enc, opt_model, proven = pending
            result.witness = _witness(enc, opt_model)
            for o in _needed_assumptions(enc, opt_model):
                if o.effect == "Allow":
                    result.assumptions.append(f"assumes the Allow condition holds: {o.reason} ({o.statement})")
                else:
                    result.assumptions.append(f"assumes the Deny condition does not apply: {o.reason} ({o.statement})")
            if proven == z3.unknown:
                result.reasons = ["Allowed in some context, but the solver gave up proving it for the worst case."]
            else:
                result.reasons = ["Allowed only if conditions Reach does not model yet go the attacker's way."]
        elif gave_up:
            result.reasons = ["The solver timed out or gave up on this query."]
        else:
            result.verdict = Verdict.DENIED
            result.reasons = _explain_classes(denied, principal, query)

    if result.witness is not None:
        _self_check(principal, query, env, result)
        _tidy(principal, query, env, result)

    if principal.unresolved and result.verdict is not Verdict.UNKNOWN:
        result.reasons.append(
            f"Downgraded from {result.verdict.value}: attached policies could not be loaded: "
            + ", ".join(principal.unresolved)
        )
        result.verdict = Verdict.UNKNOWN
    return result


def _self_check(principal: Principal, query: Query, env: Environment, result: Result) -> None:
    """Replay the witness through the solver-free reference evaluator.

    An ALLOWED witness must be allowed outright; an UNKNOWN one must at
    least not be denied outright. Anything else means the Z3 encoding and
    the reference implementation disagree, and no verdict should be trusted.
    """
    from .reference import evaluate  # noqa: PLC0415 - deferred: reference.py imports this module

    w = result.witness
    assert w is not None
    concrete = evaluate(principal, w.action, w.resource, {**query.context, **w.context}, env, query.resource_policy)
    consistent = concrete is True if result.verdict is Verdict.ALLOWED else concrete is not False
    if not consistent:
        raise InconsistencyError(
            f"witness {w.action} on {w.resource!r} with context {w.context} was {result.verdict.value} by the solver "
            f"but evaluates to {concrete} in the reference evaluator; please report this as a Reach bug"
        )


_REGION = re.compile(r"[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-[0-9]")
_ACCOUNT = re.compile(r"[0-9]{12}")
_SERVICE = re.compile(r"[a-z0-9-]+")
_UNNAMED = re.compile(r"[^A-Za-z0-9/._:*-]+")


def _tidy(principal: Principal, query: Query, env: Environment, result: Result) -> None:
    """Make a checked witness's ARN read like one a person would write.

    Z3 fills a resource name it does not care about with the shortest string it finds, often " ", which gives
    witnesses like 'arn:aws:secretsmanager: : :secret: '. Asking the solver for realistic names instead made
    whole audits many times slower, so names are tidied here: each rewrite (the action's service, a real
    region, the principal's account, "example" for unnamed parts) is kept only if the reference evaluator
    still gives the same answer, so the witness stays exactly as checked.
    """
    from .reference import evaluate  # noqa: PLC0415 - deferred: reference.py imports this module

    w = result.witness
    assert w is not None
    parts = w.resource.split(":", 5)
    if len(parts) < 6:
        return
    context = {**query.context, **w.context}

    def answer(resource: str) -> object:
        return evaluate(principal, w.action, resource, context, env, query.resource_policy)

    target = answer(w.resource)
    edits: list[tuple[int, str]] = []
    if not _SERVICE.fullmatch(parts[2]) and ":" in w.action:
        edits.append((2, w.action.split(":", 1)[0].lower()))
    if parts[3] and not _REGION.fullmatch(parts[3]):
        edits.append((3, WITNESS_REGION))
    if parts[4] and not _ACCOUNT.fullmatch(parts[4]):
        edits.append((4, principal.account or WITNESS_ACCOUNT))
    rest = _UNNAMED.sub("example", parts[5])
    if rest.endswith(("/", "-", ":", "_", ".")):
        rest += "example"  # 'secret:app/search/' matched 'app/search/*' with nothing after the slash
    if rest != parts[5]:
        edits.append((5, rest))
    for index, value in edits:
        candidate = [*parts[:index], value, *parts[index + 1 :]]
        if answer(":".join(candidate)) == target:
            parts = candidate
    result.witness = replace(w, resource=":".join(parts))
