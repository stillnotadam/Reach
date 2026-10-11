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
  still capped by boundary and session policy). Whether a grant to the
  account principal also suffices on its own is unsettled: AWS's policy
  simulator says yes, while delegation is documented for KMS and
  cross-account access. Until a live test settles it, such a grant gives
  UNKNOWN rather than a verdict either way.
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

from dataclasses import dataclass, field
from enum import Enum

import z3

from .catalog import Catalog, bundled, iam_glob_regex
from .conditions import Context, encode_conditions
from .patterns import PRINTABLE, ArnVar, has_wildcard, matches_any, sval
from .policy import Policy, Statement
from .principals import Match, classify
from .values import IPV6_WITNESS, TIME_KEYS, principal_type, render_ipv4, render_time

SOLVER_TIMEOUT_MS = 30_000
RECENT_EPOCH = 1_577_836_800  # 2020-01-01: witnesses prefer plausible clock values
ACCOUNT_GRANT_REASON = (
    "a same-account grant to the account principal allows without identity permissions (AWS's "
    "policy simulator says so; not yet confirmed on a live service)"
)


class InconsistencyError(RuntimeError):
    """The solver and the reference evaluator disagree about a witness. Always a Reach bug."""


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
    context: dict[str, str | None] = field(default_factory=dict)
    resource_policy: ResourcePolicy | None = None


@dataclass
class Witness:
    action: str
    resource: str
    context: dict[str, str | None]  # None = key absent from the request


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


class _Encoding:
    """All symbolic pieces of one query, built once and reused by every solver call."""

    def __init__(
        self, principal: Principal, query: Query, env: Environment, catalog: Catalog | None, action: str | None
    ):
        fixed: dict[str, str | None] = {
            "aws:PrincipalArn": principal.arn,
            "aws:PrincipalAccount": principal.account,
            "aws:PrincipalType": principal_type(principal.arn),
        }
        fixed.update({f"aws:PrincipalTag/{k}": v for k, v in principal.tags.items()})
        fixed.update(query.context)
        self.ctx = Context(fixed, closed_prefixes=("aws:PrincipalTag/",))
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
            globs = catalog.resource_globs(action) if catalog is not None else ()
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
        if not by_kind[Match.ACCOUNT]:
            return z3.Or(self.identity_path, direct)
        unsettled = self.ctx.assumption("Allow", ACCOUNT_GRANT_REASON, rp.policy.name)
        return z3.Or(self.identity_path, direct, z3.And(anyof(Match.ACCOUNT), unsettled))

    def _key_support(self) -> list[z3.BoolRef]:
        """Service-specific keys exist only on actions that support them (FINDINGS.md, finding 3)."""
        if self.rep is None or self.catalog is None:
            return []
        return [
            z3.Not(self.ctx.presence[k])
            for k, key in self.ctx.keys.items()
            if not k.startswith("aws:") and key.kind == "string" and not self.catalog.supports_key(self.rep, key.name)
        ]

    def _statement(self, stmt: Statement) -> z3.BoolRef:
        if self.rep is not None:
            if not _action_matches(stmt, self.rep):
                return z3.BoolVal(False)
            action: z3.BoolRef = z3.BoolVal(True)
        else:
            action = matches_any(self.action, tuple(a.lower() for a in stmt.actions), arn=False)
            if stmt.not_actions:
                action = z3.Not(action)
        resource = self.arn.matches_any(stmt.resources)
        if stmt.not_resources:
            resource = z3.Not(resource)
        return z3.And(action, resource, encode_conditions(stmt, self.ctx))

    def _allows(self, policies: list[Policy]) -> z3.BoolRef:
        terms = [self._statement(s) for p in policies for s in p.statements if s.effect == "Allow"]
        return z3.Or(terms) if terms else z3.BoolVal(False)

    def _collect_denies(self, policy: Policy) -> None:
        for s in policy.statements:
            if s.effect == "Deny":
                self.denies.append((s, self._statement(s)))

    def pessimistic(self) -> list[z3.BoolRef]:
        return [o.var == z3.BoolVal(o.effect == "Deny") for o in self.ctx.opaques]

    def preferences(self) -> list[list[z3.BoolRef]]:
        """Witness niceties, strongest first. They only shape which example we show, never a verdict."""
        strings = [self.action, *self.arn.segments, *self.ctx.strings.values()]
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
    for preference in enc.preferences():
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
    context: dict[str, str | None] = {}
    for k, key in ctx.keys.items():
        slot = TIME_KEYS[k][0] if key.kind == "time" else k
        if not z3.is_true(model.eval(ctx.presence[slot], model_completion=True)):
            context[key.name] = None
        elif key.kind == "string":
            context[key.name] = text(ctx.strings[k])
        elif key.kind == "ip":
            is_v4, address = ctx.ips[k]
            v4 = z3.is_true(model.eval(is_v4, model_completion=True))
            context[key.name] = render_ipv4(value(address)) if v4 else IPV6_WITNESS
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
    statements = [st for p in policies for st in p.statements]
    keys = sorted({c.key for st in statements for c in st.conditions if not c.key.lower().startswith("aws:")})

    classes: dict[tuple, str] = {}
    for action in kept:
        signature = (
            tuple(_action_matches(st, action) for st in statements),
            catalog.resource_globs(action),
            tuple(catalog.supports_key(action, k) for k in keys),
        )
        classes.setdefault(signature, action.lower())
    return list(classes.values()), notes


def _explain_classes(denied: list[_Encoding], principal: Principal, query: Query) -> list[str]:
    if not denied:
        return [f"No identity-based or resource policy grants any action matching {query.action}."]
    if len(denied) == 1:
        return _explain_denial(denied[0], principal)
    shown = 3
    reasons = []
    for enc in denied[:shown]:
        name = enc.catalog.canonical(enc.rep) if enc.catalog is not None and enc.rep else enc.rep
        reasons.extend(f"{name}: {r}" for r in _explain_denial(enc, principal))
    if len(denied) > shown:
        reasons.append(f"... and {len(denied) - shown} more action groups, each also proven denied.")
    return reasons


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
    for action in actions:
        enc = _Encoding(principal, query, env, cat, action)
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
