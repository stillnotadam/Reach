# Findings from differential testing against AWS

Reach is compared against AWS's IAM policy simulator (`iam:SimulateCustomPolicy`) with
`validation/aws_simulator.py`. Findings 1 to 4 came from disagreements between Reach and AWS; finding 5 was found by
hand and then checked against AWS. Each one is either a Reach bug that is now fixed and covered by a test, a documented limitation, or a quirk of the simulator itself.

## Reach bugs (fixed)

### 1. `aws:RequestedRegion` is never absent

- **Found:** seed 1, case 195. Reach said DENIED, AWS said allowed.
- **Cause:** Reach treated `aws:RequestedRegion` as an optional key. A Deny with `StringLikeIfExists` on it therefore
  applied to a request with no region, but no such request exists. Every request goes to a region, and the simulator
  fills in its endpoint region (`us-east-1`).
- **Probe:** with the key not supplied, `Null: {"aws:RequestedRegion": "false"}` fires in the simulator, so the key is
  present. The same probe shows `aws:PrincipalType`, `aws:userid` and `aws:ResourceAccount` are always present too.
- **Fix:** these keys are always present in Reach's model, and `aws:PrincipalType` is pinned from the principal
  (`User` / `AssumedRole`). Tests: `test_requested_region_is_never_absent`,
  `test_if_exists_deny_on_region_cannot_use_a_regionless_request`, `test_principal_type_is_pinned`.

### 5. Policy variables in `Resource` were literal text

- **Found:** by hand, writing `"Resource": "arn:aws:s3:::corp/home/${aws:username}/*"` for user `alice`. Reach proved
  `s3:GetObject` on `corp/home/alice/x` DENIED, which AWS allows. Its witness for `corp/home/*` contained the text
  `${aws:username}`. The differential fuzzer had never put a variable in a `Resource` element, and conditions with
  variables were already reported UNKNOWN, so nothing caught it.
- **Severity:** a false DENIED proof is the worst error Reach can make: it claims something is impossible.
- **Fix:** variables are resolved per statement by one module shared by the engine and the reference evaluator,
  following the IAM User Guide: only under `Version: 2012-10-17`; null keys make an entry match nothing (negated
  operators match); `${key, 'default'}`; `${*}`, `${?}`, `${$}` as literal characters. Known values (`aws:username`,
  principal tags, pinned keys) are substituted as text. A key the request decides is substituted symbolically, with
  the key's own solver variable inside a Z3 regular expression, so the verdict stays exact. Variables AWS does not
  substitute (before the fifth colon of an ARN, over IP, time or multi-valued keys, in ARN operators) stay UNKNOWN.
- **Checked:** the fuzzer now generates variables in 31% of statements (with and without `Version`); 4,000 cases,
  0 failures. Against the simulator: 652 compared cases, 378 of them with variables, 0 disagreements.
  Tests: `test_username_variable_scopes_a_user_to_their_own_prefix` and the other policy-variable tests in
  `tests/test_engine.py`.

### 6. `Bool` reads both sides as booleans, for every key

- **Found:** seed 23, case 194, the first run after set operators were added. Reach said DENIED, AWS said allowed:
  `Bool: {"aws:MultiFactorAuthPresent": "false"}` against a request value of `other`.
- **Probe:** 92 direct simulator calls, over `aws:MultiFactorAuthPresent`, `aws:SecureTransport`, `aws:SourceVpc` and
  `s3:prefix`, with string- and boolean-typed context entries. The rule is uniform: a value is true exactly when it is
  `true` in any letter case; anything else (`other`, `1`, the empty string) is false; then the two booleans are
  compared. A policy value of `yes` is false. A first probe on `s3:prefix` with `s3:GetObject` denied everything,
  because that action does not support the key (finding 3); with `s3:ListBucket` it follows the same rule.
- **Cause:** Reach compared lowercase strings, and it restricted any key used under `Bool` to exactly `true` or
  `false` everywhere in the query. For a non-boolean key that restriction is wrong: an Allow with
  `Bool: {"s3:prefix": "false"}` and `StringLike: {"s3:prefix": "home/*"}` was proved DENIED, but AWS allows
  `s3:prefix = home/x`.
- **Fix:** both evaluators read both sides as booleans (`parse_bool`); only the real boolean global keys keep the
  `true`/`false` domain. Tests: `test_bool_reads_any_case_true_and_treats_everything_else_as_false`,
  `test_bool_on_a_non_boolean_key_does_not_shrink_its_values` (both fail on the previous release).

### 7. IP conditions: IPv6, mixed families and malformed values, measured

- **Before:** Reach modelled IPv4 only. Any IPv6 network made the whole condition UNKNOWN.
- **Probe:** `validation/ip_probe.py`, 684 simulator calls: four operators, 19 network lists, nine sources (IPv4,
  IPv6 in several spellings, IPv4-mapped, IPv4-compatible, absent). What AWS does:
  - the families never mix: `0.0.0.0/0` matches no IPv6 source, `::/0` no IPv4 source, and `10.0.0.0/8` does not
    match `::a00:1`, the IPv6 address with the same number;
  - an IPv4-mapped source (`::ffff:10.1.2.3`) is the IPv4 address it carries: it matches `10.0.0.0/8`, not `::/0`;
  - a network value AWS cannot parse (`bogus`, `10.0.0.0/33`, a leading space, `::ffff:10.0.0.0/104`) makes the
    condition false for `IpAddress` and `NotIpAddress` alike once the key is present, unless a valid network earlier in
    the list already matched. With the key absent, the values are never read: `IpAddress` is false, `NotIpAddress` and
    the `IfExists` forms are true;
  - spellings are free: `2001:DB8:0:0:0:0:0:0/32` is `2001:db8::/32`, host bits are ignored (`10.1.2.3/8`), and a
    zero-padded prefix (`/08`) is accepted.
- **Model:** one 128-bit vector and an "is IPv4" flag (IPv4 in the low 32 bits), so CIDR matching is exact masking
  for both families. A free IPv6 source is never IPv4-mapped. A malformed or IPv4-mapped network is decided exactly
  for an absent key and is UNKNOWN for a present one.
- **Caught on the way:** a first version stripped whitespace from network values; the probe showed AWS rejects
  `" 10.0.0.0/8"`, so a Deny on it would have been read as matching. Removed before release.
- **Result:** 460 cases decided by Reach and compared, 0 disagreements. Tests: `test_ipv6_conditions`,
  `test_ip_families_never_mix`, `test_malformed_networks_decide_an_absent_key_exactly`.

### 8. `StringEqualsIgnoreCase` compares full Unicode lowercase forms

- **Before:** not modelled; every case-insensitive condition was UNKNOWN.
- **The trap:** "ignore case" has several meanings. ASCII-only folding misses `É`/`é`. Java's `equalsIgnoreCase`
  also matches long s with `s` and dotless i with `i`. A model that matches too little can prove DENIED a request
  AWS allows; one that matches too much can do the opposite on a Deny.
- **Probe:** `validation/case_probe.py`, 42 simulator calls over pairs chosen to separate the candidates. AWS
  matches `K` (Kelvin sign) with `k`, `ẞ` with `ß`, `É` with `é`; it does not match long s with `s`, dotless or dotted
  I with `i`, the micro sign with Greek mu, or `ß` with `SS`. That is exactly "the full Unicode lowercase forms are
  equal", and rules out both ASCII folding and Java's rule. A side result: IAM rejects any policy containing text
  outside Latin-1 (`ValidationError`), so a policy value is always Latin-1.
- **Model:** each character of the policy value's lowercase becomes the set of characters whose lowercase it is:
  Latin-1 itself plus four others (Kelvin sign, Angstrom sign, capital sharp s, `Ÿ`); `tests/test_reference_data.py`
  checks that list against the whole Unicode table. A value outside Latin-1 is not modelled. Also under
  `ForAnyValue`/`ForAllValues`.
- **Result:** 42 compared, 0 disagreements. Tests: `test_string_equals_ignore_case_compares_lowercase_forms`,
  `test_ignore_case_denies_are_proofs_over_every_spelling`, `test_ignore_case_set_operator_and_text_iam_rejects`.

### 9. Numeric operators read BigDecimal syntax and compare exactly

- **Before:** only non-negative integers were modelled; a decimal or signed value made the condition UNKNOWN.
- **Probe:** `validation/num_probe.py`, 2,090 simulator calls (plus 70 exploratory ones): five operators, 19
  policy value lists, 22 request values. What AWS does:
  - numbers follow Java's BigDecimal syntax: a sign, a leading or trailing point (`.5`, `5.`), an exponent
    (`1e1`, `1E-1`, `1e+1`) and leading zeros (`007`) are fine; whitespace, hex (`0x10`, `0x1p3`), `1d`,
    `Infinity`, `NaN`, `1_000` and `1,000` are not;
  - comparison is exact, not floating point: `9007199254740993` is not `9007199254740992`, and
    `0.10000000000000000001` is greater than `0.1`;
  - a request value may use any Unicode decimal digit (`١٠` equals `10`); IAM rejects such text in a policy;
  - an invalid request value makes every Numeric operator false, `NumericNotEquals` and the `IfExists` forms
    included; an invalid policy value just never matches (`["abc", "10"]` still matches `10`, and
    `NumericNotEquals: "abc"` is true for any valid number); an absent key behaves as for any operator.
- **Model:** a request value that is a plain decimal (`-12.50`) is decided exactly: it is split into sign, whole
  and fraction digits and read on the grid of the policy bounds' decimal places, with a flag for digits cut off
  below it, so every comparison is linear integer arithmetic. Other spellings that may be valid (`+5`, `1e1`,
  non-ASCII digits) are UNKNOWN in both evaluators; anything else is invalid and decided as false.
- **Found on the way:** the fuzzer gave `aws:MultiFactorAuthPresent` the value `other`, which AWS never sends and
  Reach's proofs rightly exclude (seed 72, case 424). The fuzzer now keeps boolean keys to `true`/`false`.
- **Result:** 1,615 cases decided by Reach and compared, 0 disagreements. Tests: `test_numbers_are_exact_decimals`,
  `test_free_decimal_and_negative_witnesses`, `test_invalid_numbers_make_every_numeric_operator_false`.

## Modelling gaps (fixed with AWS's Service Authorization Reference)

### 2. Actions apply only to their own resource types

- **Found:** seed 1, smoke run. `s3:PutObject` on an IAM role ARN, and `iam:CreateUser` on a role ARN.
- **AWS behaviour:** the simulator implicitly denies an action on a resource type the action does not use, even under
  `Allow *`, with zero matched statements.
- **Impact on Reach:** DENIED proofs stay sound, because Reach searches a superset of real requests. An ALLOWED witness,
  though, could pair an action with an impossible resource.
- **Fix:** Reach bundles AWS's Service Authorization Reference (22,080 actions, 456 services). Each action applies only
  to its documented resource types. Test: `test_action_on_wrong_resource_type_cannot_happen`.

### 3. Service-specific condition keys exist only for the actions that support them

- **Found:** seed 1, case 29. `s3:max-keys` was pinned on an `s3:GetObject` request.
- **AWS behaviour:** AWS drops the key, so an `IfExists` condition on it passes.
- **Fix:** a service-specific key is absent on any action the reference does not list it for, and documented key
  placeholders (`${TagKey}`, `<key>`) match by prefix, so the data can only widen the model. Test:
  `test_service_key_only_on_supporting_actions`.

## AWS's policy simulator vs live AWS

### 4. Same-account grants to the account principal: the simulator is wrong

- **Found:** seed 2. All 7 disagreements in 1,157 compared cases. Reach said DENIED, the simulator said allowed.
- **What happened:** in every case the only grant was a same-account resource policy naming the *account*
  (`"123456789012"` or `arn:aws:iam::123456789012:root`), with no identity policy allowing the action. Reach applied
  delegation: an account grant needs identity permissions too.
- **Live test** (`validation/live_account_grant.py`): one real S3 bucket, read by an IAM user with no permissions of its
  own. The bucket was deleted afterwards.

  | Case | Bucket policy | Live S3 |
  |------|---------------|---------|
  | A (control) | none | denied |
  | **B** | grants `s3:GetObject` to `arn:aws:iam::ACCOUNT:root` | **denied** |
  | C (control) | grants `s3:GetObject` to the user's ARN | allowed |

  Both controls behaved as expected, and two independent runs gave identical results. S3's denial reason for B: *"no identity-based policy allows the s3:GetObject
  action"*.
- **Conclusion:** on live S3 an account-principal grant only delegates, as Reach modelled it. **AWS's own IAM policy
  simulator gets this wrong.** Reach keeps the delegation rule, and the simulator harness skips these cases with a
  named reason instead of counting a known simulator error as agreement or disagreement. Test:
  `test_account_grant_only_delegates`.
- **Scope:** verified live for S3. Other services' resource policies follow the same documented IAM rule, but have not
  been tested live.
- **Lesson for the methodology:** the first live run's controls failed too. The test sampled for only ~12 seconds, and
  the bucket policy was not live yet. It now waits 60 seconds after every policy change. A test whose controls fail
  says nothing about the case under study.

## Simulator quirks (not Reach bugs)

- **Missing keys:** keys a policy mentions but the request does not carry are reported as `MissingContextValues`. In
  hundreds of compared cases the simulator's decision matched treating them as absent, which is how Reach and AWS
  model them.
- **`aws:CurrentTime`:** the simulator leaves it absent when not supplied. Real AWS always sets it, and Reach models it
  as always present. The harness always supplies it.
- **Input validation:** resource policies whose `Resource` is not a full ARN (`*`, `arn:aws:s3*`) are rejected as
  invalid input.
- **Limits of the simulator:** it cannot evaluate SCPs, session policies, required resource policies (trust, KMS), or
  resource policies with a role caller. Those parts of Reach are covered by the reference-evaluator fuzzer only.

## Runs

| Seed | Cases | Compared | Disagreements | Notes |
|------|-------|----------|---------------|-------|
| 1 | 500 | 281 | 0 | after finding 1 was fixed |
| 2 | 2000 | 1157 | 7 | all finding 4 (account-principal grants) |
| 2 | 2000 | 1150 | 0 | interim: account-principal grants reported UNKNOWN (AWS: 21 allowed, 28 denied) |
| 3 | 1000 | 567 | 0 | with the bundled reference data; 18 UNKNOWN (AWS: 6 allowed, 12 denied) |
| 2 | 2000 | 1104 | 0 | delegation restored after the live test; 78 account-principal cases skipped (finding 4) |
| 11, 12, 13 | 400 each | 652 | 0 | policy variables (finding 5): 378 compared cases use them |
| 21, 22, 23 | 400 each | 682 | 1, then 0 | set operators (268 cases): finding 6, then 0 after the fix |
| 24 | 2000 | 1089 | 0 | 394 cases with set operators, 630 with policy variables |
| ip_probe | 684 | 460 | 0 | finding 7: IPv6, mixed families, mapped sources, malformed networks |
| case_probe | 42 | 42 | 0 | finding 8: StringEqualsIgnoreCase and its Unicode edge cases |
| 51 | 600 | 320 | 0 | random cases with IPv6 networks and sources, malformed networks |
| num_probe | 2090 | 1615 | 0 | finding 9: decimals, signs, exponents, precision, invalid values |
| 81 | 500 | 282 | 0 | random cases with decimal, signed, exponent and invalid numbers |
