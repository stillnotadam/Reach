from __future__ import annotations

import pytest

from validation.fuzz import run


# A quick slice of the differential fuzzer; run `python -m validation.fuzz --cases N` for long campaigns.
@pytest.mark.parametrize("seed", range(4))
def test_engine_agrees_with_reference_evaluator(seed):
    failures = run(cases=60, seed=seed)
    assert not failures, "\n".join(failures[:5])
