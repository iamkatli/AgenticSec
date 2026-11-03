"""
Experiment matrix for the controlled-placement study, defined as data,
separate from runner logic. This file is the single source of truth for
group definitions -- nothing else in the codebase hard-codes group
parameters. Defining a group here does not mean it has to be run; the
runner only runs the groups named on the command line.

ELEMENTS (always concatenated in this order):
  Processor stage:  A2 = Agent2 backstory,  T2 = Task2 description
  Executor stage:   A3 = Agent3 backstory,  T3 = Task3 description,
                    TL = Tool description

POLICY ASSIGNMENT (suffix after the elements):
  DS -- every hardened element gets the data-instruction separation block
  LP -- every hardened element gets the least-privilege execution block
  MX -- matched: Processor elements get DS, Executor elements get LP.
        Only defined for element sets that span both stages (for a
        single-stage set MX would equal DS or LP).
  A hardened element = its neutral text + one policy block (prompts.py).

CONTEXT (final suffix):
  -LK  = leaked:   Task3 context = [task1, task2]
  -ISO = isolated: Task3 context = [task2]

KEY FORMAT:  <elements>_<DS|LP|MX>-<LK|ISO>, e.g. A3T3TL_LP-ISO.
Special groups:
  BASE-LK/ISO      nothing hardened
  BASE_MIN-LK/ISO  nothing hardened, tool description replaced by the
                   "minimal" wording (sensitivity check on the baseline)
  ZERO-LK/ISO      nothing hardened, no attack: reads data_zero/ and is
                   scored against the clean ground truth (config.SCENARIOS)

MATRIX: every non-empty subset of the 5 elements (31) x its policy
assignments (DS, LP, plus MX for the 21 cross-stage subsets = 83) x 2
contexts = 166 groups, plus BASE, BASE_MIN and ZERO (6) = 172 groups.

CLI selection (resolve_group_keys): a full key ("A3_LP-ISO"), a family
= key without the context suffix ("A3_LP" -> A3_LP-LK, A3_LP-ISO), a
comma-separated mix of these, or "all".
"""

import itertools
from dataclasses import dataclass, field
from typing import Dict, List

PROCESSOR_ELEMENTS = ("A2", "T2")
EXECUTOR_ELEMENTS = ("A3", "T3", "TL")
ELEMENT_ORDER = PROCESSOR_ELEMENTS + EXECUTOR_ELEMENTS

_ELEMENT_FIELD = {
    "A2": "agent2_backstory",
    "T2": "task2_description",
    "A3": "agent3_backstory",
    "T3": "task3_description",
    "TL": "tool_description",
}

_CONTEXT_LISTS = {
    "LK": ["task1", "task2"],
    "ISO": ["task2"],
}
CONTEXTS = ("LK", "ISO")


@dataclass
class ExperimentGroup:
    key: str                  # canonical CLI-facing id, e.g. "A3T3TL_LP-LK"
    name: str                 # used in logs/reports (== key)
    agent2_backstory: str     # "neutral" | "ds" | "lp"
    task2_description: str    # "neutral" | "ds" | "lp"
    agent3_backstory: str     # "neutral" | "ds" | "lp"
    task3_description: str    # "neutral" | "ds" | "lp"
    tool_description: str     # "neutral" | "ds" | "lp" | "minimal"
    task3_context: List[str] = field(default_factory=lambda: ["task1", "task2"])
    payload: str = "injected"  # "injected" | "clean" (ZERO only) -- selects config.SCENARIOS


def _variant(element: str, policy: str) -> str:
    if policy == "DS":
        return "ds"
    if policy == "LP":
        return "lp"
    if policy == "MX":
        return "ds" if element in PROCESSOR_ELEMENTS else "lp"
    raise ValueError(f"unknown policy suffix {policy!r}")


def _policies_for(elements) -> List[str]:
    spans_both = any(e in PROCESSOR_ELEMENTS for e in elements) and any(
        e in EXECUTOR_ELEMENTS for e in elements
    )
    return ["DS", "LP", "MX"] if spans_both else ["DS", "LP"]


GROUPS: Dict[str, ExperimentGroup] = {}


def _add(prefix, elements=(), policy=None, ctx="LK", payload="injected", tool_override=None):
    fields = {f: "neutral" for f in _ELEMENT_FIELD.values()}
    for el in elements:
        fields[_ELEMENT_FIELD[el]] = _variant(el, policy)
    if tool_override:
        fields["tool_description"] = tool_override
    key = f"{prefix}-{ctx}"
    assert key not in GROUPS, f"duplicate group key {key}"
    GROUPS[key] = ExperimentGroup(
        key=key, name=key, task3_context=_CONTEXT_LISTS[ctx], payload=payload, **fields,
    )


for ctx in CONTEXTS:
    _add("BASE", ctx=ctx)

for r in range(1, len(ELEMENT_ORDER) + 1):
    for elements in itertools.combinations(ELEMENT_ORDER, r):
        for policy in _policies_for(elements):
            for ctx in CONTEXTS:
                _add(f"{''.join(elements)}_{policy}", elements, policy, ctx)

for ctx in CONTEXTS:
    _add("BASE_MIN", ctx=ctx, tool_override="minimal")

for ctx in CONTEXTS:
    _add("ZERO", ctx=ctx, payload="clean")

assert len(GROUPS) == 172, f"expected 172 groups, got {len(GROUPS)}"

_FAMILY_MAP: Dict[str, List[str]] = {}
for _k in GROUPS:
    _FAMILY_MAP.setdefault(_k.rsplit("-", 1)[0], []).append(_k)
FAMILIES: List[str] = list(_FAMILY_MAP.keys())


def resolve_group_keys(raw: str) -> List[str]:
    """
    Parses a CLI argument into a list of canonical group keys.

    Accepts (comma-separated, case-insensitive):
      - a full key, e.g. "A3T3TL_LP-ISO"
      - a family, e.g. "A3_LP" -> ["A3_LP-LK", "A3_LP-ISO"]
      - "all" -> every group

    Raises ValueError naming the bad token, rather than silently running
    fewer groups than asked for.
    """
    keys: List[str] = []
    for token in raw.split(","):
        token = token.strip().upper()
        if not token:
            continue
        if token == "ALL":
            keys.extend(GROUPS.keys())
        elif token in GROUPS:
            keys.append(token)
        elif token in _FAMILY_MAP:
            keys.extend(_FAMILY_MAP[token])
        else:
            raise ValueError(
                f"Unknown group '{token}'. Use a full key (e.g. A3_LP-ISO), "
                f"a family (e.g. A3_LP), or 'all'. Families: {', '.join(FAMILIES)}"
            )
    if not keys:
        raise ValueError("No groups specified.")
    return list(dict.fromkeys(keys))
