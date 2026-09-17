"""Locate and rewrite eligible strings inside a nested JSON payload.

Two passes rather than one recursive transform: collect the paths of every
eligible string, rewrite the values (in parallel — Skyflow is a network call and
a tool payload often has several fields), then write them back. That keeps the
Skyflow round trips off the critical path of the walk and makes the number of
API calls obvious at the call site.
"""

from __future__ import annotations

import copy
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from policy import Scope

logger = logging.getLogger(__name__)

Path = tuple[Any, ...]
MAX_PARALLEL_CALLS = 8


def collect_strings(node: Any, scope: Scope) -> list[tuple[Path, str]]:
    """Return (path, value) for every string eligible under `scope`.

    A string is eligible when the nearest enclosing dict key is in scope and the
    value meets the minimum length. Strings inside a list inherit the key of the
    list itself, so `{"tags": ["..."]}` is governed by the `tags` key.
    """
    found: list[tuple[Path, str]] = []
    _walk(node, scope, (), found, None)
    return found


def _walk(node: Any, scope: Scope, path: Path, out: list[tuple[Path, str]], key: str | None) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, scope, path + (k,), out, k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, scope, path + (i,), out, key)
    elif isinstance(node, str):
        if key is not None and scope.key_in_scope(key) and scope.value_eligible(node):
            out.append((path, node))


def set_path(root: Any, path: Path, value: Any) -> None:
    """Assign `value` at `path` within `root`, mutating in place."""
    target = root
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value


def transform_strings(
    node: Any,
    scope: Scope,
    transform: Callable[[str], str],
    skip_paths: tuple = (),
) -> tuple[Any, int]:
    """Return a copy of `node` with every eligible string passed through `transform`.

    Returns (transformed_node, count). A count of zero means nothing matched and
    the copy is identical to the input.

    Any exception raised by `transform` propagates — the caller decides whether
    that means fail-closed or fail-open.
    """
    targets = collect_strings(node, scope)
    if skip_paths:
        # A skipped path holds a value that must survive verbatim — a freshly
        # issued file URL, say, which tokenizing would turn into a dead link.
        skipped = set(skip_paths)
        targets = [(path, value) for path, value in targets if path not in skipped]
    if not targets:
        return node, 0

    result = copy.deepcopy(node)

    if len(targets) == 1:
        path, value = targets[0]
        set_path(result, path, transform(value))
        return result, 1

    workers = min(len(targets), MAX_PARALLEL_CALLS)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # list() forces every future to resolve here, so exceptions surface
        # inside this call rather than when a value is later read.
        rewritten = list(pool.map(transform, [value for _, value in targets]))

    for (path, _), new_value in zip(targets, rewritten):
        set_path(result, path, new_value)

    return result, len(targets)
