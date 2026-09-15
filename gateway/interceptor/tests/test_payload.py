"""Payload traversal: which strings are found, and how they are written back."""

from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import payload as payload_utils  # noqa: E402
from policy import Scope  # noqa: E402

WIDE_OPEN = Scope(min_length=1)


def upper(text: str) -> str:
    return text.upper()


class CollectStringsTestCase(unittest.TestCase):
    def test_finds_top_level_values(self):
        found = payload_utils.collect_strings({"a": "hello there", "b": "world wide"}, WIDE_OPEN)
        self.assertEqual({path for path, _ in found}, {("a",), ("b",)})

    def test_recurses_into_nested_dicts(self):
        node = {"outer": {"inner": {"deep": "value here"}}}
        found = payload_utils.collect_strings(node, WIDE_OPEN)
        self.assertEqual(found, [(("outer", "inner", "deep"), "value here")])

    def test_strings_in_a_list_inherit_the_list_key(self):
        node = {"tags": ["alpha", "beta"]}
        found = payload_utils.collect_strings(node, WIDE_OPEN)
        self.assertEqual([p for p, _ in found], [("tags", 0), ("tags", 1)])

    def test_list_of_objects(self):
        node = {"content": [{"type": "text", "text": "first"}, {"type": "text", "text": "second"}]}
        found = payload_utils.collect_strings(node, Scope(min_length=1, exclude_keys=("type",)))
        self.assertEqual([p for p, _ in found], [("content", 0, "text"), ("content", 1, "text")])

    def test_excluded_keys_are_skipped(self):
        node = {"query": "search me", "api_key": "sk-secret-value"}
        found = payload_utils.collect_strings(node, Scope(min_length=1, exclude_keys=("api_key",)))
        self.assertEqual([p for p, _ in found], [("query",)])

    def test_short_values_are_skipped(self):
        node = {"query": "a much longer value", "n": "ab"}
        found = payload_utils.collect_strings(node, Scope(min_length=8))
        self.assertEqual([p for p, _ in found], [("query",)])

    def test_non_string_leaves_ignored(self):
        node = {"count": 5, "ok": True, "nothing": None, "text": "a real string"}
        found = payload_utils.collect_strings(node, WIDE_OPEN)
        self.assertEqual([p for p, _ in found], [("text",)])

    def test_bare_string_root_has_no_key_so_is_skipped(self):
        # Nothing governs scope for a keyless value, so it is left alone.
        self.assertEqual(payload_utils.collect_strings("naked string", WIDE_OPEN), [])

    def test_empty_structures(self):
        self.assertEqual(payload_utils.collect_strings({}, WIDE_OPEN), [])
        self.assertEqual(payload_utils.collect_strings([], WIDE_OPEN), [])


class SetPathTestCase(unittest.TestCase):
    def test_writes_through_dicts_and_lists(self):
        node = {"content": [{"text": "old"}]}
        payload_utils.set_path(node, ("content", 0, "text"), "new")
        self.assertEqual(node["content"][0]["text"], "new")

    def test_single_element_path(self):
        node = {"a": 1}
        payload_utils.set_path(node, ("a",), 2)
        self.assertEqual(node["a"], 2)


class TransformStringsTestCase(unittest.TestCase):
    def test_returns_count_and_rewrites_values(self):
        node = {"a": "one value", "b": "two value"}
        result, count = payload_utils.transform_strings(node, WIDE_OPEN, upper)
        self.assertEqual(count, 2)
        self.assertEqual(result, {"a": "ONE VALUE", "b": "TWO VALUE"})

    def test_does_not_mutate_the_input(self):
        node = {"a": "original"}
        result, _ = payload_utils.transform_strings(node, WIDE_OPEN, upper)
        self.assertEqual(node["a"], "original", "input must be left untouched")
        self.assertEqual(result["a"], "ORIGINAL")

    def test_nested_input_is_deep_copied(self):
        node = {"outer": {"inner": "value"}}
        result, _ = payload_utils.transform_strings(node, WIDE_OPEN, upper)
        self.assertEqual(node["outer"]["inner"], "value")
        self.assertIsNot(result["outer"], node["outer"])

    def test_no_matches_returns_zero_and_leaves_node_alone(self):
        node = {"n": 1}
        result, count = payload_utils.transform_strings(node, WIDE_OPEN, upper)
        self.assertEqual(count, 0)
        self.assertEqual(result, node)

    def test_single_target_takes_the_serial_path(self):
        node = {"only": "one value"}
        result, count = payload_utils.transform_strings(node, WIDE_OPEN, upper)
        self.assertEqual((result["only"], count), ("ONE VALUE", 1))

    def test_multiple_targets_are_transformed_in_parallel(self):
        """Every transform must be in flight at once.

        Counting distinct thread ids is racy — four instant callables can all be
        served by one worker. A barrier is deterministic instead: it only clears
        if all four run concurrently, and raises on timeout if they are serialised.
        """
        targets = 4
        barrier = threading.Barrier(targets, timeout=10)

        def rendezvous(text: str) -> str:
            barrier.wait()
            return text.upper()

        node = {f"k{i}": f"value number {i}" for i in range(targets)}
        result, count = payload_utils.transform_strings(node, WIDE_OPEN, rendezvous)
        self.assertEqual(count, targets)
        self.assertTrue(all(v.startswith("VALUE") for v in result.values()))

    def test_parallelism_is_capped(self):
        """More targets than MAX_PARALLEL_CALLS must not spawn unbounded threads."""
        node = {f"k{i}": f"value number {i}" for i in range(payload_utils.MAX_PARALLEL_CALLS + 5)}
        seen_threads = set()
        lock = threading.Lock()

        def record(text: str) -> str:
            with lock:
                seen_threads.add(threading.get_ident())
            return text.upper()

        _, count = payload_utils.transform_strings(node, WIDE_OPEN, record)
        self.assertEqual(count, payload_utils.MAX_PARALLEL_CALLS + 5)
        self.assertLessEqual(len(seen_threads), payload_utils.MAX_PARALLEL_CALLS)

    def test_values_land_on_their_own_paths(self):
        """Ordering between collected paths and results must not drift."""
        node = {"a": "aaa long", "b": "bbb long", "c": "ccc long"}
        result, _ = payload_utils.transform_strings(node, WIDE_OPEN, lambda s: s.split()[0] * 2)
        self.assertEqual(result, {"a": "aaaaaa", "b": "bbbbbb", "c": "cccccc"})

    def test_exception_propagates_so_caller_can_fail_closed(self):
        def boom(text: str) -> str:
            raise RuntimeError("skyflow down")

        node = {"a": "one value", "b": "two value"}
        with self.assertRaises(RuntimeError):
            payload_utils.transform_strings(node, WIDE_OPEN, boom)

    def test_exception_on_the_single_target_path_also_propagates(self):
        def boom(text: str) -> str:
            raise RuntimeError("skyflow down")

        with self.assertRaises(RuntimeError):
            payload_utils.transform_strings({"only": "one value"}, WIDE_OPEN, boom)


if __name__ == "__main__":
    unittest.main(verbosity=2)
