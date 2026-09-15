"""Policy model: parsing, scope matching, override resolution, validation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from policy import (  # noqa: E402
    DEFAULT_ENTITIES,
    DirectionAction,
    Override,
    PolicyError,
    PolicySet,
    Scope,
)


class DirectionActionTestCase(unittest.TestCase):
    def test_defaults_to_no_op(self):
        action = DirectionAction.from_json(None, "x")
        self.assertEqual(action.action, "none")
        self.assertEqual(action.token_type, "counter")

    def test_rejects_unknown_action(self):
        with self.assertRaises(PolicyError):
            DirectionAction(action="encrypt")

    def test_rejects_unknown_token_type(self):
        with self.assertRaises(PolicyError):
            DirectionAction(action="deidentify", token_type="magic")

    def test_rejects_non_object(self):
        with self.assertRaises(PolicyError):
            DirectionAction.from_json("deidentify", "defaults.request")

    def test_mints_vault_tokens_only_when_deidentifying(self):
        self.assertTrue(DirectionAction("deidentify", "vault_token").mints_vault_tokens)
        self.assertFalse(DirectionAction("deidentify", "counter").mints_vault_tokens)
        # reidentify ignores token_type, so it never mints
        self.assertFalse(DirectionAction("reidentify", "vault_token").mints_vault_tokens)


class ScopeTestCase(unittest.TestCase):
    def test_default_includes_everything(self):
        scope = Scope()
        self.assertTrue(scope.key_in_scope("query"))
        self.assertTrue(scope.key_in_scope("anything"))

    def test_exclude_beats_include(self):
        scope = Scope(include_keys=("*",), exclude_keys=("api_key",))
        self.assertFalse(scope.key_in_scope("api_key"))
        self.assertTrue(scope.key_in_scope("query"))

    def test_glob_matching_on_both_lists(self):
        scope = Scope(include_keys=("user_*",), exclude_keys=("user_id",))
        self.assertTrue(scope.key_in_scope("user_name"))
        self.assertFalse(scope.key_in_scope("user_id"), "exclude glob wins")
        self.assertFalse(scope.key_in_scope("session"), "not in include list")

    def test_min_length(self):
        scope = Scope(min_length=8)
        self.assertFalse(scope.value_eligible("short"))
        self.assertTrue(scope.value_eligible("long enough value"))
        self.assertTrue(scope.value_eligible("12345678"), "boundary is inclusive")

    def test_rejects_non_object(self):
        with self.assertRaises(PolicyError):
            Scope.from_json(["*"], "defaults.scope")


class OverrideMatchingTestCase(unittest.TestCase):
    def test_both_dimensions_must_match(self):
        ov = Override(servers=("exa",), tools=("web_*",))
        self.assertTrue(ov.matches("exa", "web_search"))
        self.assertFalse(ov.matches("github", "web_search"), "server must match")
        self.assertFalse(ov.matches("exa", "create_issue"), "tool must match")

    def test_defaults_match_everything(self):
        self.assertTrue(Override().matches("anything", "at_all"))

    def test_first_match_wins(self):
        policy_set = PolicySet.from_json({
            "defaults": {"request": {"action": "none"}},
            "overrides": [
                {"servers": ["exa"], "tools": ["*"], "request": {"action": "deidentify", "tokenType": "counter"}},
                {"servers": ["exa"], "tools": ["web_search"], "request": {"action": "none"}},
            ],
        })
        # The broad rule is listed first, so it wins even though the second is
        # more specific. Ordering is the only precedence mechanism.
        self.assertEqual(policy_set.resolve("exa", "web_search").request.action, "deidentify")

    def test_override_replaces_whole_block_rather_than_merging_fields(self):
        policy_set = PolicySet.from_json({
            "defaults": {
                "request": {"action": "none"},
                "scope": {"minLength": 8, "excludeKeys": ["api_key", "authorization"]},
            },
            "overrides": [
                {"servers": ["*"], "tools": ["noisy"], "scope": {"minLength": 20}},
            ],
        })
        resolved = policy_set.resolve("any", "noisy")
        self.assertEqual(resolved.scope.min_length, 20)
        self.assertEqual(
            resolved.scope.exclude_keys, (),
            "omitted sub-fields reset to defaults; blocks replace, they do not merge",
        )

    def test_unmatched_tool_falls_through_to_defaults(self):
        policy_set = PolicySet.from_json({
            "defaults": {"request": {"action": "deidentify", "tokenType": "counter"}},
            "overrides": [{"servers": ["github"], "tools": ["*"], "request": {"action": "none"}}],
        })
        self.assertEqual(policy_set.resolve("exa", "web_search").request.action, "deidentify")


class ToolNameSplitTestCase(unittest.TestCase):
    def setUp(self):
        self.policy_set = PolicySet.from_json({"defaults": {}})

    def test_qualified_name(self):
        self.assertEqual(self.policy_set.split_tool_name("exa___web_search"), ("exa", "web_search"))

    def test_unqualified_name_yields_empty_server(self):
        server, tool = self.policy_set.split_tool_name("x_amz_bedrock_agentcore_search")
        self.assertEqual(server, "")
        self.assertEqual(tool, "x_amz_bedrock_agentcore_search")

    def test_unqualified_still_matches_wildcard_server(self):
        policy_set = PolicySet.from_json({
            "defaults": {"request": {"action": "deidentify", "tokenType": "counter"}},
            "overrides": [{"servers": ["*"], "tools": ["x_amz_*"], "request": {"action": "none"}}],
        })
        server, tool = policy_set.split_tool_name("x_amz_bedrock_agentcore_search")
        self.assertEqual(policy_set.resolve(server, tool).request.action, "none")

    def test_splits_on_first_separator_only(self):
        self.assertEqual(
            self.policy_set.split_tool_name("a___b___c"), ("a", "b___c"),
            "partition on the first separator so tool names may contain it",
        )

    def test_custom_separator(self):
        policy_set = PolicySet.from_json({"defaults": {}, "toolNameSeparator": "::"})
        self.assertEqual(policy_set.split_tool_name("exa::search"), ("exa", "search"))


class ValidationTestCase(unittest.TestCase):
    def test_counter_tokens_paired_with_reidentify_rejected(self):
        for label, document in (
            ("response re-identifies", {"defaults": {
                "request": {"action": "deidentify", "tokenType": "counter"},
                "response": {"action": "reidentify"}}}),
            ("request re-identifies", {"defaults": {
                "request": {"action": "reidentify"},
                "response": {"action": "deidentify", "tokenType": "counter"}}}),
        ):
            with self.subTest(label):
                with self.assertRaises(PolicyError) as ctx:
                    PolicySet.from_json(document)
                self.assertIn("one-way", str(ctx.exception))

    def test_validation_also_covers_overrides(self):
        document = {
            "defaults": {"request": {"action": "none"}, "response": {"action": "none"}},
            "overrides": [{
                "servers": ["*"], "tools": ["*"],
                "request": {"action": "deidentify", "tokenType": "counter"},
                "response": {"action": "reidentify"},
            }],
        }
        with self.assertRaises(PolicyError):
            PolicySet.from_json(document)

    def test_vault_tokens_paired_with_reidentify_accepted(self):
        PolicySet.from_json({"defaults": {
            "request": {"action": "deidentify", "tokenType": "vault_token"},
            "response": {"action": "reidentify"}}})

    def test_reidentify_without_any_minting_warns_but_parses(self):
        with self.assertLogs("policy", level="WARNING") as logs:
            PolicySet.from_json({"defaults": {
                "request": {"action": "none"},
                "response": {"action": "reidentify"}}})
        self.assertTrue(any("no rule mints vault tokens" in line for line in logs.output))


class DocumentParsingTestCase(unittest.TestCase):
    def test_empty_document_uses_defaults(self):
        policy_set = PolicySet.from_json({})
        self.assertEqual(policy_set.defaults.entities, tuple(DEFAULT_ENTITIES))
        self.assertEqual(policy_set.tool_name_separator, "___")
        self.assertTrue(policy_set.defaults.is_noop)

    def test_rejects_non_object_document(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json([])

    def test_rejects_non_list_overrides(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json({"defaults": {}, "overrides": {"servers": ["*"]}})

    def test_rejects_non_object_override_entry(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json({"defaults": {}, "overrides": ["exa"]})

    def test_rejects_bad_failure_mode(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json({"defaults": {"failure": {"onError": "shrug"}}})

    def test_shipped_policy_file_is_valid(self):
        """The policy actually deployed must parse — guards against a bad edit."""
        import json
        path = Path(__file__).resolve().parents[1] / "config" / "policy.json"
        policy_set = PolicySet.from_json(json.loads(path.read_text()))
        self.assertGreater(len(policy_set.overrides), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
