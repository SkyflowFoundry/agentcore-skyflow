"""MCP text content blocks: decoding to structure and encoding back again."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import envelope  # noqa: E402

URL = "https://bucket.s3.amazonaws.com/doc.txt?X-Amz-Signature=abc"


def block(text):
    return {"content": [{"type": "text", "text": text}]}


class DecodeTests(unittest.TestCase):
    def test_json_object_becomes_structure(self):
        node = block(json.dumps({"url": URL, "size_bytes": 137}))
        decoded, paths = envelope.decode_text_blocks(node)
        self.assertEqual(decoded["content"][0]["text"]["url"], URL)
        self.assertEqual(paths, (("content", 0, "text"),))

    def test_json_array_becomes_structure(self):
        node = block(json.dumps([{"url": URL}]))
        decoded, paths = envelope.decode_text_blocks(node)
        self.assertEqual(decoded["content"][0]["text"][0]["url"], URL)
        self.assertEqual(len(paths), 1)

    def test_plain_prose_is_left_alone(self):
        node = block("no files here")
        decoded, paths = envelope.decode_text_blocks(node)
        self.assertEqual(decoded, node)
        self.assertEqual(paths, ())

    def test_scalar_json_is_left_alone(self):
        """Decoding "42" would turn a string into a number on the way back."""
        for text in ('"just a string"', "42", "true", "null"):
            with self.subTest(text=text):
                decoded, paths = envelope.decode_text_blocks(block(text))
                self.assertEqual(decoded["content"][0]["text"], text)
                self.assertEqual(paths, ())

    def test_original_is_not_mutated(self):
        node = block(json.dumps({"url": URL}))
        envelope.decode_text_blocks(node)
        self.assertIsInstance(node["content"][0]["text"], str)

    def test_only_text_blocks_are_considered(self):
        node = {"content": [{"type": "image", "data": json.dumps({"url": URL})}]}
        decoded, paths = envelope.decode_text_blocks(node)
        self.assertEqual(paths, ())
        self.assertEqual(decoded, node)

    def test_several_blocks_each_get_a_path(self):
        node = {"content": [
            {"type": "text", "text": json.dumps({"url": URL})},
            {"type": "text", "text": "prose"},
            {"type": "text", "text": json.dumps({"key": "two"})},
        ]}
        _, paths = envelope.decode_text_blocks(node)
        self.assertEqual(paths, (("content", 0, "text"), ("content", 2, "text")))

    def test_node_without_content_is_returned_unchanged(self):
        for node in ({"url": URL}, [], "text", None, {"content": "not a list"}):
            with self.subTest(node=node):
                decoded, paths = envelope.decode_text_blocks(node)
                self.assertEqual(decoded, node)
                self.assertEqual(paths, ())


class EncodeTests(unittest.TestCase):
    def test_round_trip_preserves_the_payload(self):
        original = {"url": URL, "size_bytes": 137, "nested": {"a": [1, 2]}}
        decoded, paths = envelope.decode_text_blocks(block(json.dumps(original)))
        encoded = envelope.encode_text_blocks(decoded, paths)
        self.assertEqual(json.loads(encoded["content"][0]["text"]), original)

    def test_a_swapped_value_survives_the_round_trip(self):
        decoded, paths = envelope.decode_text_blocks(block(json.dumps({"url": URL})))
        decoded["content"][0]["text"]["url"] = "https://clean/doc.txt"
        encoded = envelope.encode_text_blocks(decoded, paths)
        self.assertEqual(
            json.loads(encoded["content"][0]["text"])["url"], "https://clean/doc.txt"
        )

    def test_no_paths_returns_the_node_unchanged(self):
        node = block("prose")
        self.assertIs(envelope.encode_text_blocks(node, ()), node)

    def test_original_is_not_mutated(self):
        decoded, paths = envelope.decode_text_blocks(block(json.dumps({"url": URL})))
        envelope.encode_text_blocks(decoded, paths)
        self.assertIsInstance(decoded["content"][0]["text"], dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
