"""Shield the model: inference calls de-identified on the way in and re-identified on the way out.

Inference targets reach the interceptor as `event["http"]`. The request
carries its path and a base64 body. The response carries no request, so the
decision travels in a record keyed by the gateway's REQUEST_ID. These tests use
a fake Skyflow client and a fake record table, and no network.

Run: python3 gateway/interceptor/tests/test_inference.py
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import time
import types
import unittest
import urllib.error
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

os.environ["POLICY_PARAMETER_NAME"] = "/test/policy"
os.environ["SKYFLOW_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:0:secret:test"
os.environ["SKYFLOW_VAULT_URL"] = "https://test.vault.skyflowapis.com"
os.environ["SKYFLOW_VAULT_ID"] = "vault123"

import handler  # noqa: E402
import inference  # noqa: E402
import records  # noqa: E402
import settings  # noqa: E402
from policy import PolicyError, PolicySet  # noqa: E402
from records import CallRecord, RecordStore  # noqa: E402
from skyflow_client import FileOutput, FileRunResult, SkyflowClient, SkyflowError, _safe_error_detail  # noqa: E402

NAME, EMAIL, PHONE = "Daniel Okonkwo", "daniel.okonkwo@example.com", "+44 20 7946 0133"
TOKENS = {NAME: "[NAME_AJbrIud]", EMAIL: "[EMAIL_ADDRESS_nJFlbfH]", PHONE: "[PHONE_NUMBER_sk9spjK]"}
VALUES = {token: value for value, token in TOKENS.items()}
FOREIGN = "[NAME_Zz9Yy8X]"
SIGNATURE = "EpUICpwCCBMQARgCKkDPi+Kxmgk1ffY0TnBmRrlRRGYW"
MODEL = "bedrock/global.anthropic.claude-sonnet-5"


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode()


def unb64(text: str) -> str:
    return base64.b64decode(text).decode("utf-8")


class FakeSkyflow:
    """Replaces the three known values with fixed tokens, and back."""

    def __init__(self):
        self.deidentified: list[str] = []
        self.reidentified: list[str] = []
        self.files: list[tuple[str, str, dict]] = []
        self.fail = False
        self.file_output = FileRunResult(
            status="SUCCESS", output_type="BASE64",
            outputs=(FileOutput(url=base64.b64encode(b"%PDF redacted").decode(), file_type="redacted", extension="pdf"),),
        )

    def deidentify(self, text, entity_types, vault_token_entity_types=None):
        if self.fail:
            raise SkyflowError("Skyflow /v1/detect/deidentify/string failed with status 503")
        self.deidentified.append(text)
        for value in sorted(TOKENS, key=len, reverse=True):
            text = text.replace(value, TOKENS[value])
        return types.SimpleNamespace(processed_text=text, entities=[])

    def reidentify(self, text):
        if self.fail:
            raise SkyflowError("Skyflow /v1/detect/reidentify/string failed with status 503")
        self.reidentified.append(text)
        for token, value in {**VALUES, FOREIGN: "Someone Else"}.items():
            text = text.replace(token, value)
        return types.SimpleNamespace(text=text)

    def deidentify_file_base64(self, content_base64, data_format, configuration):
        self.files.append((content_base64, data_format, configuration))
        return "run-1"

    def wait_for_run(self, run_id, seconds_remaining, reserve_seconds=3.0):
        return self.file_output

    def processed_file_bytes(self, run, output, max_bytes):
        return base64.b64decode(output.url)


class FakeStore:
    def __init__(self):
        self.items: dict[str, CallRecord] = {}
        self.fail_put = False

    def put(self, request_id, record):
        if self.fail_put:
            raise RuntimeError("ProvisionedThroughputExceededException")
        self.items[request_id] = record

    def get(self, request_id):
        return self.items.get(request_id)


class Context:
    def __init__(self, rid: str | None = "req-1"):
        self.client_context = types.SimpleNamespace(custom={"REQUEST_ID": rid} if rid else {})

    def get_remaining_time_in_millis(self):
        return 120_000


def request_event(body, path="/v1/messages"):
    raw = b64(json.dumps(body)) if body is not None else ""
    return {"interceptorInputVersion": "1.0", "http": {"gatewayRequest": {
        "path": path, "httpMethod": "POST", "body": raw}}}


def response_event(text, content_type="application/json", status=200):
    return {"interceptorInputVersion": "1.0", "http": {"gatewayRequest": None, "gatewayResponse": {
        "statusCode": status, "headers": None, "body": b64(text), "contentType": content_type}}}


def policy(inference_block=None, overrides=None, http_payloads=None) -> dict:
    raw: dict = {"defaults": {}, "toolNameSeparator": "___"}
    if inference_block is not None:
        raw["inference"] = inference_block
    if overrides is not None:
        raw["inferenceOverrides"] = overrides
    if http_payloads is not None:
        raw["httpPayloads"] = http_payloads
    return raw


SHIELD = {"request": {"action": "deidentify"}, "response": {"action": "reidentify"}}


def conversation() -> dict:
    """A Messages body with every part that a rule can name."""
    return {
        "model": MODEL,
        "max_tokens": 256,
        "system": f"You help the analyst. The customer is {NAME}.",
        "tools": [{"name": "lookup", "description": f"Look up a customer such as {NAME}",
                   "input_schema": {"type": "object", "properties": {"email": {"type": "string"}}}}],
        "messages": [
            {"role": "user", "content": f"Summarize the dispute for {NAME} ({EMAIL})."},
            {"role": "assistant", "content": [
                # The model only ever saw tokens, so that is what its thinking holds.
                {"type": "thinking", "thinking": f"The customer is {TOKENS[NAME]}.", "signature": SIGNATURE},
                {"type": "text", "text": f"I will look up {EMAIL}."},
                {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"email": EMAIL}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": f"Phone {PHONE}"}]},
                {"type": "text", "text": "Thanks."},
            ]},
        ],
    }


class InferenceTestCase(unittest.TestCase):
    def setUp(self):
        self.saved = (settings.load_policy, settings.record_store, settings.build_client)
        self.client = FakeSkyflow()
        self.store = FakeStore()
        settings.record_store = lambda: self.store
        settings.build_client = lambda: self.client
        inference._cache.clear()
        self.use(policy(SHIELD))

    def tearDown(self):
        settings.load_policy, settings.record_store, settings.build_client = self.saved

    def use(self, raw: dict) -> None:
        settings.load_policy = lambda force=False: PolicySet.from_json(raw)

    def send(self, body, path="/v1/messages", rid="req-1"):
        return handler.lambda_handler(request_event(body, path), Context(rid))

    def sent_body(self, out) -> dict:
        return json.loads(base64.b64decode(out["http"]["transformedGatewayRequest"]["body"]))

    def error(self, out, status) -> dict:
        response = out["http"]["transformedGatewayResponse"]
        self.assertEqual(response["statusCode"], status)
        return json.loads(base64.b64decode(response["body"]))


class ClassifyTestCase(unittest.TestCase):
    def test_each_inference_path_is_recognised(self):
        cases = {
            "/v1/messages": "messages",
            "/inference/v1/messages": "messages",
            "/v1/messages/count_tokens": "count_tokens",
            "/v1/models": "models",
            "/v1/chat/completions": "openai",
            "/v1/responses": "openai",
            "/model/us.anthropic.claude-sonnet-5/invoke": "invoke",
            "/model/us.anthropic.claude-sonnet-5/invoke-with-response-stream": "invoke_stream",
        }
        for path, kind in cases.items():
            with self.subTest(path=path):
                self.assertEqual(inference.classify(path, {"model": "m"}).kind, kind)

    def test_an_invoke_path_names_its_model_decoded(self):
        arn = "arn:aws:bedrock:us-east-1:123:inference-profile/global.anthropic.claude-sonnet-5"
        call = inference.classify(f"/model/{arn.replace(':', '%3A').replace('/', '%2F')}/invoke", None)
        self.assertEqual(call.model, arn)

    def test_other_http_paths_are_not_inference(self):
        self.assertIsNone(inference.classify("/billing-runtime/invocations", {"model": "m"}))


class RequestTestCase(InferenceTestCase):
    def test_every_part_of_the_conversation_is_deidentified(self):
        sent = self.sent_body(self.send(conversation()))
        text = json.dumps(sent["messages"]) + sent["system"]
        for value in (NAME, EMAIL, PHONE):
            self.assertNotIn(value, text)
        self.assertIn(TOKENS[NAME], sent["system"])
        self.assertEqual(sent["messages"][1]["content"][2]["input"], {"email": TOKENS[EMAIL]})
        self.assertIn(TOKENS[PHONE], sent["messages"][2]["content"][0]["content"][0]["text"])

    def test_thinking_blocks_and_tool_definitions_pass_untouched(self):
        original = conversation()
        sent = self.sent_body(self.send(conversation()))
        self.assertEqual(sent["messages"][1]["content"][0], original["messages"][1]["content"][0])
        self.assertEqual(sent["tools"], original["tools"])

    def test_the_minted_tokens_are_recorded_for_the_answer(self):
        self.send(conversation())
        record = self.store.items["req-1"]
        self.assertEqual(record.kind, "messages")
        self.assertEqual(record.response_action, "reidentify")
        self.assertEqual(record.tokens, frozenset(TOKENS.values()))

    def test_a_system_note_explains_the_tokens(self):
        sent = self.sent_body(self.send(conversation()))
        self.assertTrue(sent["system"].endswith(inference.SYSTEM_NOTE))

    def test_the_note_can_be_turned_off(self):
        self.use(policy({**SHIELD, "request": {"action": "deidentify", "systemNote": False}}))
        sent = self.sent_body(self.send(conversation()))
        self.assertNotIn(inference.SYSTEM_NOTE, sent["system"])

    def test_parts_limit_what_is_deidentified(self):
        self.use(policy({**SHIELD, "request": {"action": "deidentify", "parts": ["user"]}}))
        sent = self.sent_body(self.send(conversation()))
        self.assertIn(NAME, sent["system"])
        self.assertEqual(sent["messages"][1]["content"][1]["text"], f"I will look up {EMAIL}.")
        self.assertIn(TOKENS[NAME], sent["messages"][0]["content"])
        self.assertIn(PHONE, json.dumps(sent["messages"][2]), "tool results are their own part")

    def test_each_distinct_string_is_sent_once_and_then_cached(self):
        body = {"model": MODEL, "messages": [{"role": "user", "content": f"Hi {NAME}"}] * 3}
        self.send(body)
        self.assertEqual(self.client.deidentified, [f"Hi {NAME}"])
        self.send(body, rid="req-2")
        self.assertEqual(self.client.deidentified, [f"Hi {NAME}"], "the warm cache answered")
        self.assertEqual(self.store.items["req-2"].tokens, frozenset({TOKENS[NAME]}))

    def test_count_tokens_is_deidentified_but_its_answer_is_not_touched(self):
        sent = self.sent_body(self.send(conversation(), path="/v1/messages/count_tokens"))
        self.assertNotIn(NAME, json.dumps(sent["messages"]))
        self.assertEqual(self.store.items["req-1"].response_action, "none")

    def test_invoke_model_bodies_are_deidentified_too(self):
        body = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 50,
                "messages": [{"role": "user", "content": f"Hello {NAME}"}]}
        out = self.send(body, path="/model/global.anthropic.claude-sonnet-5/invoke")
        self.assertEqual(self.sent_body(out)["messages"][0]["content"], f"Hello {TOKENS[NAME]}")

    def test_listing_models_passes_and_is_recorded(self):
        out = self.send(None, path="/v1/models")
        self.assertEqual(out, {"interceptorOutputVersion": "1.0", "http": {}})
        self.assertEqual(self.store.items["req-1"].kind, "models")


class AttachmentTestCase(InferenceTestCase):
    def message(self, *blocks):
        return {"model": MODEL, "messages": [{"role": "user", "content": list(blocks)}]}

    def test_a_text_document_is_deidentified_as_a_string(self):
        doc = {"type": "document", "title": f"Notes on {NAME}",
               "source": {"type": "text", "media_type": "text/plain", "data": f"Call {PHONE}"}}
        sent = self.sent_body(self.send(self.message(doc)))
        block = sent["messages"][0]["content"][0]
        self.assertEqual(block["source"]["data"], f"Call {TOKENS[PHONE]}")
        self.assertEqual(block["title"], f"Notes on {TOKENS[NAME]}")

    def test_a_base64_text_document_keeps_vault_tokens(self):
        doc = {"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": b64(f"Mail {EMAIL}")}}
        sent = self.sent_body(self.send(self.message(doc)))
        self.assertEqual(unb64(sent["messages"][0]["content"][0]["source"]["data"]), f"Mail {TOKENS[EMAIL]}")
        self.assertIn(TOKENS[EMAIL], self.store.items["req-1"].tokens)
        self.assertEqual(self.client.files, [], "text never goes through the file API")

    def test_a_pdf_goes_through_detects_file_api_one_way(self):
        pdf = base64.b64encode(b"%PDF original").decode()
        doc = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": pdf}}
        sent = self.sent_body(self.send(self.message(doc)))
        self.assertEqual(base64.b64decode(sent["messages"][0]["content"][0]["source"]["data"]), b"%PDF redacted")
        content, data_format, configuration = self.client.files[0]
        self.assertEqual((content, data_format), (pdf, "pdf"))
        kinds = {e["deidentificationType"] for e in configuration["detect"]["entities"]}
        self.assertEqual(kinds, {"ENTITY_UNIQUE_COUNTER"})

    def test_an_image_is_redacted_through_the_file_api(self):
        self.client.file_output = FileRunResult(status="SUCCESS", output_type="BASE64", outputs=(
            FileOutput(url=base64.b64encode(b"PNG redacted").decode(), file_type="redacted", extension="png"),))
        image = {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                             "data": base64.b64encode(b"PNG original").decode()}}
        sent = self.sent_body(self.send(self.message(image)))
        self.assertEqual(base64.b64decode(sent["messages"][0]["content"][0]["source"]["data"]), b"PNG redacted")

    def test_an_image_by_url_is_refused(self):
        image = {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}}
        body = self.error(self.send(self.message(image)), 403)
        self.assertEqual(body["type"], "error")
        self.assertEqual(body["error"]["type"], "permission_error")
        self.assertIn("by reference", body["error"]["message"])

    def test_an_oversized_attachment_is_refused(self):
        self.use(policy({**SHIELD, "attachments": {"maxBytes": 4}}))
        doc = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf",
                                              "data": base64.b64encode(b"%PDF too big").decode()}}
        self.assertIn("attachment limit", self.error(self.send(self.message(doc)), 403)["error"]["message"])

    def test_an_unsupported_media_type_is_refused(self):
        image = {"type": "image", "source": {"type": "base64", "media_type": "image/webp", "data": b64("x")}}
        self.assertIn("image/webp", self.error(self.send(self.message(image)), 403)["error"]["message"])

    def test_an_unknown_block_type_is_refused(self):
        self.assertIn("container_upload", self.error(
            self.send(self.message({"type": "container_upload", "file_id": "f"})), 403)["error"]["message"])

    def test_an_excluded_part_is_left_alone_even_if_it_cannot_be_inspected(self):
        self.use(policy({**SHIELD, "request": {"action": "deidentify", "parts": ["user", "document"]}}))
        image = {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}}
        sent = self.sent_body(self.send(self.message(image, {"type": "text", "text": NAME})))
        self.assertEqual(sent["messages"][0]["content"][0], image)


class RefusalTestCase(InferenceTestCase):
    def test_a_model_no_rule_covers_is_blocked(self):
        self.use(policy({**SHIELD, "models": ["*haiku*"]}))
        self.assertIn("No shield-the-model rule", self.error(self.send(conversation()), 403)["error"]["message"])

    def test_an_override_matches_on_the_model(self):
        self.use(policy({**SHIELD, "models": ["*haiku*"]},
                        overrides=[{"models": ["*sonnet*"], "request": {"action": "none"}, "response": {"action": "none"}}]))
        out = self.send(conversation())
        self.assertEqual(out["http"], {})
        self.assertEqual(self.client.deidentified, [])

    def test_without_a_record_table_inference_is_blocked(self):
        settings.record_store = lambda: None
        self.error(self.send(conversation()), 403)

    def test_without_a_request_id_inference_is_blocked(self):
        self.error(self.send(conversation(), rid=None), 403)

    def test_a_record_that_cannot_be_written_blocks_the_call(self):
        self.store.fail_put = True
        self.error(self.send(conversation()), 503)

    def test_a_skyflow_failure_fails_closed(self):
        self.client.fail = True
        with self.assertLogs(level="ERROR") as logs:
            body = self.error(self.send(conversation()), 502)
        self.assertEqual(body["error"]["type"], "api_error")
        self.assertTrue(any("inference_fail_closed" in line for line in logs.output))

    def test_fail_open_passes_the_original_and_still_records(self):
        self.use(policy({**SHIELD, "failure": {"onError": "fail_open"}}))
        self.client.fail = True
        self.assertEqual(self.send(conversation())["http"], {})
        self.assertIn("req-1", self.store.items)

    def test_the_openai_dialect_is_refused_while_a_rule_is_active(self):
        body = self.error(self.send({"model": MODEL, "messages": []}, path="/v1/chat/completions"), 403)
        self.assertIn("OpenAI", body["error"]["message"])

    def test_a_streamed_invoke_cannot_be_reidentified_so_it_is_refused(self):
        out = self.send({"messages": []}, path="/model/global.anthropic.claude-sonnet-5/invoke-with-response-stream")
        response = out["http"]["transformedGatewayResponse"]
        self.assertEqual(response["headers"], {"x-amzn-errortype": "AccessDeniedException"})
        self.assertIn("Streamed InvokeModel", json.loads(base64.b64decode(response["body"]))["message"])

    def test_other_http_targets_still_follow_http_payloads(self):
        out = handler.lambda_handler(request_event({"prompt": NAME}, path="/billing-runtime/invocations"), Context())
        body = self.error(out, 403)
        self.assertEqual(body["error"]["code"], "SENSITIVE_DATA_UNINSPECTED")

    def test_without_an_inference_block_inference_is_an_ordinary_http_payload(self):
        self.use(policy())
        self.assertEqual(self.error(self.send(conversation()), 403)["error"]["code"], "SENSITIVE_DATA_UNINSPECTED")


class ResponseTestCase(InferenceTestCase):
    def record(self, **changes):
        base = dict(kind="messages", response_action="reidentify", response_parts=("text", "tool_call"),
                    tokens=frozenset({TOKENS[NAME], TOKENS[EMAIL]}))
        self.store.items["req-1"] = CallRecord(**{**base, **changes})

    def answer(self, text, content_type="application/json", status=200):
        return handler.lambda_handler(response_event(text, content_type, status), Context())

    def returned(self, out) -> str:
        return unb64(out["http"]["transformedGatewayResponse"]["body"])

    def test_minted_tokens_in_text_and_tool_calls_are_restored(self):
        self.record()
        message = {"type": "message", "model": "claude-sonnet-5", "content": [
            {"type": "thinking", "thinking": f"{TOKENS[NAME]} again", "signature": SIGNATURE},
            {"type": "text", "text": f"{TOKENS[NAME]} wrote from {TOKENS[EMAIL]}."},
            {"type": "tool_use", "id": "t", "name": "lookup", "input": {"email": TOKENS[EMAIL]}},
        ]}
        doc = json.loads(self.returned(self.answer(json.dumps(message))))
        self.assertEqual(doc["content"][1]["text"], f"{NAME} wrote from {EMAIL}.")
        self.assertEqual(doc["content"][2]["input"], {"email": EMAIL})
        self.assertEqual(doc["content"][0], message["content"][0], "thinking is never rewritten")

    def test_a_token_this_call_did_not_mint_stays_a_token(self):
        self.record()
        message = {"content": [{"type": "text", "text": f"{TOKENS[NAME]} and {FOREIGN}"}]}
        doc = json.loads(self.returned(self.answer(json.dumps(message))))
        self.assertEqual(doc["content"][0]["text"], f"{NAME} and {FOREIGN}")
        self.assertNotIn(FOREIGN, self.client.reidentified)

    def test_any_vault_token_restores_foreign_tokens_as_well(self):
        self.record(response_only="any_vault_token")
        message = {"content": [{"type": "text", "text": f"{TOKENS[NAME]} and {FOREIGN}"}]}
        doc = json.loads(self.returned(self.answer(json.dumps(message))))
        self.assertEqual(doc["content"][0]["text"], f"{NAME} and Someone Else")

    def test_a_token_split_across_stream_deltas_is_restored(self):
        self.record()
        token = TOKENS[NAME]
        pieces = ["Hello ", token[:6], token[6:], "!"]
        events = ["event: message_start\ndata: " + json.dumps({"type": "message_start", "message": {"model": "m"}}),
                  "event: content_block_start\ndata: " + json.dumps({"type": "content_block_start", "index": 0,
                                                                     "content_block": {"type": "text", "text": ""}})]
        events += ["event: content_block_delta\ndata: " + json.dumps(
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}}) for p in pieces]
        events += ["event: message_stop\ndata: " + json.dumps({"type": "message_stop"}), ""]
        stream = "\n\n".join(events)
        out = self.returned(self.answer(stream, "text/event-stream"))
        texts = [json.loads(line[6:])["delta"]["text"] for line in out.split("\n")
                 if line.startswith("data: ") and "text_delta" in line]
        self.assertEqual(texts, [f"Hello {NAME}!", "", "", ""])
        self.assertIn("event: message_stop", out)
        self.assertTrue(out.endswith("\n\n"), "the stream keeps its trailing blank line")

    def test_streamed_tool_call_arguments_are_restored(self):
        self.record()
        partial = json.dumps({"email": TOKENS[EMAIL]})
        events = ["event: content_block_delta\ndata: " + json.dumps(
            {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": p}})
            for p in (partial[:9], partial[9:])]
        out = self.returned(self.answer("\n\n".join(events), "text/event-stream"))
        joined = "".join(json.loads(line[6:])["delta"]["partial_json"] for line in out.split("\n") if line.startswith("data: "))
        self.assertEqual(json.loads(joined), {"email": EMAIL})

    def test_an_answer_with_no_record_is_an_ordinary_http_payload(self):
        out = self.answer(json.dumps({"content": [{"type": "text", "text": TOKENS[NAME]}]}))
        self.assertEqual(self.error(out, 403)["error"]["code"], "SENSITIVE_DATA_UNINSPECTED")

    def test_an_answer_whose_rule_does_nothing_passes(self):
        self.record(response_action="none")
        self.assertEqual(self.answer("{}")["http"], {})

    def test_an_error_answer_passes(self):
        self.record()
        self.assertEqual(self.answer(json.dumps({"type": "error"}), status=400)["http"], {})

    def test_an_answer_without_tokens_is_passed_unchanged(self):
        self.record()
        self.assertEqual(self.answer(json.dumps({"content": [{"type": "text", "text": "No names."}]}))["http"], {})
        self.assertEqual(self.client.reidentified, [])

    def test_a_reidentify_failure_fails_closed(self):
        self.record()
        self.client.fail = True
        out = self.answer(json.dumps({"content": [{"type": "text", "text": TOKENS[NAME]}]}))
        self.assertEqual(self.error(out, 502)["error"]["type"], "api_error")


class RoundTripTestCase(InferenceTestCase):
    def test_the_model_sees_tokens_and_the_caller_sees_values(self):
        sent = self.sent_body(self.send({"model": MODEL, "messages": [
            {"role": "user", "content": f"Email {NAME} at {EMAIL}."}]}))
        model_saw = sent["messages"][0]["content"]
        self.assertNotIn(NAME, model_saw)
        answer = {"content": [{"type": "text", "text": f"Done: {TOKENS[NAME]} at {TOKENS[EMAIL]}."}]}
        out = handler.lambda_handler(response_event(json.dumps(answer)), Context())
        returned = json.loads(unb64(out["http"]["transformedGatewayResponse"]["body"]))
        self.assertEqual(returned["content"][0]["text"], f"Done: {NAME} at {EMAIL}.")


class RecordStoreTestCase(unittest.TestCase):
    class Dynamo:
        def __init__(self):
            self.items = {}

        def put_item(self, TableName, Item):
            self.items[Item["requestId"]["S"]] = Item

        def get_item(self, TableName, Key, ConsistentRead):
            item = self.items.get(Key["requestId"]["S"])
            return {"Item": item} if item else {}

    def test_a_record_round_trips(self):
        store = RecordStore("t", self.Dynamo())
        record = CallRecord(kind="messages", response_action="reidentify", response_parts=("text",),
                            tokens=frozenset({TOKENS[NAME]}))
        store.put("r", record)
        self.assertEqual(store.get("r"), record)

    def test_an_expired_record_is_ignored_before_ttl_deletes_it(self):
        dynamo = self.Dynamo()
        store = RecordStore("t", dynamo)
        store.put("r", CallRecord(kind="messages"))
        dynamo.items["r"]["expiresAt"] = {"N": str(int(time.time()) - 1)}
        self.assertIsNone(store.get("r"))

    def test_records_hold_no_values(self):
        record = CallRecord(kind="messages", tokens=frozenset(TOKENS.values()))
        self.assertNotIn(NAME, record.to_json())

    def test_the_request_id_comes_from_the_client_context(self):
        self.assertEqual(records.request_id(Context("abc")), "abc")
        self.assertIsNone(records.request_id(None))


class PolicyTestCase(unittest.TestCase):
    def test_defaults_cover_every_part(self):
        rule = PolicySet.from_json(policy(SHIELD)).resolve_inference(MODEL)
        self.assertEqual(set(rule.request.parts), {"system", "user", "assistant", "tool_call", "tool_result", "document", "image"})
        self.assertEqual(rule.response.only, "minted_for_request")
        self.assertEqual(rule.scope.min_length, 3)

    def test_counter_tokens_cannot_be_reidentified(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json(policy({"request": {"action": "deidentify", "tokenType": "counter"},
                                        "response": {"action": "reidentify"}}))

    def test_restoring_minted_tokens_needs_a_request_that_mints(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json(policy({"response": {"action": "reidentify"}}))

    def test_unknown_parts_are_rejected(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json(policy({"request": {"action": "deidentify", "parts": ["prompt"]}}))

    def test_overrides_need_an_inference_block(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json(policy(overrides=[{"models": ["*"]}]))

    def test_the_shipped_policy_shields_the_model(self):
        shipped = json.loads((SRC.parent / "config" / "policy.json").read_text())
        rule = PolicySet.from_json(shipped).resolve_inference(MODEL)
        self.assertEqual((rule.request.action, rule.response.action), ("deidentify", "reidentify"))


class FileClientTestCase(unittest.TestCase):
    def client(self):
        return SkyflowClient("https://test.vault.skyflowapis.com", "vault123", "key")

    def test_a_base64_file_is_submitted_as_base64(self):
        client = self.client()
        sent = {}
        client._post = lambda path, body: sent.update(path=path, body=body) or {"runId": "run-9"}
        self.assertEqual(client.deidentify_file_base64("QUJD", "pdf", {"detect": {}}), "run-9")
        self.assertEqual(sent["path"], "/v2/detect/deidentify/file")
        self.assertEqual(sent["body"]["dataSource"], "BASE64")
        self.assertEqual(sent["body"]["value"], "QUJD")
        self.assertEqual(sent["body"]["configuration"]["vaultId"], "vault123")

    def test_a_base64_output_is_decoded_and_capped(self):
        client = self.client()
        run = FileRunResult(status="SUCCESS", output_type="BASE64")
        output = FileOutput(url=base64.b64encode(b"12345").decode(), file_type="redacted", extension="pdf")
        self.assertEqual(client.processed_file_bytes(run, output, max_bytes=10), b"12345")
        with self.assertRaises(SkyflowError):
            client.processed_file_bytes(run, output, max_bytes=4)

    def test_a_url_output_must_be_https(self):
        run = FileRunResult(status="SUCCESS", output_type="PRESIGNED_URL")
        with self.assertRaises(SkyflowError):
            self.client().processed_file_bytes(run, FileOutput("http://x/y", "redacted", "pdf"), 10)

    def test_a_run_reports_its_output_type(self):
        client = self.client()
        client._get = lambda path: {"status": "success", "outputType": "base64",
                                    "output": [{"processedFile": "QUJD", "processedFileExtension": "pdf"}]}
        self.assertEqual(client.get_run("run-1").output_type, "BASE64")

    def test_an_error_that_echoes_base64_content_is_cut(self):
        echoed = base64.b64encode(f"{NAME} {EMAIL} " .encode() * 4).decode()
        exc = urllib.error.HTTPError("https://x", 400, "bad", {}, io.BytesIO(
            json.dumps({"error": {"message": f"cannot parse {echoed}"}}).encode()))
        detail = _safe_error_detail(exc)
        self.assertNotIn(echoed[:40], detail)
        self.assertIn("<base64>", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
