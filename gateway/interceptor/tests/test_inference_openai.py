"""Shield the model on the OpenAI formats: Chat Completions and Responses.

Uses the fake Skyflow client and record table from test_inference.py. Answers
are read by their own shape, so these tests also cover a Messages call that
comes back as a Chat Completions answer, which is what the gateway's Bedrock
connector does for DeepSeek and Qwen.

Run: python3 gateway/interceptor/tests/test_inference_openai.py
"""

from __future__ import annotations

import base64
import json
import types
import unittest

from test_inference import (  # noqa: E402 - test_inference sets up the path and environment
    EMAIL,
    FOREIGN,
    NAME,
    PHONE,
    SHIELD,
    TOKENS,
    Context,
    InferenceTestCase,
    b64,
    handler,
    inference,
    policy,
    response_event,
    unb64,
)
from records import CallRecord  # noqa: E402
from skyflow_client import FileOutput, FileRunResult  # noqa: E402

CHAT_MODEL = "bedrock/deepseek.v3.2"
MODEL_CLAUDE = "bedrock/global.anthropic.claude-sonnet-5"
RESPONSES_MODEL = "mantle/openai.gpt-oss-120b"
LOOKUP = {"type": "object", "properties": {"email": {"type": "string"}}}


def chat_conversation() -> dict:
    """A Chat Completions body with every part a rule can name."""
    return {
        "model": CHAT_MODEL,
        "max_tokens": 200,
        "tools": [{"type": "function", "function": {
            "name": "lookup", "description": f"Look up a customer such as {NAME}", "parameters": LOOKUP}}],
        "messages": [
            {"role": "system", "content": f"You help the analyst. The customer is {NAME}."},
            {"role": "user", "content": f"Summarize the dispute for {NAME} ({EMAIL})."},
            {"role": "assistant", "content": None, "reasoning": f"Look up {EMAIL} first.",
             "tool_calls": [{"id": "call_1", "type": "function",
                             "function": {"name": "lookup", "arguments": json.dumps({"email": EMAIL})}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": f"Phone {PHONE}"},
            {"role": "user", "content": [{"type": "text", "text": "Thanks."}]},
        ],
    }


def responses_conversation() -> dict:
    """A Responses body with every kind of input item shield the model reads."""
    return {
        "model": RESPONSES_MODEL,
        "instructions": f"You help the analyst. The customer is {NAME}.",
        "tools": [{"type": "function", "name": "lookup", "description": f"Look up {NAME}", "parameters": LOOKUP}],
        "input": [
            {"role": "user", "content": f"Email {EMAIL}"},
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": f"Call {PHONE}"}]},
            {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "opaque",
             "content": [{"type": "reasoning_text", "text": f"Look up {NAME}"}]},
            {"type": "function_call", "call_id": "c1", "name": "lookup", "arguments": json.dumps({"email": EMAIL})},
            {"type": "function_call_output", "call_id": "c1", "output": f"Phone {PHONE}"},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": f"Found {NAME}."}]},
        ],
    }


def data_url(media: str, content: bytes) -> str:
    return f"data:{media};base64," + base64.b64encode(content).decode()


def sse(*events, done=False) -> str:
    """A buffered server-sent event stream in the OpenAI style: data lines only."""
    lines = ["data: " + json.dumps(event) for event in events]
    if done:
        lines.append("data: [DONE]")
    return "\n\n".join(lines) + "\n\n"


def stream_data(text: str) -> list:
    out = []
    for line in text.split("\n"):
        if line.startswith("data: ") and line != "data: [DONE]":
            out.append(json.loads(line[6:]))
    return out


class OpenAITestCase(InferenceTestCase):
    def openai_error(self, out, status) -> dict:
        response = out["http"]["transformedGatewayResponse"]
        self.assertEqual(response["statusCode"], status)
        body = json.loads(base64.b64decode(response["body"]))
        self.assertEqual(set(body), {"error"}, "OpenAI's error shape, so the OpenAI SDK raises a typed error")
        self.assertEqual(body["error"]["code"], status)
        return body["error"]

    def record(self, kind="chat", **changes):
        base = dict(kind=kind, response_action="reidentify", response_parts=("text", "tool_call"),
                    tokens=frozenset({TOKENS[NAME], TOKENS[EMAIL]}))
        self.store.items["req-1"] = CallRecord(**{**base, **changes})

    def answer(self, text, content_type="application/json"):
        return handler.lambda_handler(response_event(text, content_type), Context())

    def returned(self, out) -> str:
        return unb64(out["http"]["transformedGatewayResponse"]["body"])


class ChatRequestTestCase(OpenAITestCase):
    def send_chat(self, body):
        return self.send(body, path="/v1/chat/completions")

    def test_every_part_of_the_conversation_is_deidentified(self):
        sent = self.sent_body(self.send_chat(chat_conversation()))
        messages = sent["messages"]
        self.assertIn(TOKENS[NAME], messages[0]["content"])
        self.assertEqual(messages[1]["content"], f"Summarize the dispute for {TOKENS[NAME]} ({TOKENS[EMAIL]}).")
        self.assertEqual(messages[2]["reasoning"], f"Look up {TOKENS[EMAIL]} first.")
        arguments = messages[2]["tool_calls"][0]["function"]["arguments"]
        self.assertIsInstance(arguments, str, "arguments stay a JSON string")
        self.assertEqual(json.loads(arguments), {"email": TOKENS[EMAIL]})
        self.assertEqual(messages[3]["content"], f"Phone {TOKENS[PHONE]}")
        self.assertEqual(sent["tools"], chat_conversation()["tools"], "tool definitions are never touched")
        for value in (NAME, EMAIL, PHONE):
            self.assertNotIn(value, json.dumps(messages))

    def test_the_minted_tokens_are_recorded_for_the_answer(self):
        self.send_chat(chat_conversation())
        record = self.store.items["req-1"]
        self.assertEqual((record.kind, record.response_action), ("chat", "reidentify"))
        self.assertEqual(record.tokens, frozenset(TOKENS.values()))

    def test_the_system_note_joins_the_first_system_message(self):
        messages = self.sent_body(self.send_chat(chat_conversation()))["messages"]
        self.assertTrue(messages[0]["content"].endswith(inference.SYSTEM_NOTE))
        self.assertEqual([m["role"] for m in messages].count("system"), 1)

    def test_without_a_system_message_the_note_becomes_one(self):
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": f"Hi {NAME}"}]}
        messages = self.sent_body(self.send_chat(body))["messages"]
        self.assertEqual(messages[0], {"role": "system", "content": inference.SYSTEM_NOTE})
        self.assertEqual(messages[1]["content"], f"Hi {TOKENS[NAME]}")

    def test_parts_limit_what_is_deidentified(self):
        self.use(policy({**SHIELD, "request": {"action": "deidentify", "parts": ["user"]}}))
        messages = self.sent_body(self.send_chat(chat_conversation()))["messages"]
        self.assertIn(NAME, messages[0]["content"])
        self.assertEqual(json.loads(messages[2]["tool_calls"][0]["function"]["arguments"]), {"email": EMAIL})
        self.assertEqual(messages[3]["content"], f"Phone {PHONE}")
        self.assertIn(TOKENS[EMAIL], messages[1]["content"])

    def test_arguments_are_parsed_so_the_scope_key_globs_apply(self):
        self.use(policy({**SHIELD, "scope": {"excludeKeys": ["email"]}}))
        body = chat_conversation()
        body["messages"][2]["tool_calls"][0]["function"]["arguments"] = json.dumps({"email": EMAIL, "note": f"for {NAME}"})
        messages = self.sent_body(self.send_chat(body))["messages"]
        arguments = json.loads(messages[2]["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(arguments, {"email": EMAIL, "note": f"for {TOKENS[NAME]}"})

    def test_arguments_that_are_not_json_are_deidentified_as_text(self):
        body = chat_conversation()
        body["messages"][2]["tool_calls"][0]["function"]["arguments"] = f"email={EMAIL}"
        messages = self.sent_body(self.send_chat(body))["messages"]
        self.assertEqual(messages[2]["tool_calls"][0]["function"]["arguments"], f"email={TOKENS[EMAIL]}")

    def test_an_image_data_url_goes_through_the_file_api(self):
        self.client.file_output = FileRunResult(status="SUCCESS", output_type="BASE64", outputs=(
            FileOutput(url=base64.b64encode(b"PNG redacted").decode(), file_type="redacted", extension="png"),))
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [
            {"type": "text", "text": "Read this."},
            {"type": "image_url", "image_url": {"url": data_url("image/png", b"PNG original"), "detail": "low"}}]}]}
        part = self.sent_body(self.send_chat(body))["messages"][-1]["content"][1]
        self.assertEqual(part["image_url"], {"url": data_url("image/png", b"PNG redacted"), "detail": "low"})
        self.assertEqual(self.client.files[0][1], "png")

    def test_an_image_by_url_is_refused(self):
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}]}]}
        self.assertIn("sent by URL", self.openai_error(self.send_chat(body), 403)["message"])

    def test_a_pdf_file_goes_through_the_file_api_and_its_filename_is_deidentified(self):
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [
            {"type": "file", "file": {"filename": f"{NAME} statement.pdf",
                                      "file_data": data_url("application/pdf", b"%PDF original")}}]}]}
        file = self.sent_body(self.send_chat(body))["messages"][-1]["content"][0]["file"]
        self.assertEqual(file["file_data"], data_url("application/pdf", b"%PDF redacted"))
        self.assertEqual(file["filename"], f"{TOKENS[NAME]} statement.pdf")

    def test_a_text_file_keeps_vault_tokens(self):
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [
            {"type": "file", "file": {"filename": "note.txt", "file_data": data_url("text/plain", f"Mail {EMAIL}".encode())}}]}]}
        messages = self.sent_body(self.send_chat(body))["messages"]
        file = messages[-1]["content"][0]["file"]
        self.assertEqual(file["file_data"], data_url("text/plain", f"Mail {TOKENS[EMAIL]}".encode()))
        self.assertIn(TOKENS[EMAIL], self.store.items["req-1"].tokens)
        self.assertEqual(messages[0]["content"], inference.SYSTEM_NOTE,
                         "a token minted inside an attachment still earns the note")

    def test_raw_base64_file_data_is_read_by_its_filename(self):
        raw = base64.b64encode(f"Mail {EMAIL}".encode()).decode()
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [
            {"type": "file", "file": {"filename": "note.txt", "file_data": raw}}]}]}
        file = self.sent_body(self.send_chat(body))["messages"][-1]["content"][0]["file"]
        self.assertEqual(base64.b64decode(file["file_data"]).decode(), f"Mail {TOKENS[EMAIL]}")

    def test_what_cannot_be_inspected_is_refused(self):
        cases = {
            "file id": {"type": "file", "file": {"file_id": "file-abc"}},
            "audio": {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
            "unknown part": {"type": "video_url", "video_url": {"url": "x"}},
        }
        for name, part in cases.items():
            with self.subTest(name=name):
                body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [part]}]}
                self.openai_error(self.send_chat(body), 403)
        for name, body in {
            "unknown role": {"model": CHAT_MODEL, "messages": [{"role": "narrator", "content": NAME}]},
            "predicted output": {"model": CHAT_MODEL, "messages": [], "prediction": {"type": "content", "content": NAME}},
            "no messages": {"model": CHAT_MODEL, "prompt": NAME},
        }.items():
            with self.subTest(name=name):
                self.openai_error(self.send_chat(body), 403)
        self.assertEqual(self.client.deidentified, [])


class ResponsesRequestTestCase(OpenAITestCase):
    def send_responses(self, body):
        return self.send(body, path="/v1/responses")

    def test_every_input_item_is_deidentified(self):
        sent = self.sent_body(self.send_responses(responses_conversation()))
        items = sent["input"]
        self.assertTrue(sent["instructions"].startswith(f"You help the analyst. The customer is {TOKENS[NAME]}."))
        self.assertTrue(sent["instructions"].endswith(inference.SYSTEM_NOTE))
        self.assertEqual(items[0]["content"], f"Email {TOKENS[EMAIL]}")
        self.assertEqual(items[1]["content"][0]["text"], f"Call {TOKENS[PHONE]}")
        self.assertEqual(items[2]["content"][0]["text"], f"Look up {TOKENS[NAME]}")
        self.assertEqual(items[2]["encrypted_content"], "opaque", "encrypted reasoning stays as it came")
        self.assertEqual(json.loads(items[3]["arguments"]), {"email": TOKENS[EMAIL]})
        self.assertEqual(items[4]["output"], f"Phone {TOKENS[PHONE]}")
        self.assertEqual(items[5]["content"][0]["text"], f"Found {TOKENS[NAME]}.")
        self.assertEqual(sent["tools"], responses_conversation()["tools"])
        self.assertEqual(self.store.items["req-1"].kind, "responses")

    def test_a_string_input_gets_the_note_as_instructions(self):
        sent = self.sent_body(self.send_responses({"model": RESPONSES_MODEL, "input": f"Hi {NAME}"}))
        self.assertEqual(sent["input"], f"Hi {TOKENS[NAME]}")
        self.assertEqual(sent["instructions"], inference.SYSTEM_NOTE)

    def test_image_and_file_data_urls_go_through_the_file_api(self):
        body = {"model": RESPONSES_MODEL, "input": [{"role": "user", "content": [
            {"type": "input_image", "image_url": data_url("image/png", b"PNG original")},
            {"type": "input_file", "filename": "s.pdf", "file_data": data_url("application/pdf", b"%PDF original")}]}]}
        content = self.sent_body(self.send_responses(body))["input"][0]["content"]
        self.assertEqual(content[1]["file_data"], data_url("application/pdf", b"%PDF redacted"))
        self.assertEqual([f[1] for f in self.client.files], ["png", "pdf"])

    def test_continuing_a_stored_conversation_is_refused_when_only_minted_tokens_are_restored(self):
        """Its earlier turns mint nothing here, so their tokens could never be restored."""
        for name, extra in {
            "previous response": {"previous_response_id": "resp_1", "input": "What was the email again?"},
            "conversation": {"conversation": "conv_1", "input": "What was the email again?"},
            "item reference": {"input": [{"type": "item_reference", "id": "msg_1"}, {"role": "user", "content": "Again?"}]},
        }.items():
            with self.subTest(name=name):
                body = {"model": RESPONSES_MODEL, **extra}
                self.assertIn("stored conversation", self.openai_error(self.send_responses(body), 403)["message"])

    def test_continuing_is_allowed_when_any_vault_token_is_restored_and_gets_the_note(self):
        self.use(policy({**SHIELD, "response": {"action": "reidentify", "only": "any_vault_token"}}))
        body = {"model": RESPONSES_MODEL, "previous_response_id": "resp_1",
                "input": [{"type": "item_reference", "id": "msg_1"}, {"role": "user", "content": "Again?"}]}
        sent = self.sent_body(self.send_responses(body))
        self.assertEqual(sent["input"][0], {"type": "item_reference", "id": "msg_1"})
        self.assertEqual(sent["instructions"], inference.SYSTEM_NOTE, "the stored turns hold tokens the model must not remark on")

    def test_what_cannot_be_inspected_is_refused(self):
        cases = {
            "image by file id": {"model": RESPONSES_MODEL, "input": [{"role": "user", "content": [
                {"type": "input_image", "file_id": "file-abc"}]}]},
            "file by URL": {"model": RESPONSES_MODEL, "input": [{"role": "user", "content": [
                {"type": "input_file", "file_url": "https://example.com/a.pdf"}]}]},
            "server tool item": {"model": RESPONSES_MODEL, "input": [{"type": "web_search_call", "id": "ws_1"}]},
            "stored prompt": {"model": RESPONSES_MODEL, "input": "Hi", "prompt": {"id": "pmpt_1", "variables": {"n": NAME}}},
            "no input": {"model": RESPONSES_MODEL, "messages": []},
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                self.openai_error(self.send_responses(body), 403)


class CrossFormatTestCase(OpenAITestCase):
    """The gateway hands a body on unchanged, so every format's fields are read on every path."""

    def test_chat_tool_calls_on_the_messages_path_are_deidentified(self):
        """The Bedrock connector sends a Messages call to DeepSeek on to an OpenAI endpoint."""
        body = {"model": CHAT_MODEL, "max_tokens": 100, "messages": [
            {"role": "user", "content": f"Find {NAME}."},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "lookup", "arguments": json.dumps({"email": EMAIL})}}]},
            {"role": "tool", "tool_call_id": "c1", "content": f"Phone {PHONE}"}]}
        messages = self.sent_body(self.send(body))["messages"]
        self.assertEqual(json.loads(messages[1]["tool_calls"][0]["function"]["arguments"]), {"email": TOKENS[EMAIL]})
        self.assertEqual(messages[2]["content"], f"Phone {TOKENS[PHONE]}")

    def test_anthropics_system_on_the_chat_path_is_deidentified(self):
        """The Bedrock connector sends a Chat Completions call to Claude on to InvokeModel."""
        body = {"model": "bedrock/global.anthropic.claude-sonnet-5", "anthropic_version": "bedrock-2023-05-31",
                "system": f"The customer is {NAME}.", "messages": [{"role": "user", "content": "Who is it?"}]}
        sent = self.sent_body(self.send(body, path="/v1/chat/completions"))
        self.assertEqual(sent["system"], f"The customer is {TOKENS[NAME]}.\n\n{inference.SYSTEM_NOTE}")

    def test_the_note_goes_where_claude_reads_it_on_the_chat_path(self):
        """Claude refuses a first message with the system role. Seen live."""
        body = {"model": "bedrock/global.anthropic.claude-sonnet-5", "anthropic_version": "bedrock-2023-05-31",
                "messages": [{"role": "user", "content": f"Who is {NAME}?"}]}
        sent = self.sent_body(self.send(body, path="/v1/chat/completions"))
        self.assertEqual(sent["system"], inference.SYSTEM_NOTE)
        self.assertEqual([m["role"] for m in sent["messages"]], ["user"])

    def test_chat_tool_calls_in_an_invoke_body_are_deidentified(self):
        body = {"anthropic_version": "bedrock-2023-05-31", "messages": [
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "lookup", "arguments": json.dumps({"email": EMAIL})}}]}]}
        messages = self.sent_body(self.send(body, path="/model/deepseek.v3-v1:0/invoke"))["messages"]
        self.assertEqual(json.loads(messages[0]["tool_calls"][0]["function"]["arguments"]), {"email": TOKENS[EMAIL]})

    def test_text_fields_of_formats_not_read_are_refused(self):
        for key, value in {"prompt": f"Human: {NAME}", "inputText": NAME, "message": NAME,
                           "chat_history": [{"role": "USER", "message": NAME}], "documents": [{"text": NAME}]}.items():
            with self.subTest(key=key):
                body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": "Hi"}], key: value}
                self.openai_error(self.send(body, path="/v1/chat/completions"), 403)
        self.assertEqual(self.client.deidentified, [])

    def test_a_messages_name_is_deidentified(self):
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "name": f"{NAME} desk", "content": "Hello there."}]}
        messages = self.sent_body(self.send(body, path="/v1/chat/completions"))["messages"]
        self.assertEqual(messages[-1]["name"], f"{TOKENS[NAME]} desk")

    def test_arguments_sent_as_json_rather_than_a_string_are_deidentified(self):
        chat = {"model": CHAT_MODEL, "messages": [{"role": "assistant", "content": None, "tool_calls": [
            {"id": "c", "type": "function", "function": {"name": "f", "arguments": {"email": EMAIL}}}]}]}
        sent = self.sent_body(self.send(chat, path="/v1/chat/completions"))
        self.assertEqual(sent["messages"][-1]["tool_calls"][0]["function"]["arguments"], {"email": TOKENS[EMAIL]})
        responses = {"model": RESPONSES_MODEL, "input": [
            {"type": "function_call", "call_id": "c", "name": "f", "arguments": {"email": EMAIL}}]}
        sent = self.sent_body(self.send(responses, path="/v1/responses"))
        self.assertEqual(sent["input"][0]["arguments"], {"email": TOKENS[EMAIL]})

    def test_arguments_of_another_type_are_refused(self):
        body = {"model": CHAT_MODEL, "messages": [{"role": "assistant", "content": None, "tool_calls": [
            {"id": "c", "type": "function", "function": {"name": "f", "arguments": 5}}]}]}
        self.openai_error(self.send(body, path="/v1/chat/completions"), 403)

    def test_text_fields_of_the_wrong_type_are_refused(self):
        cases = {
            "chat text object": {"role": "user", "content": [{"type": "text", "text": {"value": NAME}}]},
            "responses text list": {"role": "user", "content": [{"type": "input_text", "text": [NAME]}]},
            "document title list": {"role": "user", "content": [{"type": "document", "title": [NAME],
                                                                 "source": {"type": "text", "data": "x"}}]},
            "text source data list": {"role": "user", "content": [{"type": "document",
                                                                   "source": {"type": "text", "data": [NAME]}}]},
        }
        for name, message in cases.items():
            with self.subTest(name=name):
                self.error(self.send({"model": MODEL_CLAUDE, "messages": [message]}), 403)

    def test_citations_annotations_and_search_sources_are_deidentified(self):
        body = {"model": MODEL_CLAUDE, "messages": [
            {"role": "user", "content": [{"type": "search_result", "source": f"https://x.example/{EMAIL}",
                                          "title": "Note", "content": [{"type": "text", "text": "See source."}]}]},
            {"role": "assistant", "content": [{"type": "text", "text": "Quoted.", "citations": [
                {"type": "char_location", "cited_text": f"{NAME} wrote", "document_title": f"{NAME} file"}]}]},
            {"role": "assistant", "content": [{"type": "output_text", "text": "Linked.", "annotations": [
                {"type": "url_citation", "title": f"About {NAME}", "url": "https://x.example"}]}]}]}
        messages = self.sent_body(self.send(body))["messages"]
        self.assertEqual(messages[0]["content"][0]["source"], f"https://x.example/{TOKENS[EMAIL]}")
        citation = messages[1]["content"][0]["citations"][0]
        self.assertEqual((citation["cited_text"], citation["document_title"]),
                         (f"{TOKENS[NAME]} wrote", f"{TOKENS[NAME]} file"))
        self.assertEqual(messages[2]["content"][0]["annotations"][0]["title"], f"About {TOKENS[NAME]}")

    def test_a_file_that_also_names_a_file_id_is_refused(self):
        """The provider might read the uploaded file, which never passes through here."""
        part = {"type": "file", "file": {"filename": "a.txt", "file_data": data_url("text/plain", b"harmless"),
                                         "file_id": "file-abc"}}
        body = {"model": CHAT_MODEL, "messages": [{"role": "user", "content": [part]}]}
        self.openai_error(self.send(body, path="/v1/chat/completions"), 403)

    def test_a_system_block_other_than_text_is_refused(self):
        body = {"model": CHAT_MODEL, "system": [{"type": "image", "source": {}}], "messages": []}
        self.error(self.send(body), 403)

    def test_an_internal_error_on_an_openai_path_answers_in_openai_form_and_is_recorded(self):
        def broken(*args, **kwargs):
            raise KeyError("boom")
        saved = inference.formats.collect
        inference.formats.collect = broken
        try:
            with self.assertLogs(level="ERROR"):
                out = self.send({"model": CHAT_MODEL, "messages": []}, path="/v1/chat/completions")
        finally:
            inference.formats.collect = saved
        self.openai_error(out, 502)
        self.assertEqual(self.store.items["req-1"].kind, "chat", "recorded, so the refusal reaches the caller")


class ChatAnswerTestCase(OpenAITestCase):
    def test_text_reasoning_and_tool_arguments_are_restored(self):
        self.record()
        answer = {"object": "chat.completion", "choices": [{"index": 0, "message": {
            "role": "assistant", "content": f"<reasoning>{TOKENS[NAME]}</reasoning>Hello {TOKENS[NAME]}",
            "reasoning": f"Write to {TOKENS[EMAIL]}",
            "tool_calls": [{"id": "c", "type": "function", "function": {
                "name": "lookup", "arguments": json.dumps({"email": TOKENS[EMAIL]})}}]}}]}
        message = json.loads(self.returned(self.answer(json.dumps(answer))))["choices"][0]["message"]
        self.assertEqual(message["content"], f"<reasoning>{NAME}</reasoning>Hello {NAME}")
        self.assertEqual(message["reasoning"], f"Write to {EMAIL}")
        self.assertEqual(json.loads(message["tool_calls"][0]["function"]["arguments"]), {"email": EMAIL})

    def test_a_token_this_call_did_not_mint_stays_a_token(self):
        self.record()
        answer = {"choices": [{"message": {"content": f"{TOKENS[NAME]} and {FOREIGN}"}}]}
        message = json.loads(self.returned(self.answer(json.dumps(answer))))["choices"][0]["message"]
        self.assertEqual(message["content"], f"{NAME} and {FOREIGN}")

    def test_a_stream_is_restored_across_split_chunks(self):
        self.record()
        token = TOKENS[NAME]
        chunks = [{"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}]
        chunks += [{"object": "chat.completion.chunk", "obfuscation": "pad",
                    "choices": [{"index": 0, "delta": {"content": piece}}]}
                   for piece in ("Hello ", token[:5], token[5:], "!")]
        out = self.returned(self.answer(sse(*chunks, done=True), "text/event-stream"))
        contents = [c["choices"][0]["delta"].get("content") for c in stream_data(out)]
        self.assertEqual(contents, [f"Hello {NAME}!", "", "", "", ""])
        self.assertTrue(out.endswith("data: [DONE]\n\n"), "the stream keeps its end marker and blank line")

    def test_streamed_tool_arguments_are_restored(self):
        self.record()
        arguments = json.dumps({"email": TOKENS[EMAIL]})
        chunks = [{"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c", "type": "function",
                                                                     "function": {"name": "lookup", "arguments": ""}}]}}]}]
        chunks += [{"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": piece}}]}}]}
                   for piece in (arguments[:8], arguments[8:20], arguments[20:])]
        out = self.returned(self.answer(sse(*chunks), "text/event-stream"))
        joined = "".join(c["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] for c in stream_data(out))
        self.assertEqual(json.loads(joined), {"email": EMAIL})

    def test_a_streamed_custom_tool_call_is_restored(self):
        self.record()
        chunks = [{"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "type": "custom", "custom": {"input": piece}}]}}]}
            for piece in ("mail ", TOKENS[EMAIL][:6], TOKENS[EMAIL][6:])]
        out = self.returned(self.answer(sse(*chunks), "text/event-stream"))
        joined = "".join(c["choices"][0]["delta"]["tool_calls"][0]["custom"]["input"] for c in stream_data(out))
        self.assertEqual(joined, f"mail {EMAIL}")

    def test_streamed_reasoning_is_restored(self):
        self.record()
        chunks = [{"choices": [{"index": 0, "delta": {"reasoning": piece}}]}
                  for piece in ("About ", TOKENS[NAME][:3], TOKENS[NAME][3:])]
        out = self.returned(self.answer(sse(*chunks), "text/event-stream"))
        self.assertEqual("".join(c["choices"][0]["delta"]["reasoning"] for c in stream_data(out)), f"About {NAME}")


class ResponsesAnswerTestCase(OpenAITestCase):
    def test_message_reasoning_and_function_call_are_restored(self):
        self.record("responses")
        answer = {"object": "response", "output": [
            {"type": "reasoning", "content": [{"type": "reasoning_text", "text": f"About {TOKENS[NAME]}"}], "summary": []},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": f"Hello {TOKENS[NAME]}"}]},
            {"type": "function_call", "name": "lookup", "call_id": "c", "arguments": json.dumps({"email": TOKENS[EMAIL]})}]}
        output = json.loads(self.returned(self.answer(json.dumps(answer))))["output"]
        self.assertEqual(output[0]["content"][0]["text"], f"About {NAME}")
        self.assertEqual(output[1]["content"][0]["text"], f"Hello {NAME}")
        self.assertEqual(json.loads(output[2]["arguments"]), {"email": EMAIL})

    def test_the_echoed_instructions_are_given_back_without_the_note(self):
        self.record("responses")
        answer = {"object": "response", "instructions": f"Customer is {TOKENS[NAME]}.\n\n{inference.SYSTEM_NOTE}",
                  "output": [{"type": "message", "content": [{"type": "output_text", "text": "Done."}]}]}
        doc = json.loads(self.returned(self.answer(json.dumps(answer))))
        self.assertEqual(doc["instructions"], f"Customer is {NAME}.")
        answer["instructions"] = inference.SYSTEM_NOTE
        self.assertIsNone(json.loads(self.returned(self.answer(json.dumps(answer))))["instructions"],
                          "instructions the caller never sent come back as none")

    def test_every_copy_of_a_streamed_text_is_restored_alike(self):
        self.record("responses")
        token = TOKENS[NAME]
        text = f"Hello {token}!"
        arguments = json.dumps({"email": TOKENS[EMAIL]})
        message = {"type": "message", "id": "m1", "content": [{"type": "output_text", "text": text}]}
        call = {"type": "function_call", "id": "f1", "name": "lookup", "arguments": arguments}
        events = [
            {"type": "response.created", "response": {"object": "response", "output": []}},
            {"type": "response.output_item.added", "output_index": 0, "item": {**message, "content": []}},
            {"type": "response.content_part.added", "output_index": 0, "content_index": 0,
             "part": {"type": "output_text", "text": ""}},
        ]
        events += [{"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "content_index": 0,
                    "delta": piece} for piece in ("Hello ", token[:4], token[4:], "!")]
        events += [
            {"type": "response.output_text.done", "item_id": "m1", "output_index": 0, "content_index": 0, "text": text},
            {"type": "response.content_part.done", "output_index": 0, "content_index": 0,
             "part": {"type": "output_text", "text": text}},
            {"type": "response.output_item.done", "output_index": 0, "item": message},
            {"type": "response.function_call_arguments.delta", "item_id": "f1", "output_index": 1, "delta": arguments[:9]},
            {"type": "response.function_call_arguments.delta", "item_id": "f1", "output_index": 1, "delta": arguments[9:]},
            {"type": "response.function_call_arguments.done", "item_id": "f1", "output_index": 1, "arguments": arguments},
            {"type": "response.completed", "response": {"object": "response", "output": [message, call]}},
        ]
        out = stream_data(self.returned(self.answer(sse(*events), "text/event-stream")))
        expected = f"Hello {NAME}!"
        deltas = [e["delta"] for e in out if e["type"] == "response.output_text.delta"]
        self.assertEqual(deltas, [expected, "", "", ""])
        by_type = {e["type"]: e for e in out}
        self.assertEqual(by_type["response.output_text.done"]["text"], expected)
        self.assertEqual(by_type["response.content_part.done"]["part"]["text"], expected)
        self.assertEqual(by_type["response.output_item.done"]["item"]["content"][0]["text"], expected)
        completed = by_type["response.completed"]["response"]["output"]
        self.assertEqual(completed[0]["content"][0]["text"], expected)
        self.assertEqual(json.loads(completed[1]["arguments"]), {"email": EMAIL})
        self.assertEqual(json.loads(by_type["response.function_call_arguments.done"]["arguments"]), {"email": EMAIL})
        argument_deltas = "".join(e["delta"] for e in out if e["type"] == "response.function_call_arguments.delta")
        self.assertEqual(json.loads(argument_deltas), {"email": EMAIL})
        self.assertEqual(sorted(self.client.reidentified), sorted([TOKENS[NAME], TOKENS[EMAIL]]),
                         "each token is re-identified once however many copies there are")


class AnswerShapeTestCase(OpenAITestCase):
    def test_a_messages_call_answered_in_chat_form_is_restored(self):
        """The Bedrock connector answers a Messages call to DeepSeek or Qwen this way."""
        self.record("messages")
        answer = {"object": "chat.completion", "choices": [{"message": {"content": f"Hello {TOKENS[NAME]}"}}]}
        message = json.loads(self.returned(self.answer(json.dumps(answer))))["choices"][0]["message"]
        self.assertEqual(message["content"], f"Hello {NAME}")

    def test_an_unknown_shape_that_carries_a_token_fails_closed(self):
        self.record()
        with self.assertLogs(level="ERROR") as logs:
            out = self.answer(json.dumps({"generation": f"Hello {TOKENS[NAME]}"}))
        self.openai_error(out, 502)
        self.assertTrue(any("unrecognised shape" in line for line in logs.output))

    def test_an_unknown_shape_without_tokens_passes(self):
        """Claude on Responses through the Bedrock connector answers 200 with this."""
        self.record("responses")
        odd = {"Output": {"__type": "com.amazon.coral.service#UnknownOperationException"}, "Version": "1.0"}
        self.assertEqual(self.answer(json.dumps(odd))["http"], {})

    def test_an_answer_that_is_not_json_is_judged_by_its_tokens(self):
        self.record()
        self.assertEqual(self.answer("plain words", "text/plain")["http"], {})
        self.openai_error(self.answer(f"plain {TOKENS[NAME]}", "text/plain"), 502)


class RestorerTestCase(unittest.TestCase):
    """Values restored into tool-call arguments stay valid JSON."""

    def restorer(self, value):
        client = types.SimpleNamespace(reidentify=lambda text: types.SimpleNamespace(text=value))
        return inference._Restorer(client, CallRecord(kind="chat", response_only="any_vault_token"))

    def test_a_value_with_quotes_is_escaped_in_parsed_arguments(self):
        out = self.restorer('Dan "D" O').json_string(json.dumps({"name": TOKENS[NAME]}))
        self.assertEqual(json.loads(out), {"name": 'Dan "D" O'})

    def test_arguments_cut_short_are_restored_with_escaping(self):
        out = self.restorer('Dan "D" O').json_string('{"name": "' + TOKENS[NAME])
        self.assertEqual(out, '{"name": "Dan \\"D\\" O')

    def test_free_form_arguments_get_plain_values(self):
        out = self.restorer('Dan "D" O').json_string("Send the letter to " + TOKENS[NAME])
        self.assertEqual(out, 'Send the letter to Dan "D" O')
        out = self.restorer('Dan "D" O').json_string(TOKENS[NAME] + " gets the letter")
        self.assertEqual(out, 'Dan "D" O gets the letter', "a leading token is not the start of a JSON array")

    def test_arguments_without_tokens_are_left_byte_for_byte(self):
        original = '{"name":   "x"}'
        self.assertEqual(self.restorer("unused").json_string(original), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
