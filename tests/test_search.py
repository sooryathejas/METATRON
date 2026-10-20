"""Caller tests using the real MCP SDK over a deterministic HTTP transport.

Run with: python -m unittest discover -s tests -v
Install requirements-parallel.txt first. Ollama and recon tools are not invoked.
"""

import asyncio
import copy
import json
import os
import signal
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import httpx

import llm
import parallel_search
from search import SearchContext, handle_search_dispatch


REAL_CLIENT = httpx.AsyncClient
PAGE = "https://docs.python.org/3/library/ssl.html"
SOURCE = f"TLS guidance: {PAGE}\nKeep Python and OpenSSL updated."


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.requests = []
        self.lock = threading.Lock()
        self.tool_error = False
        self.http_status = 200
        self.block = False
        self.interrupt = False

        async def respond(request):
            with self.lock:
                self.requests.append((request, threading.current_thread().name))
            if request.method != "POST":
                return httpx.Response(200, json={})
            payload = json.loads(request.content)
            method = payload["method"]
            if "id" not in payload:
                return httpx.Response(202)
            if method == "initialize":
                result = {
                    "protocolVersion": payload["params"]["protocolVersion"],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fixture", "version": "1"},
                }
            elif method == "tools/list":
                result = {"tools": [
                    {"name": name, "inputSchema": {"type": "object"}}
                    for name in ("web_search", "web_fetch")
                ]}
            elif method == "tools/call":
                if self.interrupt:
                    os.kill(os.getpid(), signal.SIGINT)
                    await asyncio.sleep(1)
                if self.block:
                    await asyncio.Event().wait()
                if self.http_status != 200:
                    return httpx.Response(self.http_status, text="fixture HTTP failure")
                result = {
                    "content": [{"type": "text", "text": "Quota exceeded" if self.tool_error else SOURCE}],
                    "isError": self.tool_error,
                }
            else:
                raise AssertionError(f"Unexpected MCP method: {method}")
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

        self.client_patch = patch(
            "httpx.AsyncClient",
            side_effect=lambda **kwargs: REAL_CLIENT(transport=httpx.MockTransport(respond), **kwargs),
        )
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)

    def calls(self):
        return [
            (json.loads(request.content)["params"], thread)
            for request, thread in self.requests
            if request.method == "POST" and json.loads(request.content)["method"] == "tools/call"
        ]

    def assert_transport(self):
        methods = []
        for request, _ in self.requests:
            self.assertEqual(str(request.url), parallel_search.MCP_URL)
            self.assertEqual(request.headers["User-Agent"], parallel_search.USER_AGENT)
            self.assertNotIn("authorization", request.headers)
            if request.method == "POST":
                methods.append(json.loads(request.content)["method"])
        for method in ("initialize", "tools/list", "tools/call"):
            self.assertIn(method, methods)

    def run_analysis(self):
        responses = iter([
            "[SEARCH: Python TLS mitigation guidance]",
            f"[SEARCH: {PAGE}]",
            "[SEARCH: Python TLS update guidance]",
            "RISK_LEVEL: LOW\nSUMMARY: Use maintained Python releases.",
        ])
        seen = []

        def model(messages):
            seen.append(copy.deepcopy(messages))
            return next(responses)

        with patch("llm.ask_ollama", side_effect=model):
            result = llm.analyse_target("example.com", "Fixture recon; no scans executed.")
        self.assertEqual(result["risk_level"], "LOW")
        for turn in seen[1:]:
            self.assertIn(PAGE, turn[-1]["content"])
            self.assertIn("Keep Python and OpenSSL updated", turn[-1]["content"])
        return seen

    def test_analysis_search_fetch_followup_and_new_analysis(self):
        os.environ["METATRON_SEARCH_PROVIDER"] = "parallel"
        os.environ["PARALLEL_API_KEY"] = "unused-ambient-credential"
        self.run_analysis()
        self.run_analysis()
        calls = [params for params, _ in self.calls()]
        ids = [call["arguments"]["session_id"] for call in calls]
        self.assertEqual(len(set(ids[:3])), 1)
        self.assertEqual(len(set(ids[3:])), 1)
        self.assertNotEqual(ids[0], ids[3])
        self.assertEqual([call["name"] for call in calls[:3]], ["web_search", "web_fetch", "web_search"])
        self.assertEqual(calls[1]["arguments"]["urls"], [PAGE])
        self.assertEqual(calls[0]["arguments"]["search_queries"], ["Python TLS mitigation guidance"])
        self.assert_transport()

    def test_concurrent_analyses_keep_separate_ids(self):
        os.environ["METATRON_SEARCH_PROVIDER"] = "parallel"
        state = threading.local()
        barrier = threading.Barrier(2)

        def model(messages):
            turn = getattr(state, "turn", 0)
            state.turn = turn + 1
            if turn == 0:
                barrier.wait(timeout=5)
                return "[SEARCH: Python TLS guidance]"
            self.assertIn(SOURCE, messages[-1]["content"])
            if turn == 1:
                return f"[SEARCH: {PAGE}]"
            return "RISK_LEVEL: LOW\nSUMMARY: Current TLS guidance retrieved."

        with patch("llm.ask_ollama", side_effect=model), ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(llm.analyse_target, "example.com", "Fixture") for _ in range(2)]
            for future in futures:
                self.assertEqual(future.result(timeout=10)["risk_level"], "LOW")
        ids_by_thread = {}
        for params, thread in self.calls():
            ids_by_thread.setdefault(thread, []).append(params["arguments"]["session_id"])
        self.assertEqual(len(ids_by_thread), 2)
        self.assertTrue(all(len(ids) == 2 and len(set(ids)) == 1 for ids in ids_by_thread.values()))
        self.assertEqual(len({ids[0] for ids in ids_by_thread.values()}), 2)

    def test_default_and_explicit_override_preserve_duckduckgo(self):
        ddgs = MagicMock()
        ddgs.return_value.__enter__.return_value.text.return_value = [
            {"title": "Python", "href": PAGE, "body": "TLS guidance"}
        ]
        with patch("search.DDGS", ddgs):
            self.assertIn(PAGE, llm.run_tool_calls([("SEARCH", "TLS guidance")]))
            os.environ["METATRON_SEARCH_PROVIDER"] = "parallel"
            self.assertIn(PAGE, llm.run_tool_calls(
                [("SEARCH", "TLS guidance")], SearchContext(provider="duckduckgo")
            ))
        self.assertEqual(ddgs.call_count, 2)
        self.assertFalse(self.requests)

    def test_provider_choice_is_captured_for_analysis(self):
        os.environ["METATRON_SEARCH_PROVIDER"] = "parallel"
        responses = iter(["[SEARCH: TLS guidance]", "RISK_LEVEL: LOW\nSUMMARY: Done."])

        def model(messages):
            os.environ["METATRON_SEARCH_PROVIDER"] = "none"
            return next(responses)

        with patch("llm.ask_ollama", side_effect=model):
            llm.analyse_target("example.com", "Fixture")
        self.assertEqual(len(self.calls()), 1)

    def test_disabled_and_invalid_provider_never_dispatch(self):
        with patch("search.web_search") as ddg, patch("search.fetch_page") as fetch:
            for provider, expected in [("none", "disabled"), ("unknown", "Unknown")]:
                os.environ["METATRON_SEARCH_PROVIDER"] = provider
                result = llm.run_tool_calls([("SEARCH", "CVE-2021-44228")])
                self.assertIn(expected, result)
            ddg.assert_not_called()
            fetch.assert_not_called()
        self.assertFalse(self.requests)

    def test_tool_error_and_retry_keep_context_without_fallback(self):
        os.environ["METATRON_SEARCH_PROVIDER"] = "parallel"
        context = SearchContext()
        self.tool_error = True
        with patch("search.DDGS") as ddg:
            result = llm.run_tool_calls([("SEARCH", "TLS guidance")], context)
            self.assertIn("Quota exceeded", result)
            self.tool_error = False
            self.assertIn(SOURCE, llm.run_tool_calls([("SEARCH", "TLS guidance")], context))
            ddg.assert_not_called()
        self.assertEqual({p["arguments"]["session_id"] for p, _ in self.calls()}, {context.session_id})

    def test_http_error_reaches_dispatcher(self):
        self.http_status = 401
        result = llm.run_tool_calls([("SEARCH", "TLS guidance")], SearchContext(provider="parallel"))
        self.assertIn("failed", result)
        self.assert_transport()

    def test_timeout_cancels_sdk_request(self):
        self.block = True
        with patch.object(parallel_search, "TIMEOUT_SECONDS", 0.1):
            result = llm.run_tool_calls([("SEARCH", "TLS guidance")], SearchContext(provider="parallel"))
        self.assertIn("timed out", result)
        self.assert_transport()

    def test_keyboard_interrupt_propagates_from_dispatcher(self):
        self.interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            llm.run_tool_calls([("SEARCH", "TLS guidance")], SearchContext(provider="parallel"))
        self.assert_transport()

    def test_missing_optional_sdk_has_actionable_error(self):
        with patch.dict("sys.modules", {"mcp": None}):
            result = handle_search_dispatch("TLS guidance", SearchContext(provider="parallel"))
        self.assertIn("requirements-parallel.txt", result)


if __name__ == "__main__":
    unittest.main()
