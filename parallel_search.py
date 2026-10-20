"""Optional anonymous Parallel Search MCP transport for the SEARCH dispatcher."""

import asyncio
from datetime import timedelta
from urllib.parse import urlsplit


MCP_URL = "https://search.parallel.ai/mcp"
USER_AGENT = "METATRON (+https://github.com/sooryathejas/METATRON)"
TIMEOUT_SECONDS = 30


def _error_text(error: Exception) -> str:
    """Expose the actionable cause wrapped by the SDK's task groups."""
    children = getattr(error, "exceptions", ())
    return "; ".join(_error_text(child) for child in children) if children else str(error)


async def _call_tool(name: str, arguments: dict) -> str:
    # Keep the SDK optional: the default DuckDuckGo installation is unchanged.
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(TIMEOUT_SECONDS),
        follow_redirects=False,
    ) as client:
        async with streamable_http_client(MCP_URL, http_client=client) as streams:
            async with ClientSession(
                streams[0], streams[1],
                read_timeout_seconds=timedelta(seconds=TIMEOUT_SECONDS),
            ) as session:
                await session.initialize()
                tools = await session.list_tools()
                if name not in {tool.name for tool in tools.tools}:
                    raise ValueError(f"Parallel MCP does not advertise {name}.")
                result = await session.call_tool(name, arguments)
                text = "\n".join(
                    block.text for block in result.content if block.type == "text"
                )
                if result.isError:
                    raise ValueError(text or "Parallel MCP tool returned an error.")
                return text or "[!] No text results returned by Parallel MCP."


def dispatch(query: str, session_id: str) -> str:
    """Search, or fetch a complete HTTP(S) URL, within the caller's analysis."""
    if not query:
        return "[!] Search query is empty."
    try:
        url = urlsplit(query)
        is_url = url.scheme.lower() in ("http", "https") and bool(url.netloc) and not any(
            char.isspace() for char in query
        )
        if is_url:
            name = "web_fetch"
            arguments = {"urls": [query], "session_id": session_id}
        else:
            name = "web_search"
            arguments = {
                "objective": query,
                "search_queries": [query],
                "session_id": session_id,
            }

        async def run():
            return await asyncio.wait_for(
                _call_tool(name, arguments), timeout=TIMEOUT_SECONDS
            )

        text = asyncio.run(run())
        return f"[PARALLEL {name.upper()} RESULTS FOR: {query}]\n{text}"
    except ImportError:
        return "[!] Parallel requires Python 3.10+ and: pip install -r requirements-parallel.txt"
    except (asyncio.TimeoutError, TimeoutError):
        return "[!] Parallel search/fetch timed out."
    except Exception as exc:
        # Never silently switch providers after an explicit selection fails.
        return f"[!] Parallel search/fetch failed: {_error_text(exc)}"
