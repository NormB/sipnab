# snippet:start sipnab-mcp
"""Minimal MCP client driving sipnab over stdio."""
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(pcap: str) -> None:
    params = StdioServerParameters(
        command="sipnab",
        args=["--mcp", "-N", "-I", pcap, "--quiet"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"{t.name:20s}  {t.description[:60]}")

            # 2. Find one-way audio + late-media problems
            res = await session.call_tool(
                "find_problems",
                {"kinds": ["one-way", "late-media"], "limit": 50},
            )
            for content in res.content:
                if content.type == "text":
                    print(content.text[:500])


if __name__ == "__main__":
    import sys
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"))
# snippet:end sipnab-mcp
