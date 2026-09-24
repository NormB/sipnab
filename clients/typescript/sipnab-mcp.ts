// snippet:start sipnab-mcp
// npm i @modelcontextprotocol/sdk
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "sipnab",
  args: ["--mcp", "-N", "-I", process.argv[2] ?? "capture.pcap", "--quiet"],
});

const client = new Client({ name: "sipnab-demo", version: "0.1" });
await client.connect(transport);

const tools = await client.listTools();
console.log(`${tools.tools.length} tools available`);

const result = await client.callTool({
  name: "find_problems",
  arguments: { kinds: ["nat-issues", "one-way"], limit: 20 },
});
console.log(JSON.stringify(result, null, 2));

await client.close();
// snippet:end sipnab-mcp
