import { spawn } from "node:child_process";

const HASP_MCP_COMMAND = __HASP_MCP_COMMAND__;
const HASP_AGENT_ID = __HASP_AGENT_ID__;
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

// One transport retains the broker's project sessions. A failed call is never
// replayed: the child may already have performed the requested operation.
class Bridge {
  constructor() {
    this.connection = undefined;
    this.lastError = undefined;
  }

  async connect(cwd) {
    if (this.connection) return this.connection.ready;
    const child = spawn(HASP_MCP_COMMAND, [], {
      cwd: cwd || process.cwd(), env: process.env, stdio: ["pipe", "pipe", "pipe"],
    });
    const connection = { child, pending: new Map(), nextID: 0, buffer: "", closed: false };
    connection.refs = (active) => {
      for (const handle of [child, child.stdin, child.stdout, child.stderr]) {
        if (active) handle.ref?.();
        else handle.unref?.();
      }
    };
    this.connection = connection;
    const fail = (message) => {
      if (connection.closed) return;
      connection.closed = true;
      if (this.connection === connection) this.connection = undefined;
      this.lastError = message;
      child.kill();
      for (const pending of connection.pending.values()) pending.reject(new Error(message));
      connection.pending.clear();
    };
    connection.fail = fail;
    const lost = "HASP MCP connection ended. Pending command outcomes are unknown; do not repeat a command without checking its effects. Recover long commands with hasp_job_status and their original request_id.";
    child.on("error", () => fail("HASP MCP could not start. Re-run hasp agent connect pi and check the managed wrapper."));
    child.on("exit", () => fail(lost));
    child.stdin.on("error", () => fail(lost));
    child.stdout.on("error", () => fail(lost));
    child.stdout.on("end", () => fail(lost));
    // Drain diagnostics without retaining or exposing potentially sensitive text.
    child.stderr.resume();
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      connection.buffer += chunk;
      for (;;) {
        const end = connection.buffer.indexOf("\n");
        if (end < 0) break;
        const line = connection.buffer.slice(0, end);
        connection.buffer = connection.buffer.slice(end + 1);
        if (Buffer.byteLength(line) > MAX_MESSAGE_BYTES) return fail("HASP MCP response exceeded the 8 MiB limit; command outcome is unknown.");
        if (!line.trim()) continue;
        let response;
        try { response = JSON.parse(line); }
        catch { return fail("HASP MCP returned invalid JSON; command outcome is unknown."); }
        const pending = connection.pending.get(response.id);
        if (!pending) continue;
        connection.pending.delete(response.id);
        // SDK disposal need not emit session_shutdown. An idle bridge must not
        // hold the host open; the exit listener still terminates its MCP child.
        if (connection.pending.size === 0) connection.refs(false);
        if (response.error) pending.reject(new Error(JSON.stringify(response.error)));
        else pending.resolve(response.result);
      }
      if (Buffer.byteLength(connection.buffer) > MAX_MESSAGE_BYTES) fail("HASP MCP response exceeded the 8 MiB limit; command outcome is unknown.");
    });
    connection.ready = this.request(connection, "initialize", {
      protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "pi", version: "hasp-bridge-2" },
    }).then(() => {
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      this.lastError = undefined;
      return connection;
    });
    const timeout = setTimeout(() => fail("HASP MCP initialization timed out. Re-run hasp agent connect pi and check the managed wrapper."), 30000);
    connection.ready.then(() => clearTimeout(timeout), () => clearTimeout(timeout));
    return connection.ready;
  }

  request(connection, method, params, signal) {
    if (signal?.aborted) return Promise.reject(new Error("HASP call cancelled before sending."));
    if (connection.closed) return Promise.reject(new Error("HASP MCP connection is closed."));
    const id = ++connection.nextID;
    const abort = () => connection.fail("HASP call cancelled after sending; command outcome is unknown. Check its effects or use hasp_job_status before repeating it.");
    return new Promise((resolve, reject) => {
      connection.refs(true);
      const cleanup = () => signal?.removeEventListener("abort", abort);
      connection.pending.set(id, {
        resolve: (value) => { cleanup(); resolve(value); },
        reject: (error) => { cleanup(); reject(error); },
      });
      signal?.addEventListener("abort", abort, { once: true });
      connection.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  async call(method, params, cwd, signal) {
    if (signal?.aborted) throw new Error("HASP call cancelled before sending.");
    return this.request(await this.connect(cwd), method, params, signal);
  }

  close() {
    this.connection?.fail("HASP extension stopped; pending command outcomes are unknown.");
  }
}

export default async function haspPiExtension(pi) {
  // The MCP child cannot protect sibling shell tools. This parent guard is
  // inherited by Pi's ordinary children; daemon identity requires agent launch.
  process.env.HASP_AGENT_SAFE_MODE = "1";
  const bridge = new Bridge();
  const close = () => bridge.close();
  process.once("exit", close);
  pi.on("session_shutdown", () => { close(); process.removeListener("exit", close); });
  pi.registerTool({
    name: "hasp_status", label: "HASP status",
    description: "Report this Pi extension's MCP connection and inherited shell guard. Use hasp agent status pi from Bash to inspect daemon-backed process protection.",
    parameters: { type: "object", properties: {}, additionalProperties: false },
    async execute() {
      const details = {
        agent_id: HASP_AGENT_ID, extension: "loaded", connection: bridge.connection ? "connected" : "disconnected",
        shell_guard: process.env.HASP_AGENT_SAFE_MODE === "1" ? "inherited_environment" : "missing",
        process_protection: "not_checked", error: bridge.lastError,
        protected_launch: "hasp agent launch pi -- pi",
      };
      return { content: [{ type: "text", text: JSON.stringify(details) }], details };
    },
  });
  let tools;
  try {
    const result = await bridge.call("tools/list");
    if (!Array.isArray(result?.tools)) throw new Error("HASP MCP tools/list returned no tools array.");
    tools = result.tools;
  } catch (error) {
    bridge.close();
    bridge.lastError = error instanceof Error ? error.message : String(error);
    return;
  }
  for (const tool of tools) {
    if (tool.name === "hasp_status") continue;
    pi.registerTool({
      name: tool.name, label: tool.title || tool.name,
      description: tool.description || `HASP MCP tool ${tool.name}`,
      parameters: tool.inputSchema || { type: "object", properties: {}, additionalProperties: true },
      async execute(_id, params, signal, _onUpdate, ctx) {
        const args = { ...params };
        if (tool.inputSchema?.properties?.project_root && !args.project_root) args.project_root = ctx?.cwd || process.cwd();
        const result = await bridge.call("tools/call", { name: tool.name, arguments: args }, ctx?.cwd, signal);
        // Pi marks a tool error by a thrown exception. Keep partial scan data.
        if (result?.isError) throw new Error(JSON.stringify(result));
        const content = Array.isArray(result?.content) && result.content.length ? result.content : [{ type: "text", text: JSON.stringify(result) }];
        return { content, details: result };
      },
    });
  }
}
