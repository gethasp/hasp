import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const { createAgentSession, DefaultResourceLoader, SessionManager, SettingsManager } =
  await import(pathToFileURL(process.argv[2]).href);
const cwd = process.cwd();
const agentDir = process.env.PI_CODING_AGENT_DIR;
const settingsManager = SettingsManager.create(cwd, agentDir);
const resourceLoader = new DefaultResourceLoader({
  cwd, agentDir, settingsManager,
  noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
});
await resourceLoader.reload();
assert.equal(resourceLoader.getExtensions().errors.length, 0, "extension failed to load");
const { session } = await createAgentSession({
  cwd, agentDir, settingsManager, resourceLoader,
  sessionManager: SessionManager.inMemory(cwd),
});
const outputs = [];
try {
  await session.bindExtensions({});
  const actions = JSON.parse(await readFile(process.argv[3], "utf8"));
  for (const [name, args] of actions) {
    if (name === "grant") {
      const response = await fetch(`${process.env.HASP_FIXTURE_URL}/fixture/approve`, {
        method: "POST",
        body: JSON.stringify({ key: process.env.HASP_FIXTURE_APPROVAL_KEY }),
      });
      assert.equal(response.status, 200, "fixture operator grant failed");
      continue;
    }
    const tool = session.agent.state.tools.find(t => t.name === (name === "shell" ? "bash" : name));
    assert(tool, `missing real Pi tool: ${name}`);
    let output;
    try {
      output = await tool.execute(`replay-${outputs.length}`, args, new AbortController().signal, () => {});
    } catch (error) {
      output = String(error);
    }
    outputs.push({ name, output });
  }
  // The parent captures these synthetic results and prints only check names.
  console.log(JSON.stringify(outputs));
} finally {
  session.dispose();
}
