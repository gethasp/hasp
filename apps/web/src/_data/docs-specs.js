import fs from "node:fs";

const catalog = JSON.parse(fs.readFileSync(new URL("./docs-specs.json", import.meta.url), "utf8"));

export const docsUpdated = catalog.docsUpdated;
export const docSpecs = catalog.docSpecs;
