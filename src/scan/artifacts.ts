import fs from "fs";
import path from "path";
import { ScanResults } from "../types.js";

export type ArtifactPaths = {
  resultsPath: string;
  rawPath?: string;
};

type ArtifactOptions = {
  outputDir?: string;
  raw?: unknown;
};

export function writeScanArtifacts(results: ScanResults, options: ArtifactOptions = {}): ArtifactPaths {
  const baseDir = options.outputDir ?? path.resolve(process.cwd(), "artifacts");
  const scanDir = path.join(baseDir, `scan-${results.metadata.id}`);
  fs.mkdirSync(scanDir, { recursive: true });

  const resultsPath = path.join(scanDir, "results.json");
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));

  let rawPath: string | undefined;
  if (options.raw !== undefined) {
    rawPath = path.join(scanDir, "raw.json");
    fs.writeFileSync(rawPath, JSON.stringify(options.raw, null, 2));
  }

  return { resultsPath, rawPath };
}
