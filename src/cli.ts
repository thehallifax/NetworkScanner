import { runScan } from "./scan/runScan.js";

function parseArgs(argv: string[]) {
  const args = new Map<string, string | boolean>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        args.set(key, next);
        i += 1;
      } else {
        args.set(key, true);
      }
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = args.get("source");
  if (source !== "meraki") {
    console.error("Unsupported source. Use --source meraki.");
    process.exit(1);
  }
  const emitRaw = args.get("emit-raw") === true;
  const result = await runScan({ source: "meraki", emitRaw });
  console.log(JSON.stringify(result.summary, null, 2));
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
