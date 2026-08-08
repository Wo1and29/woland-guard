// Reads the actual monorepo tree so the landing page's stats never drift
// from reality the way hand-typed numbers eventually do. Run before every
// build (see package.json). No external deps: this is just recursive
// directory walking and line counting.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");

function countLines(dir, extension) {
  let total = 0;
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return 0;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    const info = statSync(full);
    if (info.isDirectory()) {
      if (entry === "__pycache__") continue;
      total += countLines(full, extension);
    } else if (entry.endsWith(extension)) {
      total += readFileSync(full, "utf8").split("\n").length;
    }
  }
  return total;
}

const productionDirs = [
  "apps/agent/src",
  "apps/control-plane/src",
  "packages/contracts/src",
].map((p) => join(repoRoot, p));

const testsDir = join(repoRoot, "tests");
const adrDir = join(repoRoot, "docs", "adr");

const linesProduction = productionDirs.reduce((sum, dir) => sum + countLines(dir, ".py"), 0);
const linesTests = countLines(testsDir, ".py");
const adrCount = readdirSync(adrDir).filter((f) => f.endsWith(".md")).length;

const stats = { linesProduction, linesTests, adrCount, generatedAt: new Date().toISOString() };
writeFileSync(resolve(import.meta.dirname, "..", "src", "stats.generated.json"), JSON.stringify(stats, null, 2) + "\n");
console.log("stats:", stats);
