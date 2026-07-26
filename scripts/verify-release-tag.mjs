import { appendFile, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const STABLE_SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

export function verifyReleaseTag(packageVersion, refName) {
  if (!STABLE_SEMVER.test(packageVersion)) {
    throw new Error(`Refusing OIDC publication for non-stable package version ${packageVersion}`);
  }
  if (refName !== `v${packageVersion}`) {
    throw new Error(`Release tag ${refName || "<missing>"} does not match stable package version v${packageVersion}`);
  }
  return packageVersion;
}

async function main() {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const version = verifyReleaseTag(packageJson.version, process.env.GITHUB_REF_NAME);
  if (!process.env.GITHUB_OUTPUT) {
    throw new Error("GITHUB_OUTPUT is required");
  }
  await appendFile(process.env.GITHUB_OUTPUT, `version=${version}\n`, "utf8");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
