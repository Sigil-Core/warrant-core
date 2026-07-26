import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import { verifyReleaseTag } from "../scripts/verify-release-tag.mjs";

interface WorkflowStep {
  id?: string;
  name?: string;
  run?: string;
  if?: string;
  "continue-on-error"?: boolean;
}

interface WorkflowJob {
  needs?: string | string[];
  steps?: WorkflowStep[];
  "continue-on-error"?: boolean;
}

interface PublishWorkflow {
  concurrency?: { queue?: string };
  jobs?: Record<string, WorkflowJob>;
}

const publishWorkflow = parse(
  readFileSync(new URL("../.github/workflows/publish.yml", import.meta.url), "utf8"),
) as PublishWorkflow;

function executableSteps(job: WorkflowJob): Array<WorkflowStep & { run: string }> {
  return (job.steps ?? []).filter((step): step is WorkflowStep & { run: string } => typeof step.run === "string");
}

describe("npm release workflow", () => {
  it("accepts only an exact stable v<package version> tag", () => {
    expect(verifyReleaseTag("0.1.0", "v0.1.0")).toBe("0.1.0");
    expect(verifyReleaseTag("12.34.56", "v12.34.56")).toBe("12.34.56");
  });

  it.each([
    ["0.1.0-rc.0", "v0.1.0-rc.0"],
    ["0.1.0+build.1", "v0.1.0+build.1"],
    ["01.2.3", "v01.2.3"],
    ["1.2", "v1.2"],
    ["1.2.3", "v1.2.4"],
    ["1.2.3", "bootstrap-1.2.3"],
  ])("rejects package version %s with release ref %s", (packageVersion, refName) => {
    expect(() => verifyReleaseTag(packageVersion, refName)).toThrow();
  });

  it("keeps stable-tag, immutable-version, and trusted-publishing gates in the workflow", () => {
    const verifyTag = publishWorkflow.jobs?.["verify-tag"];
    const publish = publishWorkflow.jobs?.publish;
    expect(verifyTag).toBeDefined();
    expect(publish).toBeDefined();
    if (!verifyTag || !publish) throw new Error("Publish workflow jobs are missing");

    const versionStep = executableSteps(verifyTag).find((step) => step.id === "version");
    expect(versionStep?.run.trim()).toBe("node scripts/verify-release-tag.mjs");
    expect(verifyTag["continue-on-error"]).not.toBe(true);
    expect(versionStep?.["continue-on-error"]).not.toBe(true);

    const dependencies = Array.isArray(publish.needs) ? publish.needs : [publish.needs];
    expect(dependencies).toContain("verify-tag");

    const publishSteps = executableSteps(publish);
    const immutableIndex = publishSteps.findIndex((step) => step.name === "Refuse to republish an immutable npm version");
    const publishIndex = publishSteps.findIndex((step) => step.name === "Publish with npm trusted publishing");
    expect(immutableIndex).toBeGreaterThanOrEqual(0);
    expect(publishIndex).toBeGreaterThan(immutableIndex);

    const immutableStep = publishSteps[immutableIndex]!;
    const npmPublishStep = publishSteps[publishIndex]!;
    expect(immutableStep.run).toContain("npm view \"$package_name@$package_version\" version");
    expect(immutableStep.run).toContain("exit 1");
    expect(publish["continue-on-error"]).not.toBe(true);
    for (const step of publishSteps.slice(immutableIndex, publishIndex + 1)) {
      expect(step["continue-on-error"]).not.toBe(true);
    }
    expect(npmPublishStep.if).toBeUndefined();
    expect(npmPublishStep.run).toMatch(/\bnpm\s+publish\b/);
    expect(npmPublishStep.run).toContain("--access public");
    expect(npmPublishStep.run).toContain("--provenance");
    expect(publishWorkflow.concurrency?.queue).toBe("max");
  });
});
