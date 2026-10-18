import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import { resolvePaperclipInstanceRootForAdapter } from "@paperclipai/adapter-utils/server-utils";
import { persistCodexMcpOauthStore, stageCodexMcpOauthStore } from "./codex-mcp-oauth-store.js";

const serverName = "gitlab_ingress";
const serverUrl = "https://gitlab.example/api/v4/mcp";
const key = `${serverName}|${createHash("sha256").update(JSON.stringify({ headers: {}, type: "http", url: serverUrl })).digest("hex").slice(0, 16)}`;
const entry = (token: string) => ({ server_name: serverName, server_url: serverUrl, client_id: "client", access_token: token, refresh_token: `refresh-${token}`, expires_at: 1234, scopes: ["mcp"] });
const dirs: string[] = [];

async function fixture() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "codex-mcp-store-test-"));
  dirs.push(root);
  const stablePath = path.join(root, "stable", ".credentials.json");
  const runHome = path.join(root, "run");
  await fs.mkdir(path.dirname(stablePath), { recursive: true });
  await fs.mkdir(runHome);
  await fs.writeFile(stablePath, JSON.stringify({ [key]: entry("old"), "other|1234567890abcdef": { server_name: "other", server_url: "https://other.example/mcp", client_id: "other", access_token: "other-secret" } }), { mode: 0o600 });
  return { stablePath, runHome };
}

afterEach(async () => { for (const dir of dirs.splice(0)) await fs.rm(dir, { recursive: true, force: true }); });

describe("Codex MCP OAuth file store", () => {
  it("stages only the requested server entry with private permissions", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    expect(baseline).not.toBeNull();
    const staged = JSON.parse(await fs.readFile(path.join(paths.runHome, ".credentials.json"), "utf8"));
    expect(Object.keys(staged)).toEqual([key]);
    expect((await fs.stat(path.join(paths.runHome, ".credentials.json"))).mode & 0o777).toBe(0o600);
  });

  it("persists a refreshed token without dropping other server entries", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ [key]: entry("new") }));
    expect(await persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline })).toBe("copied");
    const stable = JSON.parse(await fs.readFile(paths.stablePath, "utf8"));
    expect(stable[key].access_token).toBe("new");
    expect(stable["other|1234567890abcdef"].access_token).toBe("other-secret");
    expect((await fs.stat(paths.stablePath)).mode & 0o777).toBe(0o600);
  });

  it("keeps a concurrent newer stable credential", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    await fs.writeFile(paths.stablePath, JSON.stringify({ [key]: entry("winner") }));
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ [key]: entry("loser") }));
    expect(await persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline })).toBe("conflict");
    expect(JSON.parse(await fs.readFile(paths.stablePath, "utf8"))[key].access_token).toBe("winner");
  });

  it("refuses malformed or wrong-server run credentials", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ [key]: { server_name: "other", server_url: "https://other.example", access_token: "bad" } }));
    expect(await persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline })).toBe("invalid");
    expect(JSON.parse(await fs.readFile(paths.stablePath, "utf8"))[key].access_token).toBe("old");
  });

  it("rejects ambiguous run credentials without changing the stable store", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    const stableBefore = await fs.readFile(paths.stablePath, "utf8");
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({
      [key]: entry("new"),
      "duplicate|1234567890abcdef": entry("duplicate"),
    }));
    await expect(persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline })).resolves.toBe("invalid");
    expect(await fs.readFile(paths.stablePath, "utf8")).toBe(stableBefore);
  });

  it("rejects a forged key even when the entry claims the GitLab endpoint", async () => {
    const paths = await fixture();
    await fs.rm(paths.stablePath);
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    expect(baseline).toBeNull();
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ "forged|1234567890abcdef": entry("forged") }));
    expect(await persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline })).toBe("invalid");
  });

  it("tightens an existing stable directory before writing a credential", async () => {
    const paths = await fixture();
    await fs.chmod(path.dirname(paths.stablePath), 0o755);
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ [key]: entry("new") }));
    await persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline });
    expect((await fs.stat(path.dirname(paths.stablePath))).mode & 0o777).toBe(0o700);
  });

  it("tightens an existing stable credential before staging", async () => {
    const paths = await fixture();
    await fs.chmod(paths.stablePath, 0o644);
    await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    expect((await fs.stat(paths.stablePath)).mode & 0o777).toBe(0o600);
  });

  it("refuses a symlinked stable parent", async () => {
    const paths = await fixture();
    const real = path.dirname(paths.stablePath);
    const symlink = path.join(path.dirname(real), "linked");
    await fs.symlink(real, symlink);
    await expect(stageCodexMcpOauthStore({ stablePath: path.join(symlink, ".credentials.json"), runHome: paths.runHome, serverName, serverUrl })).rejects.toThrow();
  });

  it("does not expose malformed credential bytes through parse errors", async () => {
    const paths = await fixture();
    await fs.writeFile(paths.stablePath, 'tokenseed');
    let message = "";
    try {
      await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toBeTruthy();
    expect(message).not.toContain("tokenseed");
  });

  it("allows an empty serialized scope list when the server omits the scope response", async () => {
    const paths = await fixture();
    await fs.writeFile(paths.stablePath, JSON.stringify({ [key]: { ...entry("unscoped"), scopes: [] } }));
    await expect(stageCodexMcpOauthStore({ ...paths, serverName, serverUrl })).resolves.not.toBeNull();
  });

  it("rejects an explicit non-mcp scope", async () => {
    const paths = await fixture();
    await fs.writeFile(paths.stablePath, JSON.stringify({ [key]: { ...entry("wrong-scope"), scopes: ["api"] } }));
    await expect(stageCodexMcpOauthStore({ ...paths, serverName, serverUrl })).rejects.toThrow("Invalid Codex MCP OAuth credential");
  });

  it("waits for Codex's external file-store lock before merging a refresh", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ [key]: entry("after") }));
    const lockDir = path.join(path.dirname(paths.stablePath), "mcp-oauth-locks");
    await fs.mkdir(lockDir, { recursive: true, mode: 0o700 });
    const lockPath = path.join(lockDir, "file-store.lock");
    const holder = spawn("flock", ["-x", "--", lockPath, "sh", "-c", "echo LOCKED; sleep 2"], { stdio: ["pipe", "pipe", "pipe"] });
    const exited = once(holder, "exit");
    try {
      await Promise.race([once(holder.stdout!, "data"), new Promise((_, reject) => setTimeout(() => reject(new Error("external lock holder did not start")), 2000))]);
      let finished = false;
      const merge = persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline }).then((result) => { finished = true; return result; });
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(finished).toBe(false);
      expect(await merge).toBe("copied");
    } finally {
      await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 1000))]);
      if (holder.exitCode === null) holder.kill();
    }
  }, 10_000);

  it("merges using Codex's lock when the unrelated Paperclip lock root is unavailable", async () => {
    const paths = await fixture();
    const baseline = await stageCodexMcpOauthStore({ ...paths, serverName, serverUrl });
    await fs.writeFile(path.join(paths.runHome, ".credentials.json"), JSON.stringify({ [key]: entry("after") }));
    const previousHome = process.env.PAPERCLIP_HOME;
    const previousInstance = process.env.PAPERCLIP_INSTANCE_ID;
    const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-lock-isolated-"));
    dirs.push(isolatedHome);
    try {
      process.env.PAPERCLIP_HOME = isolatedHome;
      process.env.PAPERCLIP_INSTANCE_ID = "test-instance";
      const instanceRoot = resolvePaperclipInstanceRootForAdapter({ homeDir: isolatedHome, instanceId: "test-instance", env: process.env });
      await fs.mkdir(path.join(instanceRoot, "locks"), { recursive: true });
      await fs.writeFile(path.join(instanceRoot, "locks", "directory-merge"), "not a directory");
      expect(await persistCodexMcpOauthStore({ ...paths, serverName, serverUrl, baseline })).toBe("copied");
    } finally {
      if (previousHome === undefined) delete process.env.PAPERCLIP_HOME; else process.env.PAPERCLIP_HOME = previousHome;
      if (previousInstance === undefined) delete process.env.PAPERCLIP_INSTANCE_ID; else process.env.PAPERCLIP_INSTANCE_ID = previousInstance;
    }
  });
});
