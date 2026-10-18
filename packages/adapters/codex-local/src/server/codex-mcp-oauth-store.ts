import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";

// Codex 0.163's file backend stores a map keyed by its computed MCP server key.
// The key is opaque here; server_name + server_url bind the credential to the
// configured endpoint. Never inspect or log token values outside these helpers.
type Entry = Record<string, unknown>;
type Store = Record<string, Entry>;
export type CodexMcpOauthBaseline = { key: string; digest: string; clientId: string; issuer: string | null } | null;
type StoreInput = { stablePath: string; runHome: string; serverName: string; serverUrl: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validEntry(value: unknown, name: string, url: string): value is Entry {
  if (!isRecord(value) || value.server_name !== name || value.server_url !== url) return false;
  if (typeof value.client_id !== "string" || !value.client_id.trim()) return false;
  if (typeof value.access_token !== "string" || !value.access_token.trim()) return false;
  if (value.refresh_token !== undefined && (typeof value.refresh_token !== "string" || !value.refresh_token.trim())) return false;
  if (value.issuer !== undefined && value.issuer !== null && typeof value.issuer !== "string") return false;
  if (value.expires_at !== undefined && value.expires_at !== null && (!Number.isSafeInteger(value.expires_at) || (value.expires_at as number) < 0)) return false;
  // Codex stores [] when a server omits `scope` from its OAuth response even
  // though the authorization request asked for mcp. Explicit grants for other
  // scopes are not accepted for this governed endpoint.
  if (!Array.isArray(value.scopes) || (value.scopes.length !== 0 && (value.scopes.length !== 1 || value.scopes[0] !== "mcp"))) return false;
  return true;
}

async function readStore(file: string): Promise<Store | null> {
  const stat = await fs.lstat(file).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  });
  if (!stat) return null;
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Codex MCP OAuth store must be a regular file");
  if ((stat.mode & 0o777) !== 0o600) await fs.chmod(file, 0o600);
  let parsed: unknown;
  try { parsed = JSON.parse(await fs.readFile(file, "utf8")); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error("Invalid Codex MCP OAuth store JSON");
    throw error;
  }
  if (!isRecord(parsed) || !Object.values(parsed).every(isRecord)) throw new Error("Invalid Codex MCP OAuth store");
  return parsed as Store;
}

function matching(store: Store | null, name: string, url: string): [string, Entry] | null {
  if (!store) return null;
  const entries = Object.entries(store).filter(([, value]) => value.server_name === name && value.server_url === url);
  if (entries.length > 1) throw new Error("Ambiguous Codex MCP OAuth credential");
  return entries[0] ?? null;
}

function digest(value: Entry): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function codexStoreKey(name: string, url: string): string {
  // Codex 0.163 oauth.rs compute_store_key / sha_256_prefix. serde_json's
  // object map is lexically ordered without preserve_order.
  const payload = JSON.stringify({ headers: {}, type: "http", url });
  return `${name}|${createHash("sha256").update(payload).digest("hex").slice(0, 16)}`;
}

async function ensurePrivateParent(file: string): Promise<void> {
  const parent = path.resolve(path.dirname(file));
  let cursor = path.parse(parent).root;
  for (const component of parent.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const stat = await fs.lstat(cursor).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    });
    if (stat?.isSymbolicLink()) throw new Error("Codex MCP OAuth store parent cannot be a symlink");
    if (stat && !stat.isDirectory()) throw new Error("Codex MCP OAuth store parent must be a directory");
    if (!stat) await fs.mkdir(cursor, { mode: 0o700 });
  }
  await fs.chmod(parent, 0o700);
}

/**
 * Codex 0.163 synchronizes aggregate-file reads and writes with an OS flock on
 * CODEX_HOME/mcp-oauth-locks/file-store.lock (oauth/store_lock.rs). The same
 * exclusive lock serializes our compare-and-swap writers with an operator's
 * `codex mcp login`; a second Paperclip lock would add a shorter competing
 * timeout without covering any additional writer.
 * The child holds flock until stdin closes after the callback. If flock cannot
 * start or times out, the callback never runs.
 */
async function withCodexFileStoreLock<T>(storePath: string, mode: "shared" | "exclusive", callback: () => Promise<T>): Promise<T> {
  const lockPath = path.join(path.dirname(storePath), "mcp-oauth-locks", "file-store.lock");
  await ensurePrivateParent(lockPath);
  const existing = await fs.lstat(lockPath).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  });
  if (existing && (!existing.isFile() || existing.isSymbolicLink())) throw new Error("Invalid Codex MCP OAuth lock file");
  if (!existing) {
    const handle = await fs.open(lockPath, "wx", 0o600).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return null;
      throw error;
    });
    await handle?.close();
  }
  await fs.chmod(lockPath, 0o600);

  const child = spawn("flock", [mode === "shared" ? "-s" : "-x", "-w", "60", "--", lockPath, "sh", "-c", "printf 'LOCKED\\n'; read -r _ || true"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const closed = new Promise<number | null>((resolve) => child.once("close", (code) => resolve(code)));
  const ready = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Codex MCP OAuth file-store lock timed out")), 65_000);
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      if (error) reject(error); else resolve();
    };
    child.once("error", () => finish(new Error("Codex MCP OAuth file-store lock unavailable")));
    child.once("exit", () => finish(new Error("Codex MCP OAuth file-store lock unavailable")));
    child.stdout?.once("data", (chunk: Buffer) => {
      if (chunk.toString("utf8").includes("LOCKED")) finish();
      else finish(new Error("Codex MCP OAuth file-store lock unavailable"));
    });
  });
  try {
    await ready;
    return await callback();
  } finally {
    child.stdin?.end();
    const code = await Promise.race([closed, new Promise<null>((resolve) => setTimeout(() => resolve(null), 1000))]);
    if (code === null) child.kill();
  }
}

async function writePrivateAtomic(file: string, value: Store): Promise<void> {
  const dir = path.dirname(file);
  await ensurePrivateParent(file);
  const temp = path.join(dir, `.credentials.json.${randomUUID()}.tmp`);
  try {
    await fs.writeFile(temp, JSON.stringify(value), { flag: "wx", mode: 0o600 });
    await fs.chmod(temp, 0o600);
    await fs.rename(temp, file);
  } finally {
    await fs.rm(temp, { force: true });
  }
}

/** Stage only one endpoint's credential into the run home; return its version. */
export async function stageCodexMcpOauthStore(input: StoreInput): Promise<CodexMcpOauthBaseline> {
  await ensurePrivateParent(input.stablePath);
  await ensurePrivateParent(path.join(input.runHome, ".credentials.json"));
  return withCodexFileStoreLock(input.stablePath, "shared", async () => {
    const store = await readStore(input.stablePath);
    const selected = matching(store, input.serverName, input.serverUrl);
    if (!selected) return null;
    const [key, value] = selected;
    if (key !== codexStoreKey(input.serverName, input.serverUrl) || !validEntry(value, input.serverName, input.serverUrl)) throw new Error("Invalid Codex MCP OAuth credential");
    await writePrivateAtomic(path.join(input.runHome, ".credentials.json"), { [key]: value });
    return { key, digest: digest(value), clientId: value.client_id as string, issuer: typeof value.issuer === "string" ? value.issuer : null };
  });
}

/**
 * Merge one run's changed credential back under Codex's file-store lock. A concurrent
 * writer that changed the stable entry wins: Codex refresh tokens rotate, so
 * overwriting a changed credential with a stale run snapshot is unsafe.
 */
export async function persistCodexMcpOauthStore(
  input: StoreInput & { baseline: CodexMcpOauthBaseline },
): Promise<"copied" | "unchanged" | "conflict" | "invalid"> {
  await ensurePrivateParent(input.stablePath);
  await ensurePrivateParent(path.join(input.runHome, ".credentials.json"));
  let run: Store | null;
  try { run = await readStore(path.join(input.runHome, ".credentials.json")); }
  catch (error) { if (error instanceof SyntaxError || (error as Error).message.startsWith("Invalid Codex MCP OAuth store")) return "invalid"; throw error; }
  const selected = matching(run, input.serverName, input.serverUrl);
  if (!selected) return run ? "invalid" : "unchanged";
  const [key, value] = selected;
  if (key !== codexStoreKey(input.serverName, input.serverUrl) || !validEntry(value, input.serverName, input.serverUrl)) return "invalid";
  if (input.baseline && (key !== input.baseline.key || value.client_id !== input.baseline.clientId || (value.issuer ?? null) !== input.baseline.issuer)) return "invalid";
  if (input.baseline?.digest === digest(value)) return "unchanged";

  return withCodexFileStoreLock(input.stablePath, "exclusive", async () => {
    const stable = await readStore(input.stablePath) ?? {};
    const current = matching(stable, input.serverName, input.serverUrl);
    if (input.baseline) {
      if (!current || current[0] !== input.baseline.key || digest(current[1]) !== input.baseline.digest) return "conflict";
    } else if (current || Object.hasOwn(stable, key)) {
      return "conflict";
    }
    stable[key] = value;
    await writePrivateAtomic(input.stablePath, stable);
    return "copied";
  });
}
