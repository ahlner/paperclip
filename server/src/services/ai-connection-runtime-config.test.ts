import { describe, expect, it } from "vitest";
import { managedCodexProviderConfig, resolveManagedGitlabMcpStorePath } from "./ai-connection-runtime.js";

describe("managed Codex provider config", () => {
  it("enables only the approved GitLab MCP tools without replacing Paperclip AI auth storage", () => {
    const config = managedCodexProviderConfig();
    expect(config).toContain('cli_auth_credentials_store = "file"');
    expect(config).toContain('mcp_oauth_credentials_store = "file"');
    expect(config).toContain("[mcp_servers.gitlab_ingress]");
    expect(config).toContain('url = "https://gitlab.com/api/v4/mcp"');
    expect(config).toContain('auth = "oauth"');
    expect(config).toContain('scopes = ["mcp"]');
    const tools = "get_mcp_server_version,get_user,get_project,list_work_items,get_work_item,list_merge_requests,get_merge_request";
    expect(config).toContain(`X-Gitlab-Enabled-Mcp-Server-Tools = "${tools}"`);
    expect(config).toContain(`enabled_tools = [${tools.split(",").map((tool) => `"${tool}"`).join(", ")}]`);
    expect(config).not.toContain("access_token");
  });

  it("separates the persistent MCP store by company, responsible user, agent, and server", () => {
    const a = resolveManagedGitlabMcpStorePath("company-a", "alice", "agent-a");
    expect(a).toContain("gitlab_ingress");
    expect(a).not.toBe(resolveManagedGitlabMcpStorePath("company-a", "alice", "agent-b"));
    expect(a).not.toBe(resolveManagedGitlabMcpStorePath("company-a", "bob", "agent-a"));
    expect(a).not.toBe(resolveManagedGitlabMcpStorePath("company-b", "alice", "agent-a"));
    expect(a).not.toContain("auth.json");
  });
});
