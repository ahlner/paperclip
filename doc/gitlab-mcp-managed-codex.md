# Managed Codex GitLab MCP login

For an OpenAI managed AI connection run with `codex_local`, Paperclip creates a
private, stable GitLab MCP home. It is scoped to the company, responsible human,
agent, and `gitlab_ingress` endpoint. It contains `config.toml` and, after login,
Codex's separate `.credentials.json`. The AI subscription's `auth.json` stays in
the temporary run home. The temporary home is removed after the run.

After deploying this change, start one authorized managed Codex run to provision
the stable home. An operator on the Paperclip host can then derive its path with
the exact company, responsible-user, agent, and instance IDs used by that run:

```sh
INSTANCE_ROOT=/path/to/paperclip/instance
COMPANY_ID=...
RESPONSIBLE_USER_ID=...
AGENT_ID=...
MCP_HOME=$(node - "$INSTANCE_ROOT" "$COMPANY_ID" "$RESPONSIBLE_USER_ID" "$AGENT_ID" <<'NODE'
const path = require('node:path');
const { createHash } = require('node:crypto');
const [root, companyId, userId, agentId] = process.argv.slice(2);
const key = createHash('sha256')
  .update(JSON.stringify([companyId, userId, agentId, 'gitlab_ingress', 'https://gitlab.com/api/v4/mcp']))
  .digest('hex');
process.stdout.write(path.join(root, 'secrets', 'mcp-oauth', key, 'gitlab_ingress'));
NODE
)
test -f "$MCP_HOME/config.toml"
CODEX_HOME="$MCP_HOME" codex mcp login gitlab_ingress --no-browser --scopes mcp
```

Give the printed authorization URL to the responsible human through a private
channel. Enter the callback URL/code only in the hidden host prompt. Do not put
credentials or callback codes in an issue, repository, run log, or task comment.
Keep the stable home owned by the Paperclip server user with directory mode
`0700` and credential file mode `0600`. The Linux host needs util-linux `flock`
for a write-back coordinated with Codex's own file-store lock. Repeat login
separately for another responsible user or agent.

After login, start a new run and verify read-only calls: MCP server version,
own user, six project IDs, and issue/MR/note reads with pagination. The glab
monitor remains active; switching it, merging, releasing, or deploying needs
separate approval.

The OAuth store uses an atomic compare-and-merge under Codex's file-store lock. A run
stages only the matching GitLab entry. A changed stable entry wins over an older
parallel run snapshot; a malformed or incomplete entry is discarded. Cleanup
reports only a status and never credential bytes.
