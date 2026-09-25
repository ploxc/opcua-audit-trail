# Users and roles

Roles are cumulative: **auditor** < **operator** < **admin**.

- **auditor:** reads the audit trail, status and settings.
- **operator:** also discovers targets and uses the OPC UA browser.
- **admin:** changes the configuration, certificates and users.

Admins manage users on the **Users** page. A password an admin sets must be
changed by the user at the next login. The first user, `admin`, is created
at the first start (see [First login](first-login.md)).

## Command line

```sh
opcua-audit-gateway user list
opcua-audit-gateway user add <name> --role operator
opcua-audit-gateway user passwd <name>      # also to reset a lost admin password
opcua-audit-gateway user role <name> admin
opcua-audit-gateway user delete <name>
```

Use the same `--config` as the gateway. `user passwd admin` also creates the
admin if the gateway has not run yet.

## Sessions and logins

- Changing a password, a role or removing a user ends that user's sessions.
  Sessions also expire after 8 hours idle and 24 hours in total.
- Failed logins are rate limited per address and per user; while a user is
  blocked, only the right password still gets in.
- Behind a reverse proxy, set `trusted_proxies = ["<proxy address>"]` under
  `[web]`, so the limit applies per client (from `X-Forwarded-For`), not to
  everyone at once.

## API tokens

Each user creates API tokens for AI assistants on the **Account** page; see
[AI assistants](ai-assistants.md).
