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

Use the same `--config` as the gateway. A user that does not exist is
reported before any password is asked, with the path of the user database,
so a command run against the wrong config is noticed at once. `user passwd
admin` also creates the admin if the gateway has not run yet.

## Sessions and logins

- Changing a password, a role or removing a user ends that user's sessions.
  Sessions also expire after 8 hours idle and 24 hours in total.
- Failed logins are rate limited per address and per user; while a user is
  blocked, only the right password still gets in.
- Behind a reverse proxy, set `trusted_proxies = ["<proxy address>"]` under
  `[web]`, so the limit applies per client (from `X-Forwarded-For`), not to
  everyone at once.

## API tokens

Each user can create API tokens for AI assistants on the **Account** page;
admins see and revoke everyone's on the **Users** page. Resetting a user's
password or deleting the user deletes their tokens. See
[AI assistants](ai-assistants.md).
