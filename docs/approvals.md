# Approvals: changes an agent cannot make alone

agensio's control plane lets an AI agent manage the server through its MCP tools, and lets scripts and
people do the same with `agensio ctl`. Some changes are dangerous enough that no agent may make them on
its own word, whatever it was told and whatever it read: a change that can run code on the server, move
a secret or data off the host, grant access, or destroy something that cannot be restored. Such a change
is not made when it is asked for. The server stores it, says so, and runs it only after a person approves
it with a code from an authenticator app on their phone.

The code is what no agent holds. An agent misled by text it read on a web page, in a site's file, in a
log or in a tool's answer (a prompt injection) can ask for anything, and can even run `agensio ctl` in a
shell on the server, but it cannot produce the six digits your phone shows. And what you approve is the
change the server stored when it was asked for, described by the server itself: nothing can alter it
after it was queued.

## 1. What waits for approval

| change | since |
|---|---|
| `site_task` `pip_install` (`agensio ctl site-task NAME pip_install --param packages=...`): installs Python packages the caller names into a site's virtualenv, so their code runs as the site's account | 0.1.0-alpha.120 |
| every change to a site's files: `site_file_write`, `site_file_edit`, `site_dir_create`, `site_path_move`, `site_path_delete`, `site_file_restore` (`agensio ctl site-file-write`, ...); what waits shows the diff and what the site does with the path (served as a file, or RUNS as a script); a credential file's diff shows its names and each value's length, never a value, context lines included | 0.1.0-alpha.120 |
| reading a credential or database file of a site (`site_file_read` of `.env`, `wp-config.php`, `*.key`, `*.pem`, `.git/`, a SQLite file): its content would leave the server for whoever asked; once approved, it is handed out once (`approvals_list` with the id) | 0.1.0-alpha.120 |
| `site_install` from any source, and `site_copy`: files the site then serves or runs; the preview names the source, the target and what the install creates | 0.1.0-alpha.120 |
| the site's environment: `site_env_set` (the preview names the variables, never a value) and `site_env` with `reveal` (the values are handed out once, by id) | 0.1.0-alpha.120 |
| a `site_update` that makes other files run (`app`, `root`, `served_dir`, `rules.entry_points`, `rules.front_controller`), sends visitors elsewhere (`upstream`, a redirect to a host that is none of the site's names) or removes or widens a password or address rule (a rule gone, an allow list or `skip_for` grown, `open`, report mode, the password over plain HTTP); the preview is the managed file's diff. A `site_create` whose root already holds PHP files, whose upstream is off this host, or with a redirect to another host | 0.1.0-alpha.120 |
| `site_auth_user_set`: who may log in; a generated password is handed out once, by id | 0.1.0-alpha.120 |
| `trash_delete`, `trash_expire`: nothing brings the files back | 0.1.0-alpha.120 |

That is the whole list of `docs/design-site-operations.md` 27.2. Everything else is made at once with
the caller's `confirm`: HSTS, response headers, compression, `canonical`, redirects within the site,
`login_paths`, MIME types, limits, a protection added or narrowed, disable and enable, reload,
`cert-renew`, `site_delete` (to the trash), the other site tasks, and a new site into an empty
directory. None of it runs code, moves a secret or data off the host, grants access, or destroys
beyond undo. Everything else is made at once, as before, with
the caller's `confirm`: none of it runs code, moves a secret off the host, grants access, or destroys
beyond undo.

A dry run (`dry_run: true`, `--dry-run`) is never held: it answers as it always did and adds
`needs_approval` with the reasons the real change would wait. A command that has no dry run (a
password user, the trash, a reveal, a site's disable, enable or delete, a reload) refuses one with
400 and does nothing; `agensio ctl` refuses `--dry-run` itself on a command that only reads (a reveal,
a file's read), whose request carries no body (until 0.1.0-alpha.127 it dropped the flag and sent the
read, which then waited for approval). A change whose dry run fails (an environment change to a `.env` with a quote
never closed, a name that is no variable's) is answered at once with that failure and never waits.

## 2. Set up an approver

On the server, as root, once per person:

```sh
agensio approver-add ann
```

It prints the secret once, as text and as an `otpauth://` URI. Add it to any authenticator app (Aegis,
2FAS, Google Authenticator, 1Password, Bitwarden...): type the secret, or scan the URI as a QR code
(`qrencode -t ansiutf8 'otpauth://...'` draws it in the terminal when `qrencode` is installed). The
secret stays in `/etc/agensio/approvers/ann.totp`, root's, `0600`, in a root `0700` directory, read only
by agensio's root helper; it never travels anywhere else.

```sh
agensio approvers               # who can approve, when each was added, when each last approved
agensio approver-remove ann     # that phone's codes approve nothing from now on
agensio approver-add ann --replace   # a new secret for a lost or new phone
```

There is no way to add an approver through the control plane or MCP: an agent cannot enroll itself.

## 3. Approve

When a change waits, the tool that asked for it answers `pending: true` with an id, the reasons, and the
server's description of the change. Then, on the server:

```sh
agensio ctl approve
```

It lists every change waiting, each as the server describes it: what makes it dangerous first (lines
marked `!!`), then the change itself, then the words of whoever asked for it, marked as theirs and not
checked. It asks for the code on the terminal; one code approves exactly the list shown, and each change
then runs in the order it was asked for, with its result printed. A secret is not printed: a revealed
value, a generated password or a credential file's content goes once to whoever asked for it, by
`approvals_list` with the id (`GET /v1/approvals/ID`), so approving an agent's reveal leaves the value to
the agent (until 0.1.0-alpha.127 `ctl approve` took it, and the agent was told it was handed out
already). The changes approved together stop at
the first that fails: the ones after it are `skipped`, not run, each saying which change failed, so a
deploy queued as an install, the switch to it and the deletes of older releases never switches to a
release that did not install (since 0.1.0-alpha.124; before, every change ran whatever the one before
it did). Over SSH, `ssh -t HOST agensio ctl approve ID ...` works: the code is read from the terminal
`-t` gives.

- `agensio ctl approve ID ...` approves only those; `--list` shows without asking; `--show ID` prints one
  change whole; `--reject ID` drops one, nothing of it runs.
- A command typed by you at a terminal that needs approval asks for the code at once: one command, one
  code. You asked for it, so a secret it reads (`agensio ctl site-env NAME --reveal KEY`) is shown there.
- An MCP client that can put a question to you (MCP elicitation) shows the same list in its own dialog
  when the agent calls `approvals_ask`; you type the code there, and the agent never sees it. Claude
  Code's VS Code extension declines every such question, so with it you run `agensio ctl approve`.
- `approvals_list` (MCP) and `GET /v1/approvals` show what waits and, once it ran, its result.
- A change waits ten minutes; at most 32 wait at once. A code is accepted once: a second batch within
  the same 30 seconds waits for the app's next code.

Never give the code to the agent, and never type it anywhere it asks you to: no agensio tool takes a
code, and an agent that asks for one is misled.

## 4. What it protects, and what it does not

- The code protects against an agent, a script or a process of the agent's account that asks for a
  change on its own: it cannot approve it, through MCP, `agensio ctl` or the socket directly.
- Read what you approve. A change you approve because its description looked harmless runs; the
  description is the server's, never the agent's, and every byte a terminal could act on (escape
  sequences that move the cursor or hide a line) is shown as `\xHH`.
- The agent must not run as root, which could read the secrets. Give it a plain account in the
  control plane's admins group (`docs/mcp.md`).
- Five wrong codes within ten minutes stop approvals for ten minutes: guessing six digits gets nowhere,
  and the stop is counted by the root helper, which the server cannot reset. The audit log has every
  waiting change, every approval with the approver's name, and every refused code.
- A server started without the root helper (`[control] provision = false`, or not started as root)
  checks codes itself, against approver files of its own account: an agent running as the server's
  account could read those. Run the server with the helper.
- The phone's clock must be right within 30 seconds (authenticator apps follow the network time).

## 5. When it does not work

| message | what to do |
|---|---|
| no approver is set up | as root: `agensio approver-add NAME`, then add the secret to an app |
| the code matches no approver | a typo, a code already used (wait for the next one), or a phone clock more than 30 s off; `agensio approvers` shows when each approver last approved |
| approvals are stopped for N s | five wrong codes in ten minutes; wait, and check the audit log for who tried |
| no terminal to ask for the code on | run `agensio ctl approve` in a terminal on the server, not through a script |
| NOT USED: ... chmod 600 | an approver file others could read is never used: `chmod 600` it, or `--replace` it, since its secret may have been read |
