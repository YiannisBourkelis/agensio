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

The site's files through the control plane (write, edit, move, delete), application installs, reading a
credential or database file, a site environment's secrets, the `site_update` changes that make files run
or send visitors elsewhere, password users and the trash's deletions join this list in the next releases
(`docs/design-site-operations.md` 27.2 lists them all). Everything else is made at once, as before, with
the caller's `confirm`: none of it runs code, moves a secret off the host, grants access, or destroys
beyond undo.

A dry run (`dry_run: true`, `--dry-run`) is never held: it answers as it always did and adds
`needs_approval` with the reasons the real change would wait.

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
then runs in the order it was asked for, with its result printed.

- `agensio ctl approve ID ...` approves only those; `--list` shows without asking; `--show ID` prints one
  change whole; `--reject ID` drops one, nothing of it runs.
- A command typed by you at a terminal that needs approval asks for the code at once: one command, one
  code.
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
