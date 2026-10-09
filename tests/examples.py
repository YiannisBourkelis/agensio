#!/usr/bin/env python3
"""The configuration cookbook (docs/examples.md and docs/examples/*.md) held to the binary.

Every recipe is a `## ` heading in a category file. For each one:
  - its ```toml blocks, joined in order (a main-file block and a site-file block are one
    configuration), load with `agensio -t`: the file system paths they name are moved under a
    scratch tree and created there (directories, a certificate, a users file), and accounts or
    groups this machine does not have are replaced by the test's own. The only warnings allowed
    are an unreachable php-fpm or origin (no test machine runs the recipe's application) and the
    ones the recipe declares with a `# expect: TEXT` line; `# expect-error: TEXT` declares a
    configuration the recipe shows being refused;
  - every `agensio ctl COMMAND --flag` of its ```sh blocks names a command and flags that
    `agensio ctl --help` lists;
  - every snake_case name in backticks on a `**MCP:**` line is a tool or argument name of
    src/control/mcp.cpp.
Every relative link of the cookbook resolves, a heading anchor included, and the index
(docs/examples.md) links every recipe.

usage: tests/examples.sh build/agensio
"""
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/agensio")
ROOT = os.getcwd()
INDEX = "docs/examples.md"
CATEGORIES = sorted("docs/examples/" + f for f in os.listdir("docs/examples") if f.endswith(".md"))
T = os.path.join(ROOT, "bench/tmp/examples")
shutil.rmtree(T, ignore_errors=True)
os.makedirs(T)

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        print("ok   " + name)
        passed += 1
    else:
        print("FAIL " + name + (": " + detail if detail else ""))
        failed += 1


def slug(heading):
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def anchors(path):
    seen = {}
    out = set()
    in_code = False
    for line in open(path, encoding="utf-8"):
        if line.startswith("```"):
            in_code = not in_code
            continue
        m = re.match(r"^(#{1,6}) +(.*?)\s*#*\s*$", line)
        if m and not in_code:
            base = slug(m.group(2))
            n = seen.get(base, 0)
            seen[base] = n + 1
            out.add(base if n == 0 else f"{base}-{n}")
    return out


def recipes(path):
    """[(heading, [(lang, text)], [lines])] for each `## ` section of a category file."""
    out = []
    cur = None
    block = None
    for line in open(path, encoding="utf-8"):
        if block is not None:
            if line.startswith("```"):
                cur[1].append((block[0], "".join(block[1])))
                block = None
            else:
                block[1].append(line)
            continue
        if line.startswith("```"):
            if cur is not None:
                block = (line[3:].strip(), [])
            continue
        if line.startswith("## "):
            cur = (line[3:].strip(), [], [])
            out.append(cur)
        elif cur is not None:
            cur[2].append(line)
    return out


# Paths a recipe names on a real host, moved under the recipe's scratch tree.
HOST_PATH = re.compile(r'"(/(?:var/www|var/log|var/lib|etc/agensio|etc/ssl|srv|opt|home)(?:/[^"]*)?)"')
DIR_KEYS = {"root", "alias", "sites_root", "state_dir", "pools", "pools_run", "storage"}
CERT_KEYS = {"cert", "ca", "install_ca"}


def users_line(name):
    r = subprocess.run([BIN, "passwd", name], input="example-password\n", capture_output=True, text=True)
    return r.stdout.strip()


def prepare(text, base):
    """The recipe's configuration with its paths under `base`, and the files those paths need."""
    text = HOST_PATH.sub(lambda m: '"' + base + m.group(1) + '"', text)
    me = pwd.getpwuid(os.getuid()).pw_name
    my_group = grp.getgrgid(os.getgid()).gr_name

    def account(m):
        key, value = m.group(1), m.group(2)
        try:
            (grp.getgrnam if key in ("group", "admins", "operators", "viewers") else pwd.getpwnam)(value)
            return m.group(0)
        except KeyError:
            return f'{key} = "{my_group if key != "user" else me}"'

    text = re.sub(r'\b(user|group|admins|operators|viewers)\s*=\s*"([^"]+)"', account, text)
    conf_dir = os.path.join(base, "etc/agensio")
    os.makedirs(conf_dir, exist_ok=True)
    for m in re.finditer(r'\b([a-z_]+)\s*=\s*"([^"]+)"', text):
        key, value = m.group(1), m.group(2)
        if value.startswith(("unix:", "http://", "https://")) or value in ("off", "stderr", "auto"):
            continue
        if not (value.startswith(base) or value.startswith(("./", "../")) or key in ("users",)):
            continue
        path = os.path.normpath(os.path.join(conf_dir, value))
        if key in DIR_KEYS:
            os.makedirs(path, exist_ok=True)
            if key == "root" and re.search(r'\bapp\s*=\s*"laravel"', text):
                os.makedirs(os.path.join(path, "public"), exist_ok=True)  # the preset requires the served public/
        elif key in CERT_KEYS or key == "key":
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.copy(os.path.join(ROOT, "bench/certs", "key.pem" if key == "key" else "cert.pem"), path)
        elif key == "users":
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(users_line("anna") + "\n")
            os.chmod(path, 0o640)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
    return text


UNREACHABLE = re.compile(r"(fastcgi|proxy) upstream .*(Connection refused|No such file or directory|nothing is listening)")

ctl_help = subprocess.run([BIN, "ctl", "--help"], capture_output=True, text=True)
ctl_help = ctl_help.stdout + ctl_help.stderr
mcp_names = set(re.findall(r'"([a-z0-9_]+)"', open("src/control/mcp.cpp", encoding="utf-8").read()))

listed = set()
for line in open(INDEX, encoding="utf-8"):
    for target in re.findall(r"\]\((examples/[^)#]+\.md)#([^)]+)\)", line):
        listed.add(target)

n = 0
for path in CATEGORIES:
    name = os.path.basename(path)
    for heading, blocks, prose in recipes(path):
        label = f"{name}: {heading}"
        check(f"{label}: listed in {INDEX}", ("examples/" + name, slug(heading)) in listed)
        tomls = [t for lang, t in blocks if lang == "toml"]
        if tomls:
            n += 1
            base = os.path.join(T, str(n))
            text = prepare("\n".join(tomls), base)
            conf = os.path.join(base, "etc/agensio/agensio.toml")
            with open(conf, "w") as f:
                f.write(text)
            r = subprocess.run([BIN, "-t", "-c", conf], capture_output=True, text=True)
            out = r.stdout + r.stderr
            expect = re.findall(r"#\s*expect:\s*(.+)", text)
            expect_error = re.findall(r"#\s*expect-error:\s*(.+)", text)
            if expect_error:
                ok = r.returncode != 0 and all(e.strip() in out for e in expect_error)
                check(f"{label}: refused as the recipe says", ok, out.strip()[-600:])
            else:
                stray = [l for l in out.splitlines() if l.startswith("warning:") and not UNREACHABLE.search(l)
                         and not any(e.strip() in l for e in expect)]
                missing = [e for e in expect if e.strip() not in out]
                ok = r.returncode == 0 and "is OK" in out and not stray and not missing
                check(f"{label}: agensio -t loads it", ok,
                      (out.strip()[-600:] if r.returncode else "") + " ".join(stray) + (" missing: " + ", ".join(missing) if missing else ""))
        for lang, block in blocks:
            if lang not in ("sh", "bash", "console"):
                continue
            for line in block.splitlines():
                m = re.search(r"agensio ctl ([a-z][a-z-]*)(.*)", line)
                if not m:
                    continue
                args = m.group(2).split("#")[0]
                unknown = [w for w in [m.group(1)] + re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", args)
                           if not re.search(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", ctl_help)]
                check(f"{label}: `agensio ctl {m.group(1)}` and its flags exist", not unknown, " ".join(unknown))
        for line in prose:
            if "**MCP:**" in line:
                unknown = [w for w in re.findall(r"`([a-z0-9]+(?:_[a-z0-9]+)+)`", line) if w not in mcp_names]
                check(f"{label}: the MCP names exist", not unknown, " ".join(unknown))

# Links: every relative link of the cookbook resolves, its anchor included.
for path in [INDEX] + CATEGORIES:
    text = open(path, encoding="utf-8").read()
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    bad = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if re.match(r"[a-z]+:", target):
            continue
        file, _, anchor = target.partition("#")
        dest = os.path.normpath(os.path.join(os.path.dirname(path), file)) if file else path
        if not os.path.exists(dest):
            bad.append(target)
        elif anchor and dest.endswith(".md") and anchor not in anchors(dest):
            bad.append(target)
    check(f"{path}: every link resolves", not bad, " ".join(sorted(set(bad))))

print(f"examples: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
