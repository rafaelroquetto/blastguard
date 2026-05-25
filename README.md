# Blastguard

Blastguard watches what happens when you run `npm install` on a Linux
machine. While the install is running, it records every process that gets
started, every file that gets opened, and every network connection that
gets made. Afterwards, it gives you a report that says which npm package
caused which actions, and whether any of your secret tokens (like
`NPM_TOKEN` or `AWS_ACCESS_KEY_ID`) were in the environment at the time.

The problem this exists to solve: an npm package you depend on can have
malicious code in it, which runs automatically when the package is
installed. By the time you notice, your credentials may already be
exfiltrated. Blastguard sits next to your install and records the truth
about what happened, so when you find out a package was compromised, you
know exactly what you have to clean up.

## A small walkthrough

You run two programs.

`blastguardd` is the daemon. It needs root because it loads eBPF programs
into the Linux kernel.

`blastguardctl` is a small CLI you use to talk to the daemon.

A typical session:

```
# Terminal 1: start the daemon.
sudo ./build/blastguardd --mode audit \
    --allow registry.npmjs.org --allow github.com

# Terminal 2: tell the daemon to start watching, run your install,
# tell it to stop, and ask for the report.
./build/blastguardctl start-phase $$ install
npm install
./build/blastguardctl end-phase
./build/blastguardctl report --format markdown --fail-on high
```

A "phase" is just a name for a window of time. You start one before doing
the thing you want watched, end it when you are done, then ask for a
report covering what happened in between. The name (here, `install`) shows
up in the report so you can tell phases apart if you have more than one.

The first positional argument tells the daemon where the tree of processes
you care about is rooted. In the example above, `$$` is the shell that
runs `npm install`. Everything `npm install` spawns, and everything those
spawn, gets watched. Things happening elsewhere on the machine are
ignored.

## What the report looks like

If nothing interesting happened, the report just says so. If something
suspicious happened, you get something like:

```
Rotate the following tokens:
- NPM_TOKEN

Findings:
- HIGH  package evil-helper (postinstall) ran curl while NPM_TOKEN was in its environment
- HIGH  package evil-helper (postinstall) read /home/runner/.npmrc
```

The top-of-page rotation list is the actionable part. If something
exfiltrated your tokens, those are the ones to rotate right now. The
findings below explain why each token is in the list.

## Two modes

You pick the mode when you start the daemon with `--mode`.

- `audit` (the default) records what happened and produces the report.
  It does not interfere with the install.
- `enforce` does the same, but also blocks outbound network connections
  from inside the watched subtree, unless the destination is on the
  hostname allowlist you passed with `--allow`. If a malicious package
  tries to call home, the connection fails (EPERM).

## What blastguard can and cannot see

It sees things that happen during the install: processes spawned by npm,
files those processes open, network connections they make, what tokens
were in their environment.

It does not see anything that happens later. If a compromised package
contains malicious code that lies dormant in your `node_modules` and only
runs when your application is actually started, that is invisible to
blastguard.

It works for npm and pnpm. Yarn 2+ with Plug'n'Play (where there is no
`node_modules` directory) is not supported.

## Build

You need: clang, libbpf, bpftool, CMake 3.20 or newer, and a Linux kernel
with BTF enabled (the file `/sys/kernel/btf/vmlinux` exists).

```
cmake -B build
cmake --build build -j
```

`vmlinux.h` is generated automatically as a build step. You do not need
to run `bpftool btf dump` by hand.

The build produces `build/blastguardd` and `build/blastguardctl`.

## Trying it locally

You need root for the daemon (eBPF, plus attaching to the cgroup).

```
sudo ./build/blastguardd --mode audit \
    --allow registry.npmjs.org --allow github.com
```

In another terminal:

```
BG=$PWD
mkdir -p /tmp/bg-smoke/node_modules/evil-helper
cd /tmp/bg-smoke/node_modules/evil-helper

$BG/build/blastguardctl ping
$BG/build/blastguardctl start-phase $$ install
NPM_TOKEN=x npm_lifecycle_event=postinstall curl -s http://example.com >/dev/null
$BG/build/blastguardctl end-phase
$BG/build/blastguardctl report --format markdown --fail-on high
$BG/build/blastguardctl shutdown
```

The `node_modules/<pkg>/` cwd is what gives Blastguard a package to attribute findings
to; `npm_lifecycle_event` is what real `npm` sets to name the lifecycle phase.

## Demo fixtures

Two shell scripts you can run end-to-end:

```
bash test/integration/run-evil.sh
bash test/integration/run-benign.sh
```

`run-evil.sh` simulates a malicious package's postinstall and is expected
to produce findings (and exit non-zero). `run-benign.sh` simulates a
clean, noisy install and is expected to produce no findings.

## Using it from GitHub Actions

```yaml
- uses: ./action
  with:
    mode: enforce
    allowed-hosts: registry.npmjs.org,github.com
- run: npm ci
- run: |
    blastguardctl end-phase
    blastguardctl report --format markdown --fail-on high >> $GITHUB_STEP_SUMMARY
```

See `action/action.yml` and the example workflow in
`.github/workflows/sanity.yml`.

## Daemon flags

- `--mode audit|enforce` (default: audit)
- `-a, --allow <hostname>` allowlists a hostname. Repeatable, no default.
  Hostnames are resolved to IP addresses once, at daemon startup.
- `-v, --verbose` prints every captured event to stdout. Useful for
  debugging, noisy otherwise.

## Subcommands of `blastguardctl`

- `ping` checks the daemon is reachable
- `start-phase <PID> <NAME>` starts a new phase, rooted at the given
  process id, with the given name
- `end-phase` closes the current phase
- `report [--format markdown|json] [--fail-on low|medium|high]` writes
  the report to stdout. With `--fail-on`, the command exits non-zero if
  any finding meets or exceeds that severity, so you can use it as a CI
  gate.
- `shutdown` tells the daemon to stop

## License

Apache 2.0, except for the BPF source (`src/bpf/blastguard.bpf.c`), which
is GPL-2.0. See `LICENSE`.

## Limitations

- Linux only. eBPF is a Linux kernel feature.
- No container or PID-namespace awareness. The daemon sees the host's
  process tree.
- The IPC socket lives in the Linux abstract namespace, so any process
  in the same network namespace can talk to the daemon. Fine on a
  single-user CI runner; not appropriate for a shared host.
