# nftwho

Which rule in which chain of an nftables ruleset file decides one fully
specified packet at one traversal — and where that rule lives.

```sh
nftwho --conf firewall.nft --hook input \
  --saddr 1.2.3.4 --daddr 10.1.1.1 --proto tcp --dport 22 --ctstate new
```

```
ACCEPT (rule) — firewall.nft:14 (accept)
```

## Why this exists

Four tools look like they answer this question. None does:

- **`nft -c -f FILE` validates; it does not adjudicate.** It answers
  "does this parse and resolve against this kernel", never "for this
  packet at the input hook, which rule in which included file drops
  it, and where is that rule written".
- **`nft list ruleset` prints the live kernel ruleset — flattened,
  handle-numbered, and provenance-free.** Includes are already
  expanded, `define`s already substituted, sets show their *current
  runtime* contents, and no source file:line exists anywhere in the
  output. It also describes the machine's loaded state, not the file
  you are about to deploy.
- **`nft monitor trace` traces real packets through the live
  ruleset** — at runtime, as root, and only for packets you first
  mark with `meta nftrace set 1` rules planted in the live ruleset.
  It cannot answer a static, pre-deploy, or CI question about a file,
  and its output names kernel handles, not source lines.
- **eFeFlow (a hosted web IDE)** simulates a packet rule-by-rule over
  a ruleset model built from a pasted `nft list ruleset` dump — a
  dump that has already lost the include tree, the defines, and every
  file:line, on someone else's server, with no local CLI a pipeline
  can call.

And `grep` cannot do it at all: the deciding rule sits at the end of
a traversal that crosses base chains ordered by signed priority across
multiple tables, jumps and gotos into regular chains, verdict maps
that dispatch without naming the target chain on the deciding line,
sets whose elements live in another file, and an `inet`-family trap in
which a rule that textually matches the packet's addresses is silently
false for its address family.

nftwho is a static, pre-deploy adjudicator over the file plus its
`include` tree. It never loads a ruleset, never invokes `nft` on user
files, and never reads the live kernel ruleset.

## Usage

```
nftwho (--hook HOOK | --path in|forward|out) [--family ipv4|ipv6]
  [--saddr A] [--daddr A] [--proto P] [--sport N] [--dport N]
  [--iif NAME] [--oif NAME] [--ctstate S] [--mark N]
  [--tcpflags F] [--icmptype T] [--icmpcode N]
  [--in-interface-addr A]... [--includepath DIR]...
  [--services FILE] [--conf FILE]
```

- `--hook H`: every base chain registered at hook H, in priority
  order, and nothing else. The primitive; always exact when its
  inputs are. Hooks: `prerouting`, `input`, `forward`, `output`,
  `postrouting`, `ingress`.
- `--path in`: ingress → prerouting → input (a packet arriving on
  `--iif` destined for the local host).
- `--path forward`: ingress → prerouting → forward → postrouting.
- `--path out`: output → postrouting.
- Packet fields are all optional; every omitted field is a potential
  UNKNOWN source the walk will name. There are no defaults for packet
  fields, ever. `--family` defaults to ipv4 only when `--saddr` /
  `--daddr` are both IPv4 literals.
- `--ctstate` is the one flag that matters most: nearly every real
  ruleset's second rule is `ct state established,related accept`, and
  without it that rule blocks the traversal as UNKNOWN.
- `--services FILE` is an /etc/services-format file used for hermetic
  service-name resolution. Without it, a symbolic service name
  (`tcp dport ssh`) is UNKNOWN. The host's own /etc/services is never
  read.
- `--tcpflags`, `--icmptype`, `--icmpcode` are extensions beyond the
  design CLI: they supply the TCP-flags / ICMP-type inputs the
  corresponding matches read. Without them those matches are UNKNOWN.
- `--in-interface-addr A` is accepted and recorded in coverage; it is
  not currently used by any v1 match expression.
- Flags: `--json` (same structure, machine-readable), `--quiet`
  (verdict line and NAT block only), `--version`, `--list-chains`,
  `--list-sets` (inventory modes; no packet flags needed).

Exit codes: **0** = ACCEPT (rule or policy); **1** = DROP / REJECT
(rule or policy) or NOT-EVALUATED; **2** = UNKNOWN / QUEUED-UNKNOWN,
usage error, or an unloadable ruleset.

## Examples

A drop hidden behind an early accept in another table:

```sh
$ nftwho --conf fw.nft --hook input --saddr 10.9.9.9 --daddr 10.1.1.1 \
    --proto tcp --dport 80 --ctstate new
DROP (rule) — fw.nft:23 (drop)
```

The accept in the priority −100 chain ended *that chain only*; the
priority 0 chain still dropped the packet. The walk shows every chain
the packet had to survive.

A composed path with a DNAT in prerouting:

```sh
$ nftwho --conf fw.nft --path in --saddr 1.2.3.4 --daddr 10.9.9.9 \
    --proto tcp --dport 8080 --ctstate new
UNKNOWN — fw.nft:9 (nat-rewrites-tuple)
NAT: dnat to 10.0.0.5:80 (rule at fw.nft:9)
```

Per-hook answers stay exact (`--hook input` alone still reports the
drop); only the composed path degrades, because the DNAT rewrote the
destination a later deciding match reads.

Inventory:

```sh
$ nftwho --conf fw.nft --list-chains
$ nftwho --conf fw.nft --list-sets
```

## Limitations

The pinned semantics are in `DESIGN-nftwho.md` (NF00–NF31). The ones
that most often surprise:

- **NF08 — accept is chain-local, drop is packet-final.** An early
  `accept` in one base chain does not protect the packet from a
  `drop` in a later base chain at the same hook. A composed `--path`
  verdict is ACCEPT only if *every* hook lets the packet through.
- **NF15 — the inet trap.** In an `inet` table, an `ip saddr`
  expression against an IPv6 packet is **false**, silently — and
  `ip6 daddr` against an IPv4 packet likewise. A rule mixing `ip` and
  `ip6` address fields matches nothing, ever, and is reported as
  `[never-matches]`.
- **NF18 — dynamic/timeout sets.** A lookup against a `dynamic` set
  is UNKNOWN in both directions; a miss on a `timeout` set is
  UNKNOWN (an unlisted element may have been added with a timeout).
  This is the single largest honest-UNKNOWN source in real rulesets.
  Named sets/maps without those flags are treated as file-exact, and
  the coverage banner states on every run that runtime element
  changes are outside the file.
- **NF19 — verdict maps.** A key with no entry and no `*` default
  produces **no verdict** — evaluation continues as if the rule had
  not matched. It is not an implicit drop. Overlapping interval keys
  resolve by most-specific match.
- **NF22 — NAT.** Nat chains run only for a connection's first
  packet (`--ctstate` other than `new` skips them; no `--ctstate`
  makes the NAT outcome UNKNOWN while filter verdicts still resolve).
  A NAT statement is terminal for its chain, reported separately, and
  never folded into later matches: a composed path degrades to
  UNKNOWN with `[nat-rewrites-tuple]` when a NAT outcome fired and a
  later deciding match reads a field that NAT kind rewrites.
- **NF25 — runtime expressions are UNKNOWN, never approximated:**
  `fib` lookups (`[routing-dependent]`), `jhash`/`symhash`/`numgen`
  (`[hash-or-random]`), socket / uid / cgroup matches
  (`[process-context]`), raw payload expressions and out-of-surface
  fields (`[unmodeled-field]`), wall-clock matches
  (`[wall-clock]`), rate-shaped matches (`[rate-dependent]`, NF24),
  hostnames (`[load-time-dns]`, NF26), and symbolic service names
  without `--services` (`[symbolic-service]`, NF26).
- **NF27 — three-valued core.** Uncertainty *before* a decider
  poisons the chain; uncertainty *after* a TRUE decider is inert.
  The report always names the earliest blocking candidate.
- **NF30 — safety.** nftwho opens ruleset files read-only and never
  invokes `nft` (or anything else) on the queried file. Include
  depth, define expansion, and stream size are capped; exceeding a
  cap is exit 2 with the cap named.

### Out of scope (bannered, never silently modeled)

- `arp` / `bridge` / `netdev` tables and the ingress match surface
  (ether, vlan, pppoe headers) — NF05. An `inet`/`netdev` `ingress`
  base chain degrades a composed path to UNKNOWN.
- Routing decisions, `fib` lookups, and anything that depends on the
  kernel's tables rather than this file — NF01/NF25.
- Other writers' rules (firewalld / Docker / kube-proxy inject their
  own nft objects at runtime): the file is the whole universe of the
  answer — NF01.
- Flowtables and `flow add` offload: a deciding `flow` statement
  degrades the path verdict like a reroute — NF29.
- Stateful objects' live values (counters, quota remaining, limit
  buckets, conntrack table contents) — NF18/NF24.
- `xt` (xtables-compat) rules — `[unmodeled-field]` under NF25.
- A rule wrapped mid-expression across lines without braces or a
  semicolon is treated as two statements (statement splitting is
  line-oriented at brace depth 0; multi-line set/vmap literals are
  handled). Real `nft -f` files wrap inside braces.

### Not a validator

`nft -c -f` already validates, better than a reimplementation ever
will. nftwho therefore *explains broken files too*: constructs nft
would reject are `[load-would-fail]` findings, the walk proceeds over
the modeled remainder, and only outright unloadability (missing file,
missing literal include, include cycle, tokenizer failure) is exit 2.
A file can be perfectly valid and still get UNKNOWN — validity and
decidability are different axes.

## Tests

```sh
python3 test_nftwho.py   # 82 tests, stdlib-only runner, no pytest
```

BG1–BG10 cover core traversal (NF08), jump/goto/return/vmap (NF11/
NF19), fields and the inet trap (NF15), sets/maps/concatenations
(NF16–NF20), includes/defines/flush (NF02–NF04), conntrack and NAT
(NF21/NF22), mutation and runtime poison (NF23–NF25), the Kleene
core (NF27/NF29), names and safety (NF26/NF30), and inventory,
coverage, and the exit-code matrix (NF28/NF31). One test is
skip-guarded: `nft -c -f` over the suite's own valid fixtures runs
only when the binary exists *and* the sandbox lets it run (it is
blocked by netlink permissions in this environment, so it skips
there).

## Pre-publish checklist

- [x] `python3 test_nftwho.py` green (82 tests, 10.3s; 1 skipped —
  `nft -c -f` cross-check, sandbox blocks netlink)
- [x] `doccover` clean over README vs `--help`
- [x] `clicheck` (strict mode) clean
- [x] `prepublish-check` clean (stdlib-only, no secret-like literals)
- [x] `bench-audit` clean (map entry added for nftwho)
- [x] MIT LICENSE, copyright holder `dunkleschitz`
- [x] CI workflow `.github/workflows/tests.yml` (Python 3.12,
  runs `python3 test_nftwho.py`)
- [x] Design review BUILD APPROVED (DESIGN-nftwho.md, 2026-11-09);
  publishing NOT covered by that verdict — per-project approval
  still required before any publish
- [x] No remote origin set; local commits only, authored
  `Laszlo <laszlo@local>`; history verified clean of personal-name
  and home-directory leaks

## License

MIT — see `LICENSE`.
