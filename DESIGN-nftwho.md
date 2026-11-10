# nftwho — hazard-first design review

**Status:** BUILD APPROVED (2026-11-09).
**Question:** for one fully specified packet (family, addresses,
ports, interfaces, conntrack state) and one traversal — a single
netfilter hook, or a composed path (in / forward / out) — which
rule in which chain of an nftables ruleset file (plus its
`include` tree) gives the packet its final verdict at that
traversal, what NAT outcome (if any) a `nat` chain assigns along
the way, and at which file:line does the deciding rule live?
**Shape:** `nftwho (--hook HOOK | --path in|forward|out)
[--family ipv4|ipv6] [--saddr A] [--daddr A] [--proto P]
[--sport N] [--dport N] [--iif NAME] [--oif NAME]
[--ctstate S] [--mark N] [--in-interface-addr A]...
[--includepath DIR]... [--services FILE] [--conf FILE]`
over one ruleset file plus its `include` tree.
Flags (who-family standard): `--json`, `--quiet`, `--version`,
plus `--list-chains` and `--list-sets`.
**Pinned from:** nft(8) (nftables 1.0.9 on this box; the
chains/verdicts text cross-read in the nft source's doc/nft.8
mirror), the nftables wiki (Scripting, Configuring chains,
Netfilter hooks, Matching connection tracking stateful
metainformation, Matching packet metainformation, Data types —
all read 2026-11-09), and the Red Hat nftables chain-type /
priority matrix. Semantics pinned to the nftables 0.9.6 – 1.1.x
range (0.9.6 introduced priority keywords; the core traversal
semantics — hooks, priorities, verdicts, sets, maps — are
unchanged across that range); version-gated grammar is called
out where it appears (NF07, NF20). An `nft` binary (1.0.9)
*does* exist on this box, unlike the daemons behind the last
two designs, so two claim tags differ in kind here:
`[observed]` is used only for the binary's existence/version
and for `nft -c -f` parse-check behavior on fixture files,
never for traversal answers — obtaining a traversal answer
from the real binary would require *loading* a ruleset into a
kernel (a network namespace at best), which this tool must
never do to arbitrary configs (NF30). Every traversal claim
below is `[documented]` (nft(8) / wiki / RHEL matrix),
`[docs-inferred]` (follows from a documented rule), or
`[hypothesized]` (best-supported guess, flippable) — fixture
files are the oracle, exactly as the manual text is the only
authority. A claim that turns out wrong must flip the design,
not get quietly absorbed.

## Thinness verdict: APPROVED, and no native holder answers the question

1. **`nft -c -f FILE` validates; it does not adjudicate.** It
   answers "does this parse and resolve against this kernel",
   never "for this packet at the input hook, which rule in
   which included file drops it, and where is that rule
   written" [documented — nft(8); `observed` for the local
   binary's parse-check behavior].
2. **`nft list ruleset` prints the *live kernel* ruleset —
   flattened, handle-numbered, and provenance-free.** Includes
   are already expanded, `define`s already substituted, sets
   shown in their *current runtime* contents (including
   elements added after load), and no source file:line exists
   anywhere in the output. It also describes the machine's
   loaded state, not the file you are about to deploy
   [documented — nft(8) list semantics; wiki, Scripting].
3. **`nft monitor trace` traces real packets through the live
   ruleset — at runtime, as root, and only for packets you
   first mark with `meta nftrace set 1` rules planted in the
   live ruleset.** It cannot answer a static, pre-deploy, or
   CI question about a file, and its output names kernel
   handles, not source lines [documented — nft(8) monitor;
   netfilter trace design].
4. **The one third-party holder found, eFeFlow (a hosted web
   IDE), simulates a packet rule-by-rule — over a ruleset
   model it builds from a pasted `nft list ruleset` dump.**
   That makes it Batfish-shaped, not a holder for this
   question: the dump it consumes has already lost the include
   tree, the defines, and every file:line; the simulation runs
   on a third-party website, so using it means uploading a
   production firewall policy to someone else's server; and
   there is no local CLI a pipeline can call. It adjudicates
   an outcome, with no provenance, over a different artifact
   than the one an operator edits [documented — eFeFlow site,
   read 2026-11-09].
5. **grep cannot do this at all.** The deciding rule sits at
   the end of a traversal that crosses base chains ordered by
   signed priority across *multiple tables* (NF07), jumps and
   gotos into regular chains (NF11), verdict maps that dispatch
   without any rule text naming the target chain on the
   deciding line's left-hand side (NF19), sets whose elements
   live in another file (NF17), and an `inet`-family trap in
   which a rule that textually matches the packet's addresses
   is silently false for its address family (NF15). Grep
   prints all the candidate lines and adjudicates none of it.

If the build cannot reproduce NF08 (accept is chain-local,
drop is packet-final, same-hook chains all run), NF11
(jump/goto/return stack semantics, goto exhaustion falls to
the *base chain's* policy), and NF15 (the inet dual-stack
trap) against fixture rulesets, it does not ship — those
three are the tool's reason to exist.

## Pinned semantics

### Files and lines

- A ruleset is a stream of declarations in one of the two
  formats `nft -f` accepts [documented — wiki, Scripting]:
  the *declarative* format (`table FAMILY NAME { ... }`
  containing `chain`, `set`, and `map` blocks, with rules as
  bare lines inside chain blocks) and the *imperative* format
  (`add table ...`, `add chain ... { ... }`,
  `add rule ... ...`, `flush ruleset`, `include "..."`,
  `define NAME = VALUE`). Both may appear in one merged
  stream across the include tree (NF02). Comments start with
  `#` to end of line [documented — wiki, Scripting]; a `#`
  inside a quoted string is literal.
- **NF00 — tokenizer:** braces, semicolons, and rule lines
  must tokenize across line breaks (chain headers, set
  element lists, verdict maps, and long rules routinely span
  lines; a rule inside a chain block is terminated by the
  next rule's first token, a closing brace, or a semicolon —
  the recognizer is statement-oriented, not line-oriented).
  Quoted strings (interface names, log prefixes, comments in
  `comment "..."` user data) are single tokens even when they
  contain spaces, braces, or `#`. `$name` references,
  `@name` object references, `{ ... }` anonymous collections,
  `.` concatenation, and the operators `==`, `!=`, `>=`,
  `<=`, `>`, `<`, `&`, `|`, `<<`, `>>`, `in` (set-membership
  sugar in some spellings) are distinct token classes
  [documented — nft(8) grammar throughout].

### NF01 — Verdict scope: per-traversal adjudication, not kernel fate [design rule]

nftwho answers *which rule gives this packet its verdict for
this traversal of this ruleset file*, never *what the kernel
will ultimately do with this packet on a real machine*.
Consequences:

- It never claims a packet "will be delivered": routing,
  bridging, neighbor resolution, other subsystems' hooks
  (conntrack helpers, the bridge netfilter, XDP/eBPF programs
  attached outside nft), and *other rulesets loaded by other
  tools* (firewalld, Docker, Kubernetes all write nft rules
  into the same kernel) are outside the file and outside the
  answer. The `--path` modes compose only the hooks of the
  chains declared in the file (NF06), and the output says so.
- NAT outcomes are reported as outcomes of the nat chains in
  the file (NF22), not folded silently into the filter
  verdict.
- A hook at which the file declares no base chain is
  `NOT-EVALUATED` (NF28): nft in this file does not decide
  this packet at that hook, and the tool never invents the
  kernel's proceed-anyway behavior as an ACCEPT finding.

### NF02 — Loading model: one merged stream, includes inline [documented + design rule]

- `include` splices the included file's stream at the exact
  position of the include statement, recursively
  [documented — wiki, Scripting]. Defines, tables, chains,
  and rules therefore take effect in merged-stream order, and
  a rule's *identity* is (file, line) in the file where it is
  written, never in the including file.
- `flush ruleset` in the stream discards every object modeled
  so far in the stream (it is the standard first line of
  generated rulesets) [documented — nft(8)]. v1 models
  `flush ruleset` and `flush table FAMILY NAME` exactly;
  `delete`, `insert ... position`, `replace ... handle`, and
  `rename` operate on kernel handles a static file does not
  carry, so each is an `[unmodeled-command]` finding: harmless
  if it cannot touch the queried traversal, a poison for the
  answer if it names a table/chain on that traversal (NF29).
- Imperative `add rule F T C <matches> <statements>` appends
  a rule to chain C in stream order and is modeled exactly
  [documented — nft(8) add semantics]; `add element`
  appends elements to a named set/map and is modeled exactly
  for constant elements, and poisons that set/map under NF18
  if the elements are not constant.

### NF03 — Include resolution: including file's directory, then the search path [documented + docs-inferred]

- A relative include is searched in the directories given by
  the tool's `--includepath` flags (mirroring `nft -I`) and
  in the directory of the *file containing the include
  statement* [docs-inferred — nft(8) includepath semantics
  plus the wiki's default-search-path description; the exact
  fallback order against the process working directory is a
  flippable hypothesis, Open Questions §2]. It is *not*
  resolved against the main file's directory when the
  including file lives elsewhere — the lighttpdwho rule
  (LT03) is the opposite daemon's opposite choice, and
  copying it here would be a bug.
- Include statements support the shell wildcards `*`, `?`,
  `[...]`; a wildcard include with no matches is **not** an
  error, and files beginning with `.` are never matched by a
  wildcard [documented — wiki, Scripting]. v1 expands
  wildcards in byte-wise sorted order (the glob order nft's
  own expansion presents on Linux [docs-inferred]) and lists
  every expanded file in coverage (NF31). A *literal* include
  that resolves nowhere is a load failure: exit 2, like a
  missing main file. An include cycle is a load failure:
  exit 2 (nft itself recurses; a provenance tool must not).

### NF04 — Defines are parse-time, sequential, single-pass [documented + docs-inferred]

- `define NAME = VALUE` substitutes `$NAME` textually at
  parse time, at every *later* point in the merged stream; a
  value may be a single literal, a `{ ... }` set literal, or
  another define's expansion [documented — wiki, Scripting].
- A use of an undefined `$NAME` is a load failure in nft;
  v1 reports it as an `[undefined-define]` poison at that
  position (exit 2 if it sits on the queried traversal,
  finding otherwise) rather than guessing [design rule].
- Redefinition: v1 pins *later define wins for later uses,
  earlier uses keep the earlier value* (single-pass stream
  semantics) [docs-inferred from parse-time substitution;
  flippable, Open Questions §3]. A define whose value
  contains a hostname, a `$` reference to an undefined name,
  or a non-constant expression is poison at its use sites
  under NF26/NF29, not at the define line.

### NF05 — Families gate everything [documented]

- Table families are `ip`, `ip6`, `inet`, `arp`, `bridge`,
  `netdev` [documented — nft(8)]. A packet of address family
  IPv4 is evaluated only by `ip` and `inet` tables; IPv6 only
  by `ip6` and `inet` tables. An `arp`, `bridge`, or `netdev`
  table never sees an ip-family packet traversal of the five
  classic hooks.
- **v1 scope:** `ip`, `ip6`, and `inet` tables are modeled.
  If the file declares `arp`, `bridge`, or `netdev` tables,
  they are inventory (NF31) plus a banner: they cannot decide
  a v1 packet query, *except* a `netdev`/`inet` `ingress`
  base chain, which fires before prerouting on real hardware
  — if such a chain exists and the query is `--path in` or
  `--path forward`, the full-path verdict degrades to UNKNOWN
  with the chain cited (its match surface — ether/vlan
  headers — is out of v1's field surface, NF14), while
  per-hook answers stay exact [design rule].

### NF06 — Hooks and the three composed paths [documented + design rule]

- Base-chain hooks for ip/ip6/inet: `prerouting`, `input`,
  `forward`, `output`, `postrouting`, plus `ingress` (inet
  since kernel 5.10, netdev since 4.2) [documented — wiki,
  Netfilter hooks]. A query names exactly one traversal:
  - `--hook H`: every base chain registered at H, in the
    order of NF07, and nothing else. This is the primitive;
    it is always exact when its inputs are.
  - `--path in`: ingress (NF05 caveat) → prerouting → input.
    Models a packet arriving on `--iif` destined for the
    local host.
  - `--path forward`: ingress (caveat) → prerouting →
    forward → postrouting. Models a routed packet.
  - `--path out`: output → postrouting. Models a locally
    generated packet leaving via `--oif`.
- The path modes are *compositions the tool defines*, clearly
  labeled as such: the kernel's choice between the `in` and
  `forward` compositions is a routing decision the file does
  not contain (NF01). A DNAT outcome in prerouting can change
  that routing decision in reality; NF22 pins how that
  uncertainty is reported rather than hidden.

### NF07 — Base chains: priority orders the hook [documented]

- A base chain declares `type TYPE hook HOOK priority PRIO;
  policy POL;` where TYPE is `filter`, `nat`, or `route`,
  PRIO is a signed integer or a standard keyword, and POL is
  `accept` (the default if omitted) or `drop` [documented —
  nft(8); wiki, Configuring chains]. All base chains at one
  hook — across *all* tables of the applicable families —
  are traversed in increasing numeric priority. Standard
  keywords (ip/ip6/inet/arp/netdev): `raw` = −300,
  `mangle` = −150, `dstnat` = −100, `filter` = 0,
  `security` = 50, `srcnat` = 100 (bridge family uses its own
  values: dstnat −300, filter −200, srcnat 300) [documented —
  nft(8) priority table; RHEL matrix; wiki, Configuring
  chains].
- Priority may be an arithmetic expression over keywords and
  integers (`priority filter - 5`); v1 evaluates constant
  expressions exactly and poisons on anything else
  [documented grammar; design rule for the poison].
- Two base chains at the same hook with the *same* numeric
  priority: nft documentation does not promise an order
  between them (registration order decides in practice).
  v1 pins *merged-stream declaration order* and emits a
  `[same-priority-order]` finding whenever two chains on the
  queried hook collide, so the reader can see the answer
  rests on it [hypothesized — flippable, Open Questions §1].
- A chain block *without* the `type ... hook ...` header is
  a regular chain: it has no policy and is reached only via
  jump/goto/vmap (NF11/NF19) [documented — nft(8)].

### NF08 — THE traversal hazard: accept is chain-local, drop is packet-final [documented]

- Within one hook, base chains run one after another in
  priority order (NF07). An `accept` verdict — from a rule,
  or from a chain's policy — ends evaluation of *that chain
  only*; the packet proceeds to the next base chain at the
  same hook, which may still drop it. A `drop` (or `reject`,
  NF12) verdict anywhere ends the packet's traversal of the
  whole ruleset: no later chain at this hook, and no later
  hook on a composed path, is evaluated [documented —
  nft(8) verdicts; secondary sources state the per-chain
  terminality of accept explicitly, and it follows from
  netfilter's hook contract: each base chain is a separate
  hook registration returning a verdict for that registration].
- Consequences the fixtures must pin: an early `accept` rule
  in a priority −100 chain does **not** protect the packet
  from a `drop` rule in a priority 0 chain at the same hook;
  and a composed `--path` verdict is ACCEPT only if *every*
  hook on the path lets the packet through (by rule or by
  policy), DROP as soon as any hook drops it, with the
  deciding rule cited at the hook where it fell.
- `queue` is the exception: it hands the packet to a
  userspace program whose verdict the file cannot know. A
  deciding `queue` makes the traversal outcome
  `QUEUED-UNKNOWN` (NF28), not ACCEPT [design rule from
  documented queue semantics].

### NF09 — Policy is the fallback; return in a base chain means policy [documented]

- If a base chain's rules end with no terminal verdict —
  including when a `return` executes in the base chain
  itself, and when a chain reached by `goto` from it ends
  verdictless (NF11) — the chain's **policy** applies:
  policy accept lets the packet proceed to the next chain
  (NF08), policy drop drops the packet, cited as
  `DROP (policy)` with the chain header's file:line as the
  decider [documented — nft(8): return in a base chain
  applies the chain policy; policy is the chain-end default].
- A regular chain has no policy: ending it verdictless is a
  `return` (NF11), never an implicit accept finding.

### NF10 — Rules: top-down, first terminal verdict decides the chain [documented]

- Inside a chain, rules evaluate in declaration order. A
  rule whose matches all hold (NF13) executes its statements
  in order (NF12); the first *terminal* verdict among them —
  `accept`, `drop`, `reject`, `queue`, or a NAT statement in
  a nat chain (NF22) — decides the chain for this packet,
  and the remaining rules of the chain are not evaluated
  [documented — nft(8); wiki]. Rules with no verdict
  statement, or whose only verdict is `continue`, fall
  through to the next rule even when they match.
- This is the opposite pole from pf's last-match and from
  lighttpd's last-matching-scope (LT09/LT15): in nft, *early*
  rules shadow later ones, and the shadowed-rule report
  (rules after a decider, listed as `[not-reached]` in the
  chain walk) is part of the standard output (NF31).

### NF11 — jump / goto / return: a real call stack [documented]

- `jump CHAIN` evaluates CHAIN's rules; if CHAIN ends
  verdictless or executes `return`, evaluation resumes at
  the rule *after* the jump in the calling chain. A terminal
  verdict inside CHAIN decides as if it stood in the caller
  (subject to NF08's chain-locality at the *base* chain
  level: the base chain is what accept terminates).
- `goto CHAIN` does not return: if CHAIN ends verdictless,
  the *base chain's policy* applies (NF09) — the calling
  chain's remaining rules are dead for this packet, and if
  the goto stood in a regular chain reached by jump, the
  stack unwinds to the base chain, not to the intermediate
  caller [documented — nft(8) verdicts; the unwinding depth
  for goto-inside-jump is docs-inferred, flippable, Open
  Questions §4].
- `return` in a regular chain returns to its caller; in a
  base chain it applies the policy (NF09) [documented].
- Verdicts produced by a *verdict map* behave exactly as if
  written on the rule (NF19), including jump/goto targets.
- Call depth is kernel-limited (chains that would loop are
  rejected at load); a jump/goto cycle reachable in the file
  is therefore a config the kernel would refuse — v1
  detects the cycle statically, reports `[chain-loop]`, and
  returns UNKNOWN (exit 2 if the cycle is on the queried
  traversal), never an infinite walk [design rule].

### NF12 — Statements: order matters, most do not decide [documented]

- A rule is matches (NF13) followed by one or more
  statements executed left to right. Non-terminal statements
  — `counter`, `log ...`, `quota ...` as a statement,
  `limit rate ...` as a statement, `set` mutations (NF23),
  `dup`, `fwd`, `notrack`, `synproxy` — execute and
  evaluation continues within the rule and then the chain
  [documented — nft(8) statements]. A rule may carry several
  statements before its verdict (`counter log ... accept`).
- `reject [with ...]` is terminal like drop, but reported
  distinctly (`REJECT (rule)`, with the reject type — tcp
  reset, icmp/icmpv6 admin-prohibited, etc. — when written)
  [documented — nft(8)].
- Statements after a terminal verdict on the same rule are
  unreachable for a matching packet; v1 lists them as
  `[dead-statements]` when they appear in the deciding rule
  (a common real-world misreading: `accept counter` never
  counts) [design rule].

### NF13 — Matches are conjunctions of expressions [documented]

- All match expressions on a rule must hold for the rule to
  match; expressions evaluate left to right, and any
  expression may be negated (`!=`, `! @set`, `ip daddr !=
  10.0.0.0/8`) [documented — nft(8)]. There is no OR within
  a rule: alternation is written as a set (NF16), a vmap
  (NF19), or a second rule.
- Relational forms modeled exactly in v1: equality and
  inequality against literals, prefixes, ranges (`a-b`),
  and collections; `&`/`|`/shift bit operations against
  constant masks on modeled fields (the `tcp flags & syn ==
  syn` idiom is in this subset); membership in anonymous and
  named collections. Anything outside the modeled expression
  grammar is not approximated: it makes that *expression*
  UNKNOWN, and NF27's three-valued conjunction decides what
  the rule, and then the chain, can still conclude.

### NF14 — The v1 field surface [documented + design rule]

Modeled match fields (a field the query does not supply is
UNKNOWN when a rule on the traversal reads it — NF27 — never
silently defaulted):

- `meta iifname` / `meta oifname` (string compare; `iif` /
  `oif` name forms resolve to the same name compare in v1,
  with a finding: at load, `iif` binds an interface *index*,
  so a rule can match an interface that does not exist yet
  only via `iifname` — for a supplied name both evaluate on
  the name) [documented — wiki, Matching packet
  metainformation].
- `meta l4proto` (protocol number or the symbolic constants
  tcp/udp/icmp/icmpv6/sctp/esp/ah/...), `meta nfproto`
  (ipv4/ipv6 — the inet-family guard, NF15), `meta mark`
  (see NF23), `meta protocol` (ethertype; modeled only to
  distinguish ipv4/ipv6 in inet tables), `meta iiftype` /
  `oiftype` (numeric or `ether`/`ppp`/... constants).
- `ip saddr` / `ip daddr` (literal, prefix, range, set),
  `ip protocol` (next-header number/name), `ip length`,
  `ip ttl`, `ip dscp` (constant compare subset).
- `ip6 saddr` / `ip6 daddr`, `ip6 nexthdr`, `ip6 flowlabel`
  (constant subset).
- `tcp sport` / `tcp dport`, `udp sport` / `udp dport`,
  `sctp sport` / `sctp dport`, generic `th sport` / `th
  dport` (transport-header forms evaluate against whichever
  L4 the packet carries; a `th` match on a packet whose
  `--proto` is not tcp/udp/sctp is FALSE, not UNKNOWN)
  [design rule from documented th semantics].
- `tcp flags` (bitmask idiom of NF13).
- `icmp type` / `icmp code`, `icmpv6 type` / `icmpv6 code`
  (symbolic constants — echo-request, destination-
  unreachable, packet-too-big, ... — are pinned from nft's
  own constant tables, cited in the build's fixtures).

Out of the v1 surface (each is `[unmodeled-field]` → NF25's
UNKNOWN treatment when it decides): ether/vlan/arp header
fields, `ip option`, `ip6` extension-header expressions
(`exthdr`), DNS/name payload matches, raw payload expressions
(`@nh,off,len`, `@th,...`, `@ll,...`), `ct` keys other than
NF21's subset, `meta cpu`, `meta cgroup`, `meta skuid` /
`skgid` unless supplied via flags, `meta time` / `meta day`
/ `meta hour` (wall-clock matches are runtime facts; a
deciding one is UNKNOWN even though its text parses).

### NF15 — THE inet trap: family-mismatched matches are false, not errors [documented]

- In an `inet` table, one ruleset serves both address
  families. An `ip saddr` expression evaluated against an
  IPv6 packet is **false** (the packet has no IPv4 header),
  and an `ip6 daddr` expression against an IPv4 packet is
  false — silently. The idiom that makes real rulesets
  correct is guarding with `meta nfproto` or splitting by
  hook behavior; the misreading that makes them wrong is
  assuming an `ip`-only rule “covers both” [documented —
  the inet design in nft(8) and the wiki's family model;
  the falseness (rather than error) is docs-inferred from
  the expression model and is a headline fixture].
- Family gating of *tables* (NF05) is separate: an `ip`
  table is skipped entirely for IPv6, while inside an
  `inet` table every rule is *visited* and family-mismatched
  expressions fail individually. A rule mixing `ip saddr`
  and `ip6 daddr` matches nothing, ever, and v1 says so with
  a `[never-matches]` finding when the conjunction is
  unsatisfiable on family grounds alone.

### NF16 — Anonymous sets, ranges, prefixes [documented]

- `{ e1, e2, ... }` after a field is membership; elements
  may be literals, prefixes (`10.0.0.0/8`), ranges
  (`8000-9000`, `10.0.0.10-10.0.0.20`), and — for verdict
  positions — NF19's maps. Membership is exact set semantics
  v1 computes directly. An empty anonymous set matches
  nothing (and is a `[never-matches]` finding).
- Flags written on anonymous collections (`{ ..., flags
  interval; }` is not anonymous-set syntax — intervals arise
  from range/prefix elements themselves) need no modeling:
  overlap between a packet value and any element decides.
  Overlapping elements with *different* consequences are a
  maps problem (NF19), not a sets problem: set membership is
  boolean.

### NF17 — Named sets: declared, typed, and (usually) static [documented]

- `set NAME { type TYPE; [flags ...;] [elements = { ... }] }`
  inside a table; referenced as `@NAME` from rules in that
  table [documented — nft(8)]. Types include single-field
  types (`ipv4_addr`, `inet_service`, `ifname`, `mark`, ...)
  and concatenations (NF20). `flags interval` is required
  for range/prefix elements to be legal; its absence around
  range elements is a load error in nft — v1 reports it as a
  poison on that set, not as a silent reinterpretation
  [design rule].
- A named set with constant `elements` and no runtime flags
  is exact: membership is computed from the file, and the
  deciding citation names both the rule line and the set
  declaration's file:line (dual provenance — no other
  who-tool on the bench has needed it; sets are where nft
  answers actually live).
- A set declared *without* elements starts empty at load;
  if nothing in the stream populates it (NF02's `add
  element`), lookups against it are FALSE with an
  `[empty-at-load]` finding — *unless* NF18 applies.

### NF18 — Dynamic and timeout sets poison their lookups [documented flags + design rule]

- Set flags `dynamic` and `timeout` (and per-element
  `expires`/`timeout` values) mean the set's contents at
  packet time are not the file's contents: other programs
  (`nft add element` from fail2ban, sshguard, cron) and
  expiry change membership without touching the file
  [documented — nft(8) set flags; the runtime-mutation
  channel is the documented purpose of `dynamic`].
- Pinned treatment: a lookup against a `dynamic` set is
  UNKNOWN in both directions (a hit may have been removed, a
  miss may have been added). A lookup against a `timeout`
  set: a *hit* on a listed element is TRUE with a
  `[set-element-may-expire]` finding (the element was loaded
  from the file; expiry is the only hazard), a *miss* is
  UNKNOWN (an unlisted element may have been added with a
  timeout). If the lookup decides the traversal, the verdict
  degrades per NF27 — this is the single largest honest-
  UNKNOWN source in real-world rulesets and the README must
  say so.
- Named *counters*, *quotas*, and *limits* referenced by
  rules (`counter name X`, `quota name Y`) are stateful
  objects: as statements they never decide (NF12); a named
  quota/limit used as a *match* is NF24.

### NF19 — Maps and verdict maps: dispatch without a rule ladder [documented]

- A verdict map appears as a statement-position lookup:
  `FIELD vmap { k1 : VERDICT1, k2 : jump CHAIN, * : drop }`
  or via a named map of type `... : verdict` referenced as
  `FIELD vmap @NAME` [documented — nft(8); wiki]. The `*`
  element is the map's default: a key with no entry and no
  `*` makes the vmap produce **no verdict** — evaluation
  continues to the next statement/rule exactly as if the
  rule had not matched (it is not an implicit policy)
  [documented — vmap semantics; a headline fixture, since
  the iptables intuition “no entry = drop” is wrong].
- Overlapping keys in one map (a prefix containing the
  packet's address *and* a more specific entry) resolve by
  most-specific match for interval types [docs-inferred —
  interval lookup semantics; flippable, Open Questions §5];
  duplicate identical keys are a load error in nft and a
  poison in v1.
- Data maps (`dnat to FIELD map @NAME`, `meta mark set
  FIELD map @NAME`, named maps of non-verdict type) feed a
  statement with the mapped value; a missing key means the
  *statement does not execute* (for NAT: no binding, chain
  continues) [documented]. Mapped values flow into NF22/NF23
  exactly as literals do when the map is static.
- Named maps are runtime-updatable through the same channel
  as NF18; a named map **without** dynamic/timeout flags is
  still updatable by a privileged `nft add element` at any
  time — v1's line, pinned: named maps and sets are treated
  as file-exact *unless* flagged dynamic/timeout, because
  the bench's question is “what does this file say”, and the
  coverage banner (NF31) states that runtime element changes
  are outside the file on every run. (NF18's poison is for
  flags that declare the mutability *in* the file.)

### NF20 — Concatenations are tuple matches [documented]

- Fields joined by `.` (`ip saddr . tcp dport`,
  `iifname . ip saddr`) compare against tuple elements of
  anonymous sets, named concat-typed sets, and concat-typed
  maps, element-wise [documented — nft(8), concatenations
  since kernel 4.15 / nft 0.9]. Each component evaluates
  under its own NF14/NF15 rules — a family-mismatched
  component makes the tuple element false, and an UNKNOWN
  component makes the tuple UNKNOWN per component position
  (NF27), which is exactly how a concat lookup can be
  “known for this key, unknown for that one”.

### NF21 — Conntrack expressions: state is an input, not a derivation [documented + design rule]

- `ct state` is one of `new`, `established`, `related`,
  `invalid`, `untracked` (and bitmask combinations of them)
  [documented — wiki, Matching connection tracking
  stateful metainformation]. nftwho never derives a packet's
  ct state from its other fields — the state is a fact about
  the connection's history. The query supplies it via
  `--ctstate`; a traversal whose deciding rules read
  `ct state` while none was supplied is UNKNOWN (NF27), and
  the chain walk shows which rules were blocked on it. This
  one flag is the difference between a useful answer and a
  plausible one on nearly every real ruleset, whose second
  rule is usually `ct state established,related accept`.
- `ct status` (expected/seen-reply/assured/confirmed/snat/
  dnat/dying bits), `ct direction`, and `ct mark` (NF23)
  are modeled only as supplied-or-set constants; every other
  ct key (`ct helper`, `ct timeout`, `ct original ...`,
  `ct reply ...`, `ct expectation`) is `[unmodeled-field]`
  under NF25 when it decides.
- `notrack` as a statement marks the packet untracked from
  that point: a later `ct state` read on the same traversal
  sees `untracked` from the notrack point onward [docs-
  inferred from conntrack semantics; modeled in the walk,
  flagged in Open Questions §6].

### NF22 — NAT: first packet only, terminal in its chain, reported separately [documented + design rule]

- Chains of `type nat` are traversed **only for the first
  packet of a connection**; later packets take their binding
  from the conntrack entry and skip nat chains entirely
  [documented — wiki, Configuring chains; RHEL matrix]. In
  the walk: if `--ctstate` is supplied and is not `new`,
  nat chains on the traversal are shown as
  `[skipped — not first packet]`; if `--ctstate` is absent
  and a nat chain sits on the queried traversal, the *NAT
  outcome* (only) is UNKNOWN, while filter verdicts still
  resolve (the report separates the two, NF28).
- A matching NAT statement — `dnat to ADDR[:PORT]`,
  `snat to ADDR`, `masquerade`, `redirect to :PORT`,
  `tproxy to ...` (tproxy is reported with NAT outcomes
  though it is a route-type mechanism) — is **terminal for
  its chain**: the first matching NAT rule binds, later
  rules in that nat chain are not evaluated for the binding
  [documented — nft(8) NAT statement terminality]. The
  outcome is reported as data: kind, target value(s), and
  the deciding rule's file:line, including values produced
  by a static data map (NF19).
- Address rewriting is **not** folded into later matches: a
  DNAT in prerouting changes the destination the routing
  decision (and later hooks' `ip daddr` matches) would see,
  and modeling the rewritten tuple through the rest of the
  path is a fidelity cliff (routing itself intervenes,
  NF06). Pinned honesty split: per-hook answers after a NAT
  outcome are still computed against the *supplied* tuple
  and are exact as per-hook answers; a *composed path*
  verdict is degraded to UNKNOWN with a `[nat-rewrites-
  tuple]` banner whenever (a) a NAT outcome fired on an
  earlier hook of the path and (b) any later deciding match
  on the path reads a field that NAT kind rewrites. If no
  later deciding match reads a rewritten field, the path
  verdict stands and carries the NAT outcome as a finding.

### NF23 — Mark mutation is modeled state [design rule from documented statements]

- `meta mark set VALUE` and `ct mark set VALUE` mutate state
  that later rules — in the same chain, in later chains at
  the hook, and (for meta mark) at later hooks of a composed
  path — can match on [documented — nft(8) set statements].
  v1 tracks both marks as part of the walk's packet state:
  seeded from `--mark` (meta mark) and unsupplied/UNKNOWN
  for ct mark, updated by constant-valued set statements and
  by static data-map lookups (NF19) in exact traversal
  order. A set statement whose value is an expression over
  packet fields (`meta mark set ct mark`, jhash-derived,
  arithmetic on the old mark with non-constant operands)
  makes that mark UNKNOWN from that point, and any later
  deciding read degrades per NF27 — the walk shows the
  mutation line either way.
- `meta priority set` and `ct label set` are not tracked
  (no v1 field reads them); a set statement for them is a
  finding, not a poison, unless a later unmodeled read
  decides (NF25).

### NF24 — Rate-shaped matches are runtime facts [documented + design rule]

- `limit rate [over] X/unit [burst B]`, `quota ...` used as
  a *match expression*, and `meter` / dynamic-meter
  constructs depend on how much traffic has already passed:
  no static file can decide them. When such a match decides
  a rule on the traversal, that rule's match is UNKNOWN
  (NF27), with a `[rate-dependent]` finding [design rule].
- The same words as *statements* (`... limit rate 10/minute
  accept` is a match use; `log ... limit rate 10/minute` is
  a statement use) never gate a verdict by themselves and
  are findings only. The parser must distinguish the two
  positions; confusing them is the classic misbuild of this
  tool, and BG7 pins both shapes.

### NF25 — Runtime expressions are UNKNOWN, never approximated [design rule]

When a deciding match reads any of the following, that
expression is UNKNOWN (NF27), with the named finding —
v1 does not approximate, emulate, or shell out:

- `fib ...` (routing-table lookup: `fib daddr . iif type
  local` is common and is *the* idiom whose answer lives in
  `ip route`, not in this file) → `[routing-dependent]`.
- `jhash` / `symhash` / `numgen` / `hash` expressions →
  `[hash-or-random]` (numgen random is runtime by
  definition; the hashes are deterministic in the kernel but
  their seed/state surface is outside a faithful static
  model — honesty over cleverness).
- `socket transparent` / `socket cgroupv2` / `meta skuid` /
  `skgid` without the corresponding supplied flag →
  `[process-context]`.
- Raw payload expressions (`@nh`, `@th`, `@ll`, `@ct`) and
  any NF14 out-of-surface field → `[unmodeled-field]`.
- `meta time` / `day` / `hour` → `[wall-clock]`.
- Anything the recognizer cannot classify → NF29.

### NF26 — Names in rules: hostnames poison, service names are hermetic [documented + design rule]

- A hostname written where an address belongs is resolved
  by nft **at load time** via DNS; the file does not contain
  the answer, and the answer can change between loads. Any
  deciding match containing a hostname literal is UNKNOWN
  with a `[load-time-dns]` finding; a hostname in a set's
  elements poisons that set's lookups the same way
  [documented — nft resolves hostnames when loading].
- Symbolic service names (`tcp dport ssh`) are resolved by
  nft from the system services database at load. v1 is
  hermetic (family rule): it resolves them **only** from a
  file passed via `--services` (an /etc/services-format
  file the caller supplies), never from the host's own
  /etc/services — the tool's environment must not leak into
  the answer (the lighttpdwho env-trap, LT07). Without
  `--services`, a deciding match on a symbolic service name
  is UNKNOWN with a `[symbolic-service]` finding; numeric
  ports are always exact. The same hermeticity applies to
  symbolic protocol names (pinned built-in table — protocol
  numbers are IANA constants, cited in fixtures) and ct-state
  / icmp-type constants (NF14).

### NF27 — Three-valued evaluation and the Kleene core [design rule]

- Every match expression is TRUE, FALSE, or UNKNOWN.
  Rule match = AND over its expressions: FALSE if any is
  FALSE, UNKNOWN if none is FALSE and at least one is
  UNKNOWN, TRUE otherwise. A rule whose match is UNKNOWN
  cannot decide, but it also cannot be skipped silently: it
  stays in the walk as a *blocking candidate*.
- Traversal semantics under uncertainty, per chain: walk in
  order; a TRUE rule with a terminal verdict decides
  *unless* an earlier blocking candidate could have decided
  differently — if an earlier rule's match is UNKNOWN and
  its verdict (if it matched) would terminate the chain,
  the chain's outcome is UNKNOWN **citing that rule**, even
  when a later rule matches truly (the absorption rule is
  one-directional: uncertainty *before* the decider poisons,
  uncertainty *after* a TRUE decider is inert, because the
  decider fires first in real evaluation too). A chain whose
  rules all fall through under uncertainty applies NF09
  only when the fall-through itself is certain (no blocking
  candidate anywhere in the chain); otherwise the chain is
  UNKNOWN and the hook walk stops there for verdict
  purposes (later chains might still drop in reality —
  which is precisely why the answer is UNKNOWN, not the
  next chain's).
- The same composition lifts to hooks (NF08) and to path
  composition (NF06), and to mark state (NF23) and NAT
  (NF22): the report always names the *earliest* blocking
  candidate on the traversal — that line is the answer to
  “what would I have to pin down to get a verdict”.

### NF28 — Verdict vocabulary (exact) [design rule]

Text and JSON report, for the queried traversal:

- `ACCEPT (rule)` — a rule's accept decided; decider cited.
- `ACCEPT (policy)` — every chain on the traversal fell
  through to an accept policy (or there were chains and all
  accepted); the *last* chain's policy line cited, walk
  shown.
- `DROP (rule)` / `DROP (policy)` / `REJECT (rule)` —
  symmetric; the drop/reject decider cited.
- `NOT-EVALUATED` — no base chain of an applicable family
  exists at the hook (for `--path`: the path had no chains
  at all); exit 1.
- `QUEUED-UNKNOWN` — a `queue` verdict decided the
  traversal (NF08); exit 2.
- `UNKNOWN` — a blocking candidate (NF27) or poison
  (NF18/NF25/NF26/NF29) prevents a verdict; the earliest
  blocker cited; exit 2.
- NAT outcome, when a nat chain was on the traversal, is a
  separate block: `NAT: dnat to 10.0.0.5:8080 (rule at
  FILE:LINE)`, `NAT: masquerade (...)`, `NAT: none (no nat
  rule matched; chains walked: ...)`, `NAT: skipped (not
  first packet)`, or `NAT: UNKNOWN (blocker at FILE:LINE)`.

Exit codes (family standard): **0** = ACCEPT (rule or
policy); **1** = DROP / REJECT (rule or policy) or
NOT-EVALUATED; **2** = UNKNOWN / QUEUED-UNKNOWN, usage
error, unreadable or unloadable ruleset (missing literal
include, include cycle, unparseable stream on the queried
objects).

### NF29 — Unparseable and unmodeled constructs poison positionally [design rule]

- The recognizer classifies every statement, chain, set,
  and rule in the merged stream. Anything it cannot classify
  is an `[unparseable]` finding attached to its file:line —
  never silently skipped (a skipped `add rule` is how a
  provenance tool starts lying).
- Positional rule (the family's absorption discipline): an
  unparseable *rule* poisons its chain's walk from its
  position onward (earlier deciders still decide — NF27);
  an unparseable *statement inside a rule* makes that rule's
  execution UNKNOWN-if-matched; an unparseable declaration
  (set/map/chain header) poisons every lookup of that
  object. Constructs nft itself would reject (duplicate set
  keys, goto to a missing chain, jump cycles) are reported
  as `[load-would-fail]` findings but the walk continues on
  the modeled remainder — the tool explains files, including
  broken ones; it is not a validator (see below).
- `route`-type base chains (`type route hook output`) can
  *reroute* packets with `reroute` statements: a deciding
  reroute on a `--path out` traversal degrades the path
  verdict to UNKNOWN with `[reroute]` (the new path is a
  kernel decision), while the output-hook answer stays
  exact.

### NF30 — Safety: the ruleset is data, and it is never loaded [family rule]

- nftwho opens ruleset files read-only, executes nothing,
  and **never** invokes `nft` (or anything else) on the
  queried file: no `nft -f`, no `nft -c -f` on user files,
  no `nft list ruleset` — the live kernel state is not an
  input, both because it may differ from the file and
  because reading it needs privileges the tool must not
  require. The optional test-suite cross-check against
  `nft -c -f` (Build order §4) runs only on the suite's own
  hermetic fixtures, is skip-guarded when no `nft` binary
  exists, and is never part of answering a query.
- A ruleset is adversarial input in the family's sense:
  include paths, define bombs (a define expanding to a
  define expanding to ...), and element-list floods are
  bounded (stream size cap, expansion depth cap, include
  depth cap — exceeding any is exit 2 with the cap named),
  and no path in a config is ever written to, executed, or
  followed outside the include resolution of NF03.

### NF31 — Coverage on every run [design rule]

Every answer (including NOT-EVALUATED and UNKNOWN) ends
with a coverage block naming: every file read (with the
include edge that reached it), every table and base chain
considered on the traversal (with priority and policy),
every chain walked rule-by-rule with each rule's outcome
(decider / no-match / not-reached / blocking candidate),
every set/map consulted with its declaration site, every
define expanded on the path, and every banner that applied
(NF05 ingress, NF18 dynamic sets, NF22 NAT, NF29 unmodeled
commands). `--list-chains` prints the full base+regular
chain inventory with hook/priority/policy/provenance;
`--list-sets` prints every set/map with type, flags,
element count, and provenance. A reader must be able to
audit the verdict from the coverage alone.

## CLI, exits, and output contract

- Exactly one of `--hook` / `--path` is required for a
  packet query (both is a usage error, exit 2); the packet
  fields are flags, all optional, and every omitted field is
  a potential UNKNOWN source the walk will name (NF27) —
  there are no defaults for packet fields, ever. `--family`
  defaults to ipv4 only when `--saddr`/`--daddr` are both
  IPv4 literals; if the addresses disagree with `--family`,
  that is a usage error, not a silent coercion.
- Output order: verdict line first (NF28 vocabulary), NAT
  block second when applicable, then the hook-by-hook /
  chain-by-chain walk, then findings, then coverage (NF31).
  `--json` mirrors the same structure field-for-field.
  `--quiet` prints only the verdict line (and NAT block).
- Inventory modes (`--list-chains`, `--list-sets`) need no
  packet flags and exit 0 on a loadable stream, 2 on a load
  failure.

## Out of scope (bannered, never silently modeled)

- arp / bridge / netdev tables and the ingress match surface
  (ether, vlan, pppoe headers) — NF05.
- Routing decisions, fib lookups, and anything that depends
  on the kernel's tables rather than this file — NF01/NF25.
- Other writers' rules (firewalld / Docker / kube-proxy
  inject their own nft objects at runtime): the file is the
  whole universe of the answer, and the coverage banner
  says so on every run — NF01.
- Flowtables and `flow add` offload: a deciding `flow`
  statement on a path degrades the path verdict like NF29's
  reroute (fast-path state is runtime), bannered, never
  modeled.
- Stateful objects' live values (counters, quota remaining,
  limit buckets, conntrack table contents) — NF18/NF24.
- xtables-compat (`xt statement`) rules: `[unmodeled-field]`
  under NF25 when deciding, finding otherwise.
- BIRD-style “just run the daemon and ask it” equivalence:
  there is no safe static oracle (Thinness §3), and the tool
  does not pretend the walk is the kernel — it is the
  *documented semantics* of the file, fixtures pinned to
  nft(8).

## Not a validator (deliberate divergence, documented)

`nft -c -f` already validates, better than a reimplementation
ever will. nftwho therefore *explains broken files too*:
constructs nft would reject are `[load-would-fail]` findings
(NF29), the walk proceeds over the modeled remainder, and
only outright unloadability (missing file, missing literal
include, include cycle, tokenizer failure) is exit 2.
Conversely, a file can be perfectly valid and still get
UNKNOWN — validity and decidability are different axes, and
collapsing them is the failure mode of the validators this
bench does not build.

## Hazards reviewed (why this design is safe to build)

1. **Accept-is-final misreading (NF08).** The single most
   common nftables misunderstanding carried over from
   iptables-era intuition in both directions — some readers
   think the first accept ends the hook (it ends the
   *chain*), others think policy accept in one table
   overrides another table's drop at the same hook (it does
   not). The design pins netfilter's per-registration
   verdict contract and makes the multi-chain walk the
   primary output, so the answer shows every chain the
   packet still has to survive.
2. **Policy-vs-decider confusion (NF09/NF28).** Most “why
   was this dropped” questions end at a chain policy nobody
   remembers setting (or the *default* accept nobody
   remembers either). Policies are first-class deciders with
   their own provenance (the chain header line), never
   folded into a bare DROP.
3. **The inet trap (NF15).** A rule can textually name the
   packet's exact address and still be false. Any design
   that evaluates address matches without family context
   ships this bug; NF15 makes family a per-expression input,
   not a per-file one.
4. **goto amnesia (NF11).** `goto`'s fall-through goes to
   the base chain's policy, skipping the caller's remaining
   rules *and* any intermediate jump frames. Tools (and
   readers) that model goto as jump-without-return-address-
   but-same-fallthrough get real rulesets wrong; NF11 pins
   the unwinding explicitly and BG2 fixtures it three deep.
5. **vmap no-entry fall-through (NF19).** “No entry, no
   verdict” is the opposite of the map intuition most
   operators bring. Pinned, fixtured, and called out in the
   README limitations.
6. **Dynamic-set honesty (NF18).** The bench's standing
   failure mode would be answering crisply over a fail2ban
   set. NF18 spends precision exactly where the file declares
   its own mutability and keeps file-static sets exact —
   the asymmetry is the design's center of gravity.
7. **NAT composition cliff (NF22).** Folding DNAT into
   later matches would require modeling routing. The design
   refuses, splits per-hook exactness from path-level
   honesty, and names the rewritten field that forced the
   degradation.
8. **Hermeticity (NF26/NF30).** Load-time DNS, the host's
   /etc/services, and the live kernel ruleset are three
   different ways for the *environment* to contaminate a
   file question. All three are closed, two by UNKNOWN and
   one by never looking.

## Test plan (hermetic fixture rulesets; stdlib-only runner)

~81 tests, plain `python3` (no pytest — the aptpinswho
lesson). Every fixture is a small ruleset tree in a tmpdir;
the harness asserts no network, no subprocess (except the
skip-guarded NF30 fixture cross-check), no writes outside
the tmpdir, and no reads of the host's /etc/services or live
ruleset (trap fixtures plant both).

- **BG1 (core traversal, NF06–NF10) — 10 tests:** single
  input chain, rule accept (exit 0, decider cited); policy
  drop decides (exit 1, policy line cited); two tables'
  input chains at priorities −100/0: early accept does
  **not** stop the later chain's drop (NF08 fixture — the
  tool's reason to exist); early drop stops everything
  (later chain shown not-walked); same-priority collision
  finding (NF07); `--path in` composition across prerouting
  + input; `--path forward` skips input chains entirely;
  hook with no chains → NOT-EVALUATED exit 1; rule with no
  verdict falls through; `continue` verdict falls through.
- **BG2 (jump/goto/return/vmap, NF11/NF19) — 9 tests:** jump
  returns and caller continues; jump target's terminal
  verdict decides; goto exhaustion → base policy (caller's
  later rules shown dead); goto nested inside a jumped chain
  unwinds to base policy (§4 hypothesis fixture); return in
  regular chain vs in base chain (policy); vmap dispatch to
  jump target; vmap `*` default; vmap **no entry and no
  default → no verdict, evaluation continues** (NF19
  fixture); jump cycle → `[chain-loop]` UNKNOWN exit 2.
- **BG3 (fields & families, NF05/NF14/NF15) — 10 tests:**
  ip table skipped for an IPv6 packet (NOT-EVALUATED for
  that table in coverage); inet table: `ip saddr` rule false
  for IPv6 packet while `ip6 saddr` twin decides (NF15
  fixture); mixed `ip saddr` + `ip6 daddr` rule →
  `[never-matches]`; `meta nfproto ipv4` guard restores
  decidability; tcp dport vs `th dport` on a UDP packet
  (tcp rule no-match, th rule matches udp); omitted
  `--dport` with a port-reading candidate → UNKNOWN citing
  it; tcp flags idiom `& syn == syn` true/false; icmp type
  symbolic constant; iifname match with interface name
  containing a space (quoted token, NF00); arp table present
  → banner, verdict unaffected.
- **BG4 (sets, maps, concatenations; NF16–NF20) — 10
  tests:** anonymous set membership hit/miss; range and
  prefix elements; named static set hit with dual provenance
  (rule line + set line); named set declared empty →
  `[empty-at-load]` FALSE; `add element` stream population
  (NF02); concat `saddr . dport` tuple hit, and tuple with
  one UNKNOWN component (NF20); interval set with prefix
  elements; data map feeding `meta mark set` then a later
  mark match deciding (with NF23); named vmap via `@name`;
  data map miss → statement does not execute, chain
  continues (NF19).
- **BG5 (stream: includes, defines, flush; NF02–NF04) — 8
  tests:** include splices mid-table; nested include's
  relative path resolved against the *including* file's
  directory with a decoy file in the main file's directory
  that must NOT be read (NF03 fixture — the anti-LT03);
  wildcard include sorted order deciding a same-chain
  duplicate via two files; wildcard no-match is silent-OK;
  literal missing include → exit 2; define used in a match
  and in a set literal, redefinition splits uses (NF04);
  `flush ruleset` mid-stream discards earlier tables;
  `delete`-by-handle on an unrelated table → finding only,
  on the queried chain → poison UNKNOWN.
- **BG6 (conntrack & NAT, NF21/NF22) — 9 tests:** `ct state
  established,related accept` decides with `--ctstate
  established`; same ruleset without `--ctstate` → UNKNOWN
  citing that rule, later true decider **not** absorbed
  (NF27 direction); nat chain decides DNAT for
  `--ctstate new` (NAT block, target + provenance); nat
  chain `[skipped — not first packet]` for `--ctstate
  established`; nat outcome UNKNOWN while filter verdict
  still resolves without `--ctstate`; first matching NAT
  rule binds, second shown not-reached; composed path with
  DNAT + later `ip daddr` decider → path UNKNOWN with
  `[nat-rewrites-tuple]`, per-hook answers intact; composed
  path with DNAT + no later daddr reader → path verdict
  stands, NAT as finding; `notrack` then `ct state`
  untracked match (NF21).
- **BG7 (mutation & runtime poison, NF23–NF25) — 8 tests:**
  constant `meta mark set` in prerouting decides a forward-
  chain `meta mark` match on `--path forward`; mark set
  from packet-field expression → later mark read UNKNOWN;
  `limit rate over ...` as a *match* → `[rate-dependent]`
  UNKNOWN-if-deciding; `limit` as a *statement* on the
  deciding rule → verdict stands; `fib daddr . iif type
  local` decider → `[routing-dependent]` UNKNOWN; jhash
  match → `[hash-or-random]`; quota-as-match poison vs
  named counter statement harmless; `queue` verdict →
  QUEUED-UNKNOWN exit 2.
- **BG8 (three-valued core & absorption, NF27/NF29) — 6
  tests:** UNKNOWN-match rule *before* a TRUE decider →
  UNKNOWN citing the blocker; UNKNOWN-match rule *after* a
  TRUE decider → decider stands (absorption direction);
  UNKNOWN in a jumped chain poisons the base chain's walk
  from the jump line; FALSE-and-UNKNOWN conjunction →
  rule is no-match, walk proceeds; unparseable rule mid-
  chain poisons from its position (earlier decider still
  decides in the twin fixture); unparseable set declaration
  poisons only that set's lookups.
- **BG9 (names & safety, NF26/NF30) — 5 tests:** symbolic
  `tcp dport ssh` without `--services` → `[symbolic-
  service]` UNKNOWN; with `--services` fixture (ssh=2222 in
  the fixture file, deliberately not 22) → resolves to the
  fixture's value, proving hermeticity; hostname literal in
  a deciding match → `[load-time-dns]` UNKNOWN; include
  path traversal outside the ruleset tree via `../` chains
  is followed only through NF03 resolution (no other file
  type is ever opened — a fixture plants an executable and
  a FIFO as decoys); define-expansion bomb hits the depth
  cap → exit 2 naming the cap, and the marker-file test:
  no fixture content is ever executed or loaded (assert no
  marker, no nft state change).
- **BG10 (inventory, coverage, CLI; NF28/NF31) — 6 tests:**
  `--list-chains` full inventory across families with
  priorities normalized (keyword → number); `--list-sets`
  with flags and element counts; coverage completeness —
  every fixture asserts all files/chains/rules/sets are
  named in the block; `--json` verdict parity with text on
  the BG1 matrix; `--quiet` prints verdict (+NAT) only;
  exit-code matrix sweep (0/1/2 across ACCEPT/DROP/REJECT/
  NOT-EVALUATED/UNKNOWN/QUEUED/load-failure).

Dogfood: doccover + clicheck clean before the v1 commit, per
bench convention. README carries a Limitations section naming
NF08/NF15/NF18/NF19/NF22/NF25 and the Out-of-scope list
explicitly, plus a pre-publish checklist.

## Build order

1. Tokenizer + stream loader (NF00 statement orientation,
   NF02 merged stream + flush/add modeling, NF03 include
   resolution, NF04 defines, NF29 recognizer + caps NF30).
2. Object model (tables/chains/sets/maps with provenance;
   NF07 priority normalization; NF17/NF19/NF20 collection
   semantics) + field evaluator (NF14 surface, NF15 family
   context, NF13 conjunction/bit ops, NF26 name resolution).
3. Traversal engine (NF06 hook/path composition, NF08
   multi-chain walk, NF09 policy, NF10 rule order, NF11
   call stack, NF21 ct inputs, NF22 NAT separation, NF23
   mark state, NF24/NF25 runtime poisons, NF27 three-valued
   composition) + renderers (text/JSON, NF28 vocabulary) +
   coverage (NF31) + inventory modes.
4. Dogfood: doccover + clicheck --strict; optional
   skip-guarded `nft -c -f` parse cross-check over the
   fixture corpus (fixtures the real parser rejects get
   `[load-would-fail]` expectations reviewed, never silently
   dropped); bench-audit map extension; prepublish-check
   clean; README + CHANGELOG.

## Open questions / flippable hypotheses

1. **Same-priority base-chain order (NF07).** v1 pins
   merged-stream declaration order with a finding. If a
   documented registration-order rule (or a fixture pair
   cross-checked against kernel behavior in a disposable
   namespace by a human) shows table-name or creation order
   instead, only the colliding-chains fixtures flip.
2. **Include fallback order (NF03).** v1 pins
   --includepath-then-including-file's-directory. nft(8)'s
   includepath text admits a working-directory step in some
   versions; if the pinned nft range's text settles it
   differently, NF03's search list changes and BG5's decoy
   fixture gains a third decoy.
3. **Define redefinition (NF04).** Single-pass later-wins is
   inferred from parse-time substitution. If nft in fact
   rejects redefinition, redefinition becomes
   `[load-would-fail]` and BG5's split-uses fixture flips to
   a poison expectation.
4. **goto unwinding depth (NF11).** v1 pins goto exhaustion
   to the *base* chain's policy even when the goto sits in a
   chain reached by jump. If the kernel instead applies the
   *calling regular chain's* fall-through (resume after the
   jump), BG2's three-deep fixture flips and NF11's stack
   description narrows.
5. **vmap overlap resolution (NF19).** Most-specific-match
   for interval keys is inferred from interval lookup
   semantics. If nft's map lookup is exact-key with interval
   elements resolved first-inserted, overlapping-map
   fixtures flip; non-overlapping maps (the overwhelming
   real-world case) are unaffected either way.
6. **notrack → ct state visibility (NF21).** v1 models a
   later `ct state` read on the same traversal as seeing
   `untracked` after `notrack`. Conntrack is attached at
   specific priorities per hook, so cross-hook visibility
   may differ from same-hook visibility; the fixture pair
   splits if a source read settles it.
7. **accept chain-locality at ingress (NF08).** The pin
   follows netfilter's per-registration contract for the
   five classic hooks. The inet/netdev *ingress* hook has
   its own early-demux behavior in some kernels; v1 already
   quarantines ingress behind NF05, and this question is
   why.

## Sources (read 2026-11-09)

- nft(8) — nftables 1.0.9, local binary (`nft --version`
  observed) and the nft source's doc/nft.8 text via the
  DeepWiki mirror (tables/chains/priorities:
  https://deepwiki.com/datdd101/nft/3.1-tables-and-chains ;
  verdicts and actions:
  https://deepwiki.com/datdd101/nft/5-verdicts-and-actions )
  — chain types, priority keyword values (raw −300, mangle
  −150, dstnat −100, filter 0, security 50, srcnat 100;
  bridge dstnat −300, filter −200, srcnat 300), verdict
  semantics (accept/drop/continue/return/jump/goto), vmap
  value classes, NAT statement set.
- nftables wiki — Scripting (includes: wildcards, no-match
  not an error, dotfiles skipped, −I search path; defines
  and `$` substitution; the two `nft -f` file formats):
  https://wiki.nftables.org/wiki-nftables/index.php?title=Scripting&oldid=200
- nftables wiki — Configuring chains (base vs regular
  chains, priority ordering by increasing value, nat chains
  see only a connection's first packet):
  https://wiki.nftables.org/wiki-nftables/index.php?title=Configuring_chains&oldid=686
- nftables wiki — Netfilter hooks (hook set per family/type,
  ingress availability, internal priority landmarks —
  conntrack at −200, defrag at −400):
  https://wiki.nftables.org/wiki-nftables/index.php?title=Netfilter_hooks&oldid=950
- nftables wiki — Matching connection tracking stateful
  metainformation (ct state values and meanings; ct key
  surface):
  https://wiki.nftables.org/wiki-nftables/index.php?title=Matching_connection_tracking_stateful_metainformation&oldid=898
- nftables wiki — Matching packet metainformation (meta
  selectors incl. iifname/oifname, mark, nfproto):
  https://wiki.nftables.org/wiki-nftables/index.php?title=Matching_packet_metainformation&oldid=624
- nftables wiki — Data types (ct_state bit values incl.
  untracked; symbolic constant tables):
  https://wiki.nftables.org/wiki-nftables/index.php?title=Data_types&direction=prev&oldid=923
- Red Hat — Getting started with nftables (chain-type ×
  family × hook matrix; standard priority matrix; nat
  first-packet rule):
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-nftables_configuring-and-managing-networking
- eFeFlow — the third-party simulator adjudicated in
  Thinness §4 (packet simulation over its own ruleset model,
  hosted web IDE, no source provenance):
  https://efeflow.efespain.com/en/
- Linux nftables basics (secondary; per-chain terminality of
  accept stated explicitly, policy default):
  https://www.tomho.eu/linux_nftables.html
- Candidate adjudication sources: Kea ARM management API
  (`subnet4-select-test` / `subnet6-select-test` commands,
  via https://kea.readthedocs.io/en/kea-2.7.5/arm/ctrl-channel.html );
  BIRD User's Guide (`show route ... filter`, `eval`, `bird
  -p`, via https://bird.nic.cz/doc/bird-3.3.2.html );
  varnishtest(1) and varnishd(1) (`-C` C dump), Redis
  CONFIG GET documentation and the stock redis.conf include
  commentary, smtpd.conf(5) first-match text (OpenSMTPD —
  held in reserve, see Verdict).

## Verdict

**BUILD APPROVED.** The gap holds in full: `nft -c`
validates without adjudicating, `nft list ruleset` describes
a live kernel in flattened handles with no source
provenance, `nft monitor trace` needs live marked traffic
and root, and the one third-party simulator works over a
pasted dump on a hosted website — none of them answers
“which rule in which file decides this packet at this hook”
for a ruleset an operator is about to deploy. The semantics
are pinnable from nft(8) and the wiki to the precision this
tool needs — priority-ordered multi-chain traversal with
chain-local accept and packet-final drop (NF08), policy as a
provenance-carrying decider (NF09), a real jump/goto/return
call stack (NF11), verdict maps whose no-entry case falls
through (NF19), and the inet family's silent-false trap
(NF15) — with the genuinely uncertain points (same-priority
order, include fallback, define redefinition, goto
unwinding, vmap overlap, notrack visibility) isolated as
flippable hypotheses whose fixtures pin the chosen reading.
The honesty machinery is load-bearing and is placed where
real rulesets actually go dynamic: flagged dynamic/timeout
sets (NF18), runtime-rate matches (NF24), routing/hash/
process expressions (NF25), load-time DNS (NF26), and the
NAT composition cliff (NF22) — each degrades to a *named*
UNKNOWN rather than a confident guess, while the large
static core (fields, sets, maps, marks, ct state as an
input) decides exactly. Build in the order above; the v1
commit gate is the BG1–BG10 suite green plus
doccover/clicheck clean. **Publishing is NOT covered by
this verdict** — nftwho was not among the campaign's
pre-approved tools; it follows the normal per-project
approval path when built. One reserve note: opensmtpdwho
passed its gap test too (smtpd.conf(5) first-match is
crisply pinned and `smtpd -n` only validates) and is the
queued next candidate if a future discovery pass wants a
second design — it lost today only on audience breadth and
on sharing a mail-daemon shelf with dovecotwho, not on
merit.
