# Changelog

## 1.0.0 — 2026-11-10

Initial release. Static, pre-deploy adjudication of nftables ruleset
files: for one fully specified packet and one traversal (a single
netfilter hook, or a composed path in/forward/out), which rule in
which chain decides the packet, what NAT outcome (if any) a nat chain
assigns along the way, and at which file:line the deciding rule
lives.

Pinned semantics implemented (DESIGN-nftwho.md, NF00–NF31):

- NF00/NF02/NF03/NF04: statement-oriented tokenizer; one merged
  stream across the include tree (includes resolve against the
  including file's directory, then --includepath; wildcards sorted,
  no-match is silent-OK, dotfiles never matched); parse-time defines
  with single-pass later-wins redefinition; `flush ruleset` /
  `flush table` modeled.
- NF05/NF06/NF07: ip/ip6/inet tables only; hooks prerouting/input/
  forward/output/postrouting/ingress; composed paths in/forward/out;
  base chains ordered by signed priority with keyword normalization
  (raw -300, mangle -150, dstnat -100, filter 0, security 50,
  srcnat 100) and constant priority expressions; same-priority
  collisions reported with merged-stream declaration order.
- NF08/NF09/NF10/NF11: accept is chain-local, drop/reject is
  packet-final; policy is a provenance-carrying decider; first
  terminal verdict decides a chain; a real jump/goto/return call
  stack with goto exhaustion falling to the base chain's policy and
  static jump-cycle detection ([chain-loop]).
- NF13/NF14/NF15: conjunctions of match expressions with bit ops;
  the modeled field surface (addresses, ports, interfaces, ct state,
  marks, tcp flags, icmp types, nfproto); family-mismatched
  expressions in inet tables are silently FALSE, with
  [never-matches] for mixed ip/ip6 rules.
- NF16/NF17/NF18/NF19/NF20: anonymous and named sets (interval,
  empty-at-load, `add element` population), dynamic/timeout set
  poisoning, verdict maps (no-entry fall-through, `*` default,
  most-specific interval resolution) and data maps, concatenations.
- NF21/NF22/NF23: ct state as a supplied input (never derived);
  NAT separation with first-packet gating and [nat-rewrites-tuple]
  path degradation; meta/ct mark mutation tracked through the walk.
- NF24/NF25/NF26/NF27/NF28/NF29/NF30/NF31: rate-shaped, routing,
  hash, process-context, wall-clock, DNS, and symbolic-service
  poisons; the three-valued Kleene core with one-directional
  absorption; the exact verdict vocabulary and exit codes (0/1/2);
  positional unparseable/unmodeled poisoning; never invoking nft on
  user files, with bounded include/define/stream caps; coverage on
  every run plus --list-chains / --list-sets inventory modes.
