#!/usr/bin/env python3
"""Tests for nftwho. Hermetic fixture-ruleset tests (BG1-BG10);
stdlib-only runner, plain `python3 test_nftwho.py` (no pytest --
the aptpinswho lesson). Fixtures are small ruleset trees in tmpdirs;
the runner invokes the CLI as a subprocess with --conf pointing at a
temp file. No network, no reads of the host's /etc/services or live
ruleset. One skip-guarded test runs `nft -c -f` over the suite's own
valid fixtures only (NF30: never on user files).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "nftwho")

DEFAULT_PKT = {
    "--saddr": "1.2.3.4", "--daddr": "10.1.1.1", "--proto": "tcp",
    "--sport": "12345", "--dport": "80", "--ctstate": "new",
    "--iif": "eth0", "--oif": "eth1",
}


def run_cli(args, cwd=None):
    proc = subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


class TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nftwho-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def conf(self, text, name="rules.nft"):
        return self.write(name, text)

    def q(self, path, hook="input", path_mode=None, extra=None, omit=(),
          pkt_override=None):
        args = ["--conf", path]
        if path_mode:
            args += ["--path", path_mode]
        else:
            args += ["--hook", hook]
        pkt = dict(DEFAULT_PKT)
        if pkt_override:
            pkt.update(pkt_override)
        for k in omit:
            pkt.pop(k, None)
        for k, v in pkt.items():
            args += [k, v]
        if extra:
            args += extra
        return run_cli(args)

    def verdict(self, rc_out_err):
        rc, out, _err = rc_out_err
        first = out.splitlines()[0] if out.splitlines() else ""
        return rc, first, out


# ---------------------------------------------------------------- BG1: core

class BG1Core(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_single_chain_rule_accept(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("rules.nft:4", first)

    def test_policy_drop_decides(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 22 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (policy)"), first)
        self.assertIn("rules.nft:3", first)

    def test_nf08_early_accept_does_not_stop_later_chain_drop(self):
        p = self.conf("""table inet a {
  chain input {
    type filter hook input priority -100; policy accept;
    tcp dport 80 accept
  }
}
table inet b {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        self.assertIn("rules.nft:10", first)

    def test_early_drop_stops_everything(self):
        p = self.conf("""table inet a {
  chain input {
    type filter hook input priority -100; policy accept;
    tcp dport 80 drop
  }
}
table inet b {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        # the later chain is never walked (coverage still lists it)
        self.assertNotIn("chain inet b input",
                         out.split("Coverage:")[0])

    def test_same_priority_collision_finding(self):
        p = self.conf("""table inet a {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
table inet b {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 22 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertIn("same-priority-order", out)

    def test_path_in_composes_prerouting_and_input(self):
        p = self.conf("""table inet filter {
  chain prerouting {
    type filter hook prerouting priority 0; policy accept;
    tcp dport 80 accept
  }
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p, path_mode="in"))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_path_forward_skips_input_chains(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
}
""")
        rc, first, out = self.verdict(self.q(p, path_mode="forward"))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT"), first)

    def test_hook_with_no_chains_not_evaluated(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
  }
}
""")
        rc, first, out = self.verdict(self.q(p, hook="output"))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("NOT-EVALUATED"), first)

    def test_rule_with_no_verdict_falls_through(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 counter
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (policy)"), first)

    def test_continue_verdict_falls_through(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 continue
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("rules.nft:5", first)


# ---------------------------------------------------------------- BG2: jumps

class BG2Jumps(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_jump_returns_and_caller_continues(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 jump check
    tcp dport 80 accept
  }
  chain check {
    tcp dport 22 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertIn("rules.nft:5", first)

    def test_jump_target_terminal_verdict_decides(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 jump check
    tcp dport 80 accept
  }
  chain check {
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        self.assertIn("rules.nft:8", first)

    def test_goto_exhaustion_falls_to_base_policy(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 goto leaf
    tcp dport 80 drop
  }
  chain leaf {
    tcp dport 9999 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (policy)"), first)
        self.assertIn("goto exhausted", out)

    def test_goto_nested_in_jumped_chain_unwinds_to_base_policy(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 jump mid
    tcp dport 80 accept
  }
  chain mid {
    tcp dport 80 goto leaf
  }
  chain leaf {
    tcp dport 9999 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (policy)"), first)

    def test_return_in_regular_vs_base_chain(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 jump sub
    tcp dport 80 drop
  }
  chain sub {
    return
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        # return in a base chain applies the policy
        p2 = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 return
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p2))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (policy)"), first)

    def test_vmap_dispatch_to_jump_target(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport vmap { 80 : jump ok, 443 : drop }
  }
  chain ok {
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_vmap_star_default(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport vmap { 443 : accept, * : drop }
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_vmap_no_entry_no_default_falls_through(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport vmap { 9999 : drop }
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("rules.nft:5", first)

    def test_jump_cycle_is_unknown(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 jump a
  }
  chain a {
    tcp dport 80 jump b
  }
  chain b {
    tcp dport 80 jump a
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("chain-loop", out)


# ---------------------------------------------------------------- BG3: fields

class BG3Fields(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_ip_table_skipped_for_ipv6_packet(self):
        p = self.conf("""table ip filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(
            p, pkt_override={"--saddr": "2001:db8::1",
                             "--daddr": "2001:db8::2"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("NOT-EVALUATED"), first)

    def test_nf15_inet_trap_ip_rule_false_for_ipv6(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr 2001:db8::1 drop
    ip6 saddr 2001:db8::1 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(
            p, pkt_override={"--saddr": "2001:db8::1",
                             "--daddr": "2001:db8::2"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        self.assertIn("rules.nft:5", first)

    def test_mixed_ip_and_ip6_rule_never_matches(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr 1.2.3.4 ip6 daddr 2001:db8::2 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("never-matches", out)

    def test_nfproto_guard_restores_decidability(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    meta nfproto ipv4 ip saddr 1.2.3.4 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--saddr": "2001:db8::1",
                             "--daddr": "2001:db8::2"}))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_tcp_dport_false_but_th_dport_matches_on_udp(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 53 drop
    th dport 53 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(
            p, pkt_override={"--proto": "udp", "--dport": "53"}))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_omitted_dport_with_port_candidate_is_unknown(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
    tcp dport 22 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p, omit=("--dport",)))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("rules.nft:4", first)

    def test_tcp_flags_idiom_true_and_false(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp flags & syn == syn drop
    tcp dport 80 accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(p, extra=["--tcpflags", "syn"]))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        rc, first, _ = self.verdict(self.q(p, extra=["--tcpflags", "ack"]))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_icmp_type_symbolic_constant(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    icmp type echo-request drop
    icmp type echo-reply accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--proto": "icmp"},
            extra=["--icmptype", "echo-request"],
            omit=("--sport", "--dport")))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_iifname_with_space_quoted_token(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    meta iifname "my eth" drop
    tcp dport 80 accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--iif": "my eth"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_arp_table_banner_verdict_unaffected(self):
        p = self.conf("""table arp filter {
  chain input {
    type filter hook input priority 0; policy accept;
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        self.assertIn("out-of-scope-family", out)


# ---------------------------------------------------------------- BG4: sets

class BG4Sets(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_anonymous_set_hit_and_miss(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport { 80, 443 } accept
    tcp dport 22 drop
  }
}
""")
        rc, first, _ = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--dport": "22"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_range_and_prefix_elements(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 8000-9000 accept
    ip saddr 10.0.0.0/8 drop
  }
}
""")
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--dport": "8080"}))
        self.assertEqual(rc, 0)
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--saddr": "10.5.5.5", "--dport": "22"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_named_static_set_hit_dual_provenance(self):
        p = self.conf("""table inet filter {
  set blocklist {
    type ipv4_addr
    flags interval
    elements = { 1.2.3.4, 5.6.7.8 }
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @blocklist drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        self.assertIn("rules.nft:9", first)
        # coverage names the set declaration site too (dual provenance)
        self.assertIn("rules.nft:2", out)

    def test_named_set_empty_at_load_is_false(self):
        p = self.conf("""table inet filter {
  set empty {
    type ipv4_addr
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @empty drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("empty-at-load", out)

    def test_add_element_populates_set(self):
        p = self.conf("""add table ip filter
add set ip filter myset { type ipv4_addr; flags interval; }
add chain ip filter input { type filter hook input priority 0; policy accept; }
add element ip filter myset { 1.2.3.4 }
add rule ip filter input ip saddr @myset drop
add rule ip filter input tcp dport 80 accept
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_concat_tuple_hit_and_unknown_component(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr . tcp dport { 1.2.3.4 . 80, 1.2.3.4 . 443 } accept
    tcp dport 80 drop
  }
}
""")
        rc, first, _ = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        rc, first, out = self.verdict(self.q(p, omit=("--dport",)))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)

    def test_interval_set_with_prefix_elements(self):
        p = self.conf("""table inet filter {
  set nets {
    type ipv4_addr
    flags interval
    elements = { 10.0.0.0/8, 192.168.0.0/16 }
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @nets drop
    tcp dport 80 accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--saddr": "10.5.5.5"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_data_map_feeds_mark_then_mark_match_decides(self):
        p = self.conf("""table inet filter {
  map markmap {
    type ipv4_addr : mark
    elements = { 1.2.3.4 : 7 }
  }
  chain prerouting {
    type filter hook prerouting priority -100; policy accept;
    meta mark set ip saddr map @markmap
  }
  chain input {
    type filter hook input priority 0; policy drop;
    meta mark 7 accept
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p, path_mode="in"))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_named_vmap_via_at_name(self):
        p = self.conf("""table inet filter {
  map out {
    type inet_service : verdict
    elements = { 80 : accept, 443 : drop }
  }
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport vmap @out
  }
}
""")
        rc, first, _ = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--dport": "443"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_data_map_miss_statement_does_not_execute(self):
        p = self.conf("""table inet filter {
  map natmap {
    type ipv4_addr : ipv4_addr
    elements = { 9.9.9.9 : 10.0.0.5 }
  }
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    dnat to ip saddr map @natmap
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p, hook="prerouting"))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("NAT: none", out)


# ---------------------------------------------------------------- BG5: stream

class BG5Stream(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_include_splices_mid_table(self):
        self.write("extra.nft", """  chain extra {
    type filter hook output priority 0; policy accept;
    tcp dport 80 accept
  }
""")
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
  }
  include "extra.nft"
}
""")
        rc, first, out = self.verdict(self.q(p, hook="output"))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("extra.nft", out)

    def test_nested_include_resolves_against_including_file_dir(self):
        # NF03 anti-LT03 fixture: the decoy in the main file's dir must
        # NOT be read; the nested include resolves against sub/.
        self.write("common.nft", """table inet decoy {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
  }
}
""")
        self.write("sub/common.nft", """table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
""")
        self.write("sub/inner.nft", 'include "common.nft"\n')
        p = self.conf('include "sub/inner.nft"\n')
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertNotIn("decoy", out)

    def test_wildcard_include_sorted_order_decides(self):
        self.write("rules/a.nft",
                   "add rule inet filter input tcp dport 80 drop\n")
        self.write("rules/b.nft",
                   "add rule inet filter input tcp dport 80 accept\n")
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
  }
}
include "rules/*.nft"
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_wildcard_no_match_is_silent_ok(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
include "nothing/*.nft"
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_literal_missing_include_is_load_failure(self):
        p = self.conf('include "nope.nft"\n')
        rc, out, err = self.q(p)
        self.assertEqual(rc, 2)
        self.assertIn("resolves nowhere", err)

    def test_define_in_match_and_set_literal_with_redefinition(self):
        p = self.conf("""define WEB = 80
define LAN = { 10.0.0.0/8, 192.168.0.0/16 }
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport $WEB accept
    ip saddr $LAN drop
  }
}
""")
        rc, first, _ = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--saddr": "10.1.2.3", "--dport": "443"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        # redefinition: later define wins for later uses only
        p2 = self.conf("""define P = 80
table inet one {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport $P accept
  }
}
define P = 443
table inet two {
  chain forward {
    type filter hook forward priority 0; policy drop;
    tcp dport $P accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(p2))
        self.assertEqual(rc, 0)
        rc, first, _ = self.verdict(self.q(p2, hook="forward",
                                           pkt_override={"--dport": "443"}))
        self.assertEqual(rc, 0)
        rc, first, _ = self.verdict(self.q(p2, hook="forward"))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (policy)"), first)

    def test_flush_ruleset_discards_earlier_tables(self):
        p = self.conf("""table ip old {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
  }
}
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertNotIn("table ip old", out)

    def test_delete_unrelated_finding_vs_queried_chain_poison(self):
        p = self.conf("""delete table ip ghost
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertIn("unmodeled-command", out)
        p2 = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
delete chain inet filter input
""")
        rc, first, out = self.verdict(self.q(p2))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)


# ---------------------------------------------------------------- BG6: NAT

class BG6Nat(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    NAT_FIXTURE = """table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 8080 dnat to 10.0.0.5:80
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    meta iifname eth0 accept
  }
}
"""

    def test_ct_state_established_accepts(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    tcp dport 80 drop
  }
}
""")
        rc, first, _ = self.verdict(self.q(
            p, pkt_override={"--ctstate": "established"}))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_ct_state_absent_is_unknown_not_absorbed(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p, omit=("--ctstate",)))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("rules.nft:4", first)

    def test_nat_dnat_for_new_packet(self):
        p = self.conf(self.NAT_FIXTURE)
        rc, first, out = self.verdict(self.q(
            p, path_mode="in", pkt_override={"--dport": "8080"}))
        self.assertEqual(rc, 0)
        self.assertIn("NAT: dnat to 10.0.0.5:80 (rule at ", out)

    def test_nat_skipped_when_not_first_packet(self):
        p = self.conf(self.NAT_FIXTURE)
        rc, first, out = self.verdict(self.q(
            p, path_mode="in",
            pkt_override={"--dport": "8080", "--ctstate": "established"}))
        self.assertEqual(rc, 0)
        self.assertIn("NAT: skipped (not first packet)", out)

    def test_nat_unknown_but_filter_verdict_resolves(self):
        p = self.conf(self.NAT_FIXTURE)
        rc, first, out = self.verdict(self.q(
            p, path_mode="in", omit=("--ctstate",),
            pkt_override={"--dport": "8080"}))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("NAT: UNKNOWN", out)

    def test_first_matching_nat_rule_binds(self):
        p = self.conf("""table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 8080 dnat to 10.0.0.5:80
    tcp dport 8080 dnat to 10.0.0.6:80
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 8080 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(
            p, hook="prerouting", pkt_override={"--dport": "8080"}))
        self.assertEqual(rc, 0)
        self.assertIn("NAT: dnat to 10.0.0.5:80", out)
        self.assertNotIn("10.0.0.6", out)

    def test_path_dnat_then_daddr_decider_is_unknown(self):
        p = self.conf("""table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 8080 dnat to 10.0.0.5:80
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ip daddr 10.9.9.9 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(
            p, path_mode="in",
            pkt_override={"--dport": "8080", "--daddr": "10.9.9.9"}))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("nat-rewrites-tuple", out)
        # per-hook answers stay exact
        rc, first, _ = self.verdict(self.q(
            p, hook="input",
            pkt_override={"--dport": "8080", "--daddr": "10.9.9.9"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)

    def test_path_dnat_without_later_rewritten_reader_stands(self):
        p = self.conf("""table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 8080 dnat to 10.0.0.5
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 8080 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(
            p, path_mode="in", pkt_override={"--dport": "8080"}))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertIn("NAT: dnat to 10.0.0.5", out)
        self.assertNotIn("nat-rewrites-tuple", out)

    def test_notrack_then_ct_state_untracked(self):
        p = self.conf("""table inet filter {
  chain prerouting {
    type filter hook prerouting priority -100; policy accept;
    tcp dport 80 notrack
  }
  chain input {
    type filter hook input priority 0; policy drop;
    ct state untracked accept
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p, path_mode="in"))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)


# ---------------------------------------------------------------- BG7: poison

class BG7Poison(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_mark_set_in_prerouting_decides_forward(self):
        p = self.conf("""table inet filter {
  chain prerouting {
    type filter hook prerouting priority -100; policy accept;
    meta mark set 5
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    meta mark 5 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p, path_mode="forward"))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_mark_set_from_field_expression_is_unknown(self):
        p = self.conf("""table inet filter {
  chain prerouting {
    type filter hook prerouting priority -100; policy accept;
    meta mark set ct mark
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    meta mark 5 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p, path_mode="forward"))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)

    def test_limit_rate_as_match_is_rate_dependent(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    limit rate over 10/minute drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("rate-dependent", out)

    def test_limit_as_statement_on_deciding_rule_is_harmless(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 limit rate 10/minute accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_fib_decider_is_routing_dependent(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    fib daddr . iif type local accept
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("routing-dependent", out)

    def test_jhash_match_is_hash_or_random(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    jhash ip saddr mod 2 == 0 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("hash-or-random", out)

    def test_quota_as_match_vs_named_counter_statement(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    quota over 100000 bytes drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("rate-dependent", out)
        p2 = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 counter name c1 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p2))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_queue_verdict_is_queued_unknown(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 queue
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("QUEUED-UNKNOWN"), first)


# ---------------------------------------------------------------- BG8: Kleene

class BG8Kleene(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_unknown_before_true_decider_poisons(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    meta mark 5 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("rules.nft:4", first)

    def test_unknown_after_true_decider_is_inert(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 accept
    meta mark 5 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertNotIn("meta mark 5 drop", out)

    def test_unknown_in_jumped_chain_poisons_base(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 jump sub
    tcp dport 80 accept
  }
  chain sub {
    meta mark 5 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)

    def test_false_and_unknown_conjunction_is_no_match(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr 9.9.9.9 meta mark 5 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)

    def test_unparseable_rule_poisons_from_its_position(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
    frobnicate 1.2.3.4 drop
    tcp dport 80 drop
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        p2 = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    frobnicate 1.2.3.4 drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p2))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)

    def test_unparseable_set_poisons_only_its_lookups(self):
        p = self.conf("""table inet filter {
  set good {
    type ipv4_addr
    elements = { 1.2.3.4 }
  }
  set bad {
    type ipv4_addr
    frobnicate xyz
    elements = { 5.6.7.8 }
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @good accept
    ip saddr @bad drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        rc, first, out = self.verdict(self.q(
            p, pkt_override={"--saddr": "5.6.7.8"}))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)


# ---------------------------------------------------------------- BG9: names

class BG9Names(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_symbolic_service_without_services_file_is_unknown(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport ssh drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("symbolic-service", out)

    def test_services_file_resolves_hermetically(self):
        svc = self.write("services.txt", "ssh 2222/tcp\nhttp 80/tcp\n")
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport ssh drop
    tcp dport 80 accept
  }
}
""")
        rc, first, _ = self.verdict(self.q(
            p, extra=["--services", svc],
            pkt_override={"--dport": "2222"}))
        self.assertEqual(rc, 1)
        self.assertTrue(first.startswith("DROP (rule)"), first)
        # the fixture's 2222, not the real world's 22: dport 22 matches
        # neither rule and falls through to the accept policy
        rc, first, _ = self.verdict(self.q(
            p, extra=["--services", svc],
            pkt_override={"--dport": "22"}))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (policy)"), first)

    def test_hostname_literal_is_load_time_dns(self):
        p = self.conf("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr example.com drop
    tcp dport 80 accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 2)
        self.assertTrue(first.startswith("UNKNOWN"), first)
        self.assertIn("load-time-dns", out)

    def test_include_traversal_only_through_nf03_resolution(self):
        # decoys: an executable and a FIFO that must never be opened
        self.write("shared/decoy.sh",
                   "#!/bin/sh\ntouch %s/marker\n" % self.tmp)
        self.write("shared/common.nft", """table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 accept
  }
}
""")
        os.mkfifo(os.path.join(self.tmp, "shared", "decoy.fifo"))
        p = self.write("run/main.nft", 'include "../shared/common.nft"\n')
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertTrue(first.startswith("ACCEPT (rule)"), first)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "marker")))

    def test_define_expansion_bomb_hits_depth_cap(self):
        p = self.conf("""define A = $B
define B = $A
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport $A accept
  }
}
""")
        rc, out, err = self.q(p)
        self.assertEqual(rc, 2)
        self.assertIn("cap", err)


# ---------------------------------------------------------------- BG10: inventory

class BG10Inventory(TmpTree):
    def setUp(self):
        TmpTree.setUp(self)

    def test_list_chains_normalizes_keyword_priorities(self):
        p = self.conf("""table ip filter {
  chain input {
    type filter hook input priority filter - 5; policy drop;
  }
  chain out {
    type filter hook output priority 0; policy accept;
  }
}
table ip6 filter {
  chain input {
    type filter hook input priority raw; policy accept;
  }
}
""")
        rc, out, _ = run_cli(["--conf", p, "--list-chains"])
        self.assertEqual(rc, 0)
        self.assertIn("priority=-5", out)
        self.assertIn("priority=-300", out)
        self.assertIn("chain input", out)
        self.assertIn("chain out", out)

    def test_list_sets_with_flags_and_counts(self):
        p = self.conf("""table inet filter {
  set nets {
    type ipv4_addr
    flags interval
    elements = { 10.0.0.0/8, 192.168.0.0/16 }
  }
  map out {
    type inet_service : verdict
    elements = { 80 : accept }
  }
  chain input {
    type filter hook input priority 0; policy accept;
  }
}
""")
        rc, out, _ = run_cli(["--conf", p, "--list-sets"])
        self.assertEqual(rc, 0)
        self.assertIn("interval", out)
        self.assertIn("elements=2", out)
        self.assertIn("elements=1", out)
        self.assertIn("map out", out)

    def test_coverage_names_files_chains_rules_sets(self):
        self.write("extra.nft", """table inet filter {
  set allow {
    type ipv4_addr
    elements = { 1.2.3.4 }
  }
}
""")
        p = self.conf("""define WEB = 80
include "extra.nft"
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @allow accept
    tcp dport $WEB accept
  }
}
""")
        rc, first, out = self.verdict(self.q(p))
        self.assertEqual(rc, 0)
        self.assertIn("extra.nft", out)
        self.assertIn("chain inet filter input", out)
        self.assertIn("rules.nft:6", out)   # ip saddr @allow rule
        self.assertIn("@allow", out)
        self.assertIn("$WEB", out)

    def test_json_verdict_parity_with_text(self):
        cases = [
            ("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 accept
  }
}
""", 0, "ACCEPT"),
            ("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 drop
  }
}
""", 1, "DROP"),
            ("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
  }
}
""", 1, "NOT-EVALUATED"),
        ]
        for text, want_rc, want_verdict in cases:
            p = self.conf(text)
            hook = "input" if want_verdict != "NOT-EVALUATED" else "output"
            rc, out, _ = self.q(p, hook=hook, extra=["--json"])
            self.assertEqual(rc, want_rc)
            data = json.loads(out)
            self.assertEqual(data["verdict"], want_verdict)
            rc2, first, _ = self.verdict(self.q(p, hook=hook))
            self.assertTrue(first.startswith(want_verdict), first)

    def test_quiet_prints_verdict_only(self):
        p = self.conf("""table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 8080 dnat to 10.0.0.5:80
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 8080 accept
  }
}
""")
        rc, out, _ = self.q(p, hook="input", extra=["--quiet"],
                            pkt_override={"--dport": "8080"})
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertTrue(out.startswith("ACCEPT"))
        rc, out, _ = self.q(p, path_mode="in", extra=["--quiet"],
                            pkt_override={"--dport": "8080"})
        lines = out.strip().splitlines()
        # NF22: the dnat rewrites dport and the input decider reads it,
        # so the composed path degrades to UNKNOWN; the NAT line follows.
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("UNKNOWN"))
        self.assertTrue(lines[1].startswith("NAT: dnat"))

    def test_exit_code_matrix(self):
        def mk(body, hook="input", **kw):
            p = self.conf(body)
            return self.q(p, hook=hook, **kw)
        rc, *_ = mk("""table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 accept
  }
}
""")
        self.assertEqual(rc, 0)
        rc, *_ = mk("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 drop
  }
}
""")
        self.assertEqual(rc, 1)
        rc, *_ = mk("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 reject with icmp type admin-prohibited
  }
}
""")
        self.assertEqual(rc, 1)
        rc, *_ = mk("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
  }
}
""", hook="output")
        self.assertEqual(rc, 1)
        rc, *_ = mk("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    meta mark 5 drop
  }
}
""")
        self.assertEqual(rc, 2)
        rc, *_ = mk("""table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 80 queue
  }
}
""")
        self.assertEqual(rc, 2)
        rc, _out, _err = run_cli(["--conf", os.path.join(self.tmp, "nope.nft"),
                                  "--hook", "input"])
        self.assertEqual(rc, 2)

    def test_nft_parse_crosscheck_on_valid_fixtures(self):
        """NF30: optional skip-guarded `nft -c -f` over the suite's own
        valid fixtures only — never on user files."""
        nft = shutil.which("nft")
        if nft is None:
            self.skipTest("no nft binary on this box")
        valid = [
            """table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    tcp dport 22 accept
    ip saddr 10.0.0.0/8 drop
  }
}
""",
            """table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport { 80, 443 } accept
    tcp flags & syn == syn drop
  }
}
""",
            """table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 8080 dnat to 10.0.0.5:80
  }
}
""",
        ]
        for i, text in enumerate(valid):
            p = self.write("cross%d.nft" % i, text)
            proc = subprocess.run([nft, "-c", "-f", p],
                                  capture_output=True, text=True)
            if proc.returncode != 0 and (
                    "Operation not permitted" in proc.stderr
                    or "cache initialization failed" in proc.stderr):
                # This sandbox blocks netlink even for `nft -c`; the
                # binary cannot parse-check here at all. That is an
                # environment limitation, not a fixture rejection.
                self.skipTest("nft -c -f cannot run in this sandbox: %s"
                              % proc.stderr.strip())
            self.assertEqual(proc.returncode, 0,
                             "fixture %d rejected by nft -c -f: %s"
                             % (i, proc.stderr))


if __name__ == "__main__":
    unittest.main(verbosity=2)
