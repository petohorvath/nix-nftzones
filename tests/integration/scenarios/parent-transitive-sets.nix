/*
  Transitive zone-set scenario — confirms that a parent zone's
  auto-generated `_iifs` / `_v4` sets include every descendant's
  interfaces / CIDRs, not just the parent's own. This is the
  fix for the security audit's M1 finding: with `chainPolicy =
  "accept"` and a wildcard `from = [ "all" ]` deny policy, only
  root zones get base-chain dispatch jumps — so unless the
  parent zone's match set transitively covers descendant
  traffic, the descendant escapes the deny.

  Concretely: a packet from `192.168.0.5` on `guest0` matches
  `@lan_iifs` (which now contains both `lan0` and `guest0`),
  takes the base-chain jump into `lan`'s sub-chain, and the
  wildcard deny policy fires there. Pre-fix, `@lan_iifs`
  contained only `lan0`; guest traffic skipped lan's sub-chain
  entirely and fell through to `policy accept`.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) inSet jump expr;
  inherit (nftypes.dsl.fields) meta ip;
in
{
  body = {
    settings.chainPolicy = "accept";

    zones = {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      lan-guest = {
        parent = "lan";
        interfaces = [ "guest0" ];
        cidrs = [ "192.168.0.0/24" ];
      };
      wan = {
        interfaces = [ "wan0" ];
      };
    };

    policies.deny-all-to-wan = {
      from = [ "all" ];
      to = [ "wan" ];
      verdict = "drop";
    };
  };

  assertions = compiled: [
    {
      description = "parent's _iifs transitively includes child's interfaces";
      expr = compiled.table.sets.lan_iifs.elements;
      expected = [
        "lan0"
        "guest0"
      ];
    }
    {
      description = "parent's _v4 transitively includes child's CIDRs (coalesced by libnet.cidr.summarize)";
      expr = builtins.length compiled.table.sets.lan_v4.elements;
      # Two distinct non-overlapping CIDRs: 10.0.0.0/24 (parent)
      # and 192.168.0.0/24 (child). `summarize` keeps both since
      # they don't overlap or fuse.
      expected = 2;
    }
    {
      description = "child still has its own _iifs set (self only, not parent's interfaces)";
      expr = compiled.table.sets.lan-guest_iifs.elements;
      expected = [ "guest0" ];
    }
    {
      description = "wildcard deny policy emits a sub-chain for the parent zone (catches descendant traffic via transitive iif set)";
      expr = compiled.table.chains ? "forward-at-filter__lan-to-wan";
      expected = true;
    }
    {
      description = "same-family gate composition unchanged: parent's own iface + v4 sections still AND in one dispatch variant";
      expr = builtins.elem [
        (inSet meta.iifname (expr.setRef "lan_iifs"))
        (inSet ip.saddr (expr.setRef "lan_v4"))
        (inSet meta.oifname (expr.setRef "wan_iifs"))
        (jump "forward-at-filter__lan-to-wan")
      ] compiled.table.chains."forward-at-filter".rules;
      expected = true;
    }
  ];
}
