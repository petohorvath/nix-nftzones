/*
  Mirror of the mixed-section hierarchy scenario — an
  interface-only child zone under a cidrs-only parent. The
  parent's own gate cannot see the child's traffic (an address
  gate never matches by interface), so the fix must both leave
  the parent's own v4 variant un-narrowed *and* let the child's
  traffic reach the parent's rules: the descendant-contributed
  `lan_iifs` set rides a standalone family-agnostic dispatch
  variant instead of ANDing into the v4 gate.

  Pre-fix, the descendant-only interface set joined the prefix
  and the parent's dispatch collapsed to
  `iifname @lan_iifs ip saddr @lan_v4` — parent traffic on any
  other interface and child traffic outside the parent's CIDR
  both fell through to default-drop.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl)
    eq
    accept
    inSet
    jump
    expr
    ;
  inherit (nftypes.dsl.fields) tcp meta ip;
in
{
  body = {
    # Stateful/loopback boilerplate off so the base chain carries
    # only the dispatch jumps — assertions compare the full rule
    # list, pinning the exact gate composition.
    settings = {
      stateful = false;
      loopback = false;
    };

    zones = {
      lan.cidrs = [ "10.0.0.0/24" ];
      lan-guest = {
        parent = "lan";
        interfaces = [ "guest0" ];
      };
    };

    filters.lan-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
    };

    filters.guest-dns = {
      from = [ "lan-guest" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 53)
        accept
      ];
    };
  };

  assertions = compiled: [
    {
      description = "parent dispatch: own v4 variant un-narrowed, plus a standalone family-agnostic variant for the child's inherited interfaces";
      expr = compiled.table.chains."input-at-filter".rules;
      expected = [
        [
          (inSet ip.saddr (expr.setRef "lan_v4"))
          (jump "input-at-filter__lan-to-local")
        ]
        [
          (inSet meta.iifname (expr.setRef "lan_iifs"))
          (jump "input-at-filter__lan-to-local")
        ]
      ];
    }
    {
      description = "child refines inside the parent's pair chain via its own interface set";
      expr = builtins.elem [
        (inSet meta.iifname (expr.setRef "lan-guest_iifs"))
        (jump "input-at-filter__lan-guest-to-local")
      ] compiled.table.chains."input-at-filter__lan-to-local".rules;
      expected = true;
    }
  ];
}
