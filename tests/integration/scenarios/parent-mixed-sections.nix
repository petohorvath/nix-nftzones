/*
  Mixed-section hierarchy scenario — an address-only node attached
  to an interface-only parent zone, the default shape whenever
  `nodes` is used on a physical-interface zone. Pins the hierarchy
  invariant that adding a descendant never *narrows* what the
  ancestor matches: the parent's base-chain dispatch stays gated
  by `iifname @lan_iifs` alone (the node's traffic arrives on the
  parent's interface and rides the same gate), and the node
  refines *inside* the parent's pair chain via a child-dispatch
  jump on its own `@web_v4` set, with the parent's rules as
  fallback.

  Regression guard for the cross-family narrowing bug: the
  descendant-only `lan_v4` union set used to be ANDed into the
  parent's dispatch gate (`iifname @lan_iifs ip saddr @lan_v4`),
  so `lan` matched *only* the node's traffic and every other host
  on `lan0` fell through to the chain's default-drop.
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

    zones.lan.interfaces = [ "lan0" ];

    nodes.web = {
      zone = "lan";
      address.ipv4 = "10.0.0.5";
    };

    filters.lan-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
    };

    filters.web-http = {
      from = [ "web" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 80)
        accept
      ];
    };
  };

  assertions = compiled: [
    {
      description = "parent dispatch is gated by its own interfaces alone — no descendant-only ip saddr @lan_v4 AND clause";
      expr = compiled.table.chains."input-at-filter".rules;
      expected = [
        [
          (inSet meta.iifname (expr.setRef "lan_iifs"))
          (jump "input-at-filter__lan-to-local")
        ]
      ];
    }
    {
      description = "node refines inside the parent's pair chain: child-dispatch jump on the node's own v4 set";
      expr = builtins.elem [
        (inSet ip.saddr (expr.setRef "web_v4"))
        (jump "input-at-filter__web-to-local")
      ] compiled.table.chains."input-at-filter__lan-to-local".rules;
      expected = true;
    }
    {
      description = "child sub-chain and its own v4 set are emitted";
      expr = {
        chain = compiled.table.chains ? "input-at-filter__web-to-local";
        set = compiled.table.sets ? "web_v4";
      };
      expected = {
        chain = true;
        set = true;
      };
    }
  ];
}
