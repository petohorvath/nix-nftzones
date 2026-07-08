/*
  Unit tests for `lib/internal/emit.nix` (exposed as
  `nftzones.internal.emit`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.normalize) normalizeTable;
  inherit (nftzones.internal.expand) expandTable;
  inherit (nftzones.internal.dispatch) dispatchAndSort;
  inherit (nftzones.internal.emit)
    mkBaseChain
    mkBaseChains
    mkRuleBody
    mkSubChain
    mkSubChains
    mkDirectionVariants
    mkRootJumpRules
    mkChildDispatchJumpRules
    isRootFrom
    mkSubChainKey
    subChainNameOf
    buildEffectiveSubChains
    assembleTable
    emitTable
    ;
  inherit (nftypes.dsl) expr;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  /*
    Run Phase 1 → Phase 4 against an evalModules-produced table
    and return the final `ctx`. Tests inspect `ctx.output` (the
    `nftypes.dsl.table` value).
  */
  runEmit =
    body:
    (pkgs.lib.pipe (evalTable body) [
      normalizeTable
      expandTable
      dispatchAndSort
      emitTable
    ]).ctx;

  /*
    Test fixture: minimal `settings` attrset carrying just the
    fields `mkBaseChain` reads. Tests overlay what they care
    about.
  */
  defaultSettings = {
    stateful = true;
    loopback = true;
    rpfilter = false;
    chainPolicy = "drop";
    localZone = "local";
  };

  /*
    Empty matchOverride for tests probing the auto path. Each
    zone with no override sections set is a "regular" zone —
    interfaces and CIDRs come through `zoneSets`, override is
    inert. `getActiveMatchOverrides` filters null/empty sections,
    so `{ }` per side is equivalent to the all-null shape.
  */
  mockZone = {
    matchOverride = {
      ingress = { };
      egress = { };
    };
    parent = null;
  };
  mergedZonesFor = names: pkgs.lib.genAttrs names (_: mockZone);

  /*
    Convenience wrapper: pin family to `"inet"` and default
    settings, with neutral defaults for the jump-related args
    (no sub-chains by default, so `baseChainName` / `zoneSets` are
    inert). Tests pass a `bucket` and optionally override the
    rest.
  */
  mkChain =
    {
      settings ? defaultSettings,
      bucket,
      baseChainName ? "test-chain",
      effectiveSubChains ? { },
      mergedZones ? { },
      zoneSets ? { },
    }:
    mkBaseChain {
      family = "inet";
      inherit
        settings
        bucket
        baseChainName
        effectiveSubChains
        mergedZones
        zoneSets
        ;
    };

  # Empty bucket (no cells): just hook+priority+empty subChains.
  emptyBucket = hook: priority: {
    inherit hook priority;
    subChains = { };
  };
in
{
  # ===== emitTable — empty table assembles a table marker =====

  testEmitTableEmpty = {
    expr =
      let
        out = (runEmit { }).output;
      in
      {
        inherit (out) family name;
        hasSets = out ? sets;
        hasFlags = out ? flags;
        hasComment = out ? comment;
      };
    expected = {
      family = "inet";
      name = "fw";
      hasSets = false;
      hasFlags = false;
      hasComment = false;
    };
  };

  # ===== emitTable — non-empty table.flags surfaces on the output =====

  testEmitTableFlagsHonored = {
    expr = (runEmit { flags = [ "dormant" ]; }).output.flags;
    expected = [ "dormant" ];
  };

  # ===== emitTable — non-null table.comment surfaces on the output =====

  testEmitTableCommentHonored = {
    expr = (runEmit { comment = "main firewall"; }).output.comment;
    expected = "main firewall";
  };

  # ===== emitTable — zones flow through to body.sets =====

  testEmitTableSetsFromZones = {
    expr =
      let
        out =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "eth1" ];
                cidrs = [ "10.0.0.0/24" ];
              };
              wan = {
                interfaces = [ "eth0" ];
              };
            };
          }).output;
      in
      pkgs.lib.attrNames out.sets;
    expected = [
      "lan_iifs"
      "lan_v4"
      "wan_iifs"
    ];
  };

  # ===== emitTable — lowered nodes contribute v4/v6 sets via cidrs =====

  testEmitTableNodeAddressBecomesSet = {
    expr =
      let
        out =
          (runEmit {
            nodes.api = {
              zone = "dmz";
              address = {
                ipv4 = "10.0.0.5";
                ipv6 = "fe80::1";
              };
            };
            zones.dmz = {
              interfaces = [ "dmz0" ];
            };
          }).output;
        apiV4 = out.sets.api_v4;
        apiV6 = out.sets.api_v6;
      in
      {
        v4Type = apiV4.type;
        v4Elements = apiV4.elements;
        v6Type = apiV6.type;
        v6Elements = apiV6.elements;
      };
    expected = {
      v4Type = "ipv4_addr";
      v4Elements = [ (expr.prefix "10.0.0.5" 32) ];
      v6Type = "ipv6_addr";
      v6Elements = [ (expr.prefix "fe80::1" 128) ];
    };
  };

  # ===== emitTable — table.family propagates to output =====

  testEmitTableFamilyPropagates = {
    expr =
      (runEmit {
        family = "ip";
      }).output.family;
    expected = "ip";
  };

  # ===== assembleTable — thin wrapper around nftypes.dsl.table =====

  testAssembleTableShape = {
    expr =
      let
        body = {
          sets = {
            x = {
              type = "ifname";
              elements = [ "lo" ];
            };
          };
        };
        out = assembleTable {
          family = "inet";
          name = "fw";
          inherit body;
        };
      in
      {
        inherit (out) family name;
        hasSets = out ? sets;
        sameAsDirect = out == nftypes.dsl.table "inet" "fw" body;
      };
    expected = {
      family = "inet";
      name = "fw";
      hasSets = true;
      sameAsDirect = true;
    };
  };

  # Chain type derivation moved upstream to
  # `nftypes.compatibility.chainTypeFor`; tests for it live with
  # the upstream helper. End-to-end coverage of the consumer path
  # comes from the integration scenarios.

  # ===== mkSubChainKey — bidirectional =====

  testSubChainKeyForBidirectional = {
    expr = mkSubChainKey "lan" "wan";
    expected = "lan-to-wan";
  };

  # ===== mkSubChainKey — from-only =====

  testSubChainKeyForFromOnly = {
    expr = mkSubChainKey "wan" null;
    expected = "wan";
  };

  # ===== mkSubChainKey — to-only =====

  testSubChainKeyForToOnly = {
    expr = mkSubChainKey null "vpn";
    expected = "vpn";
  };

  # ===== subChainNameOf — `<base>__<sub>` format =====

  testSubChainNameOf = {
    # Single source of truth for the double-underscore separator
    # between base chain name and sub-chain key. Both emit (chain
    # naming) and dispatch (jump targets) build full sub-chain
    # names through this helper — pin the format so a regression
    # to a different separator surfaces with a clear failure.
    expr = subChainNameOf "forward-at-filter" "lan-to-wan";
    expected = "forward-at-filter__lan-to-wan";
  };

  # ===== isRootFrom — null parent → root =====

  testIsRootFromNullParent = {
    expr = isRootFrom { lan = mockZone; } "local" "lan";
    expected = true;
  };

  # ===== isRootFrom — non-null parent → not root =====

  testIsRootFromWithParent = {
    expr = isRootFrom {
      dmz = mockZone;
      web = mockZone // {
        parent = "dmz";
      };
    } "local" "web";
    expected = false;
  };

  # ===== isRootFrom — localZone → root =====

  testIsRootFromLocalZone = {
    expr = isRootFrom { } "local" "local";
    expected = true;
  };

  # ===== isRootFrom — unknown zone → root (defensive) =====

  testIsRootFromUnknown = {
    expr = isRootFrom { } "local" "ghost";
    expected = true;
  };

  # ===== buildEffectiveSubChains — direct only (no hierarchy) =====

  testBuildEffectiveSubChainsDirect = {
    # No descendants → no synthetic intermediates. Direct sub-chain
    # passes through unchanged.
    expr =
      let
        bucket = {
          subChains = {
            "lan-to-wan" = {
              from = "lan";
              to = "wan";
              preChildCells = [ ];
              postChildCells = [ { name = "x"; } ];
            };
          };
        };
        mergedZones = mergedZonesFor [
          "lan"
          "wan"
        ];
        eff = buildEffectiveSubChains bucket mergedZones;
      in
      builtins.attrNames eff;
    expected = [ "lan-to-wan" ];
  };

  # ===== buildEffectiveSubChains — descendant synthesizes intermediate parent =====

  testBuildEffectiveSubChainsIntermediate = {
    # web-server (parent dmz) has cells; dmz has no cells of its
    # own. An intermediate `dmz-to-local` chain must be synthesized
    # so the base chain has somewhere to dispatch into.
    expr =
      let
        bucket = {
          subChains = {
            "web-server-to-local" = {
              from = "web-server";
              to = "local";
              preChildCells = [ ];
              postChildCells = [ { name = "allow-http"; } ];
            };
          };
        };
        mergedZones = {
          dmz = mockZone;
          web-server = mockZone // {
            parent = "dmz";
          };
        };
        eff = buildEffectiveSubChains bucket mergedZones;
        intermediate = eff."dmz-to-local";
      in
      {
        keys = pkgs.lib.sort (a: b: a < b) (builtins.attrNames eff);
        intermediateIsEmpty = intermediate.preChildCells == [ ] && intermediate.postChildCells == [ ];
        intermediateFrom = intermediate.from;
        intermediateTo = intermediate.to;
      };
    expected = {
      keys = [
        "dmz-to-local"
        "web-server-to-local"
      ];
      intermediateIsEmpty = true;
      intermediateFrom = "dmz";
      intermediateTo = "local";
    };
  };

  # ===== buildEffectiveSubChains — direct wins over synthetic =====

  testBuildEffectiveSubChainsDirectOverridesSynthetic = {
    # If both parent (dmz) AND child (web-server) have cells,
    # bucket.subChains has both. The intermediate synthesis would
    # generate `dmz-to-local` empty; the direct entry must win.
    expr =
      let
        bucket = {
          subChains = {
            "dmz-to-local" = {
              from = "dmz";
              to = "local";
              preChildCells = [ ];
              postChildCells = [ { name = "dmz-rate"; } ];
            };
            "web-server-to-local" = {
              from = "web-server";
              to = "local";
              preChildCells = [ ];
              postChildCells = [ { name = "allow-http"; } ];
            };
          };
        };
        mergedZones = {
          dmz = mockZone;
          web-server = mockZone // {
            parent = "dmz";
          };
        };
        eff = buildEffectiveSubChains bucket mergedZones;
      in
      builtins.length eff."dmz-to-local".postChildCells;
    expected = 1;
  };

  # ===== buildEffectiveSubChains — terminates on parent cycle =====

  testBuildEffectiveSubChainsCycleSafe = {
    # Phase 1's `checkParentCycles` rejects cycles in normal use,
    # but a unit-test fixture (or a future caller that bypasses
    # Phase 1) might hand emit a cyclic mergedZones. The
    # `visited` guard inside `ancestorsOf` must stop the walk
    # rather than infinite-loop. We don't assert structural
    # equality — just that the call terminates and returns a
    # finite attrset.
    expr =
      let
        bucket = {
          subChains = {
            "leaf-to-local" = {
              from = "leaf";
              to = "local";
              preChildCells = [ ];
              postChildCells = [ { name = "x"; } ];
            };
          };
        };
        # cycle: a → b → a
        mergedZones = {
          a = mockZone // {
            parent = "b";
          };
          b = mockZone // {
            parent = "a";
          };
          leaf = mockZone // {
            parent = "a";
          };
        };
        eff = buildEffectiveSubChains bucket mergedZones;
      in
      builtins.isAttrs eff;
    expected = true;
  };

  # ===== mkBaseChain — filter input gets stateful + loopback =====

  testMkBaseChainFilterInput = {
    expr =
      let
        c = mkChain { bucket = emptyBucket "input" "filter"; };
      in
      {
        inherit (c)
          type
          hook
          prio
          policy
          ;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "filter";
      hook = "input";
      prio = 0;
      policy = "drop";
      ruleCount = 3; # 2 stateful + 1 loopback
    };
  };

  testMkBaseChainFilterForward = {
    expr =
      let
        c = mkChain { bucket = emptyBucket "forward" "filter"; };
      in
      {
        inherit (c) type hook;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "filter";
      hook = "forward";
      ruleCount = 2; # stateful only
    };
  };

  testMkBaseChainBoilerplateDisabled = {
    expr =
      let
        c = mkChain {
          settings = defaultSettings // {
            stateful = false;
            loopback = false;
          };
          bucket = emptyBucket "input" "filter";
        };
      in
      builtins.length c.rules;
    expected = 0;
  };

  testMkBaseChainSnat = {
    expr =
      let
        c = mkChain { bucket = emptyBucket "postrouting" "srcnat"; };
      in
      {
        inherit (c) type hook prio;
        hasPolicy = c ? policy;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "nat";
      hook = "postrouting";
      prio = 100;
      hasPolicy = false;
      ruleCount = 0;
    };
  };

  testMkBaseChainSroute = {
    # `type route` is output-only per nftypes' hooksByChainType;
    # sroute (prerouting + mangle) compiles as a regular filter
    # chain that does mangle ops. The mark-set still happens; the
    # routing-table re-evaluation that `type route` would trigger
    # is meaningless at prerouting (no routing decision yet).
    expr =
      let
        c = mkChain { bucket = emptyBucket "prerouting" "mangle"; };
      in
      {
        inherit (c) type hook prio;
        hasPolicy = c ? policy;
      };
    expected = {
      type = "filter";
      hook = "prerouting";
      prio = -150;
      hasPolicy = false;
    };
  };

  testMkBaseChainDnat = {
    expr =
      let
        c = mkChain { bucket = emptyBucket "prerouting" "dstnat"; };
      in
      {
        inherit (c) type hook prio;
        hasPolicy = c ? policy;
      };
    expected = {
      type = "nat";
      hook = "prerouting";
      prio = -100;
      hasPolicy = false;
    };
  };

  testMkBaseChainDroute = {
    expr =
      let
        c = mkChain { bucket = emptyBucket "output" "mangle"; };
      in
      {
        inherit (c) type hook prio;
        hasPolicy = c ? policy;
      };
    expected = {
      type = "route";
      hook = "output";
      prio = -150;
      hasPolicy = false;
    };
  };

  # `mkBaseChain` no longer attaches the rpfilter rule itself —
  # the synthesized chain in `mkBaseChains` carries it instead.
  # A user override at (prerouting, raw) gets only the standard
  # boilerplate + jump rules, never the rpfilter `fib` drop.
  testMkBaseChainNoRpfilterPrelude = {
    expr =
      let
        c = mkChain {
          settings = defaultSettings // {
            rpfilter = true;
          };
          bucket = emptyBucket "prerouting" "raw";
        };
      in
      {
        inherit (c) type hook prio;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "filter";
      hook = "prerouting";
      prio = -300;
      ruleCount = 0;
    };
  };

  # ===== mkBaseChains — rpfilter synthesizes a dedicated chain =====

  testMkBaseChainsRpfilterSynthesized = {
    expr =
      let
        chains = mkBaseChains {
          family = "inet";
          settings = defaultSettings // {
            rpfilter = true;
          };
          chainBuckets = { };
          effectiveSubChainsByBucket = { };
          mergedZones = { };
          zoneSets = { };
        };
        chain = chains."prerouting-at-raw";
      in
      {
        keys = builtins.attrNames chains;
        inherit (chain) type hook prio;
        ruleCount = builtins.length chain.rules;
      };
    expected = {
      keys = [ "prerouting-at-raw" ];
      type = "filter";
      hook = "prerouting";
      prio = -300;
      ruleCount = 1;
    };
  };

  # ===== mkBaseChains — user override at (prerouting, raw) suppresses synthesis =====

  testMkBaseChainsRpfilterUserOverrideWins = {
    expr =
      let
        chains = mkBaseChains {
          family = "inet";
          settings = defaultSettings // {
            rpfilter = true;
          };
          chainBuckets = {
            "prerouting-at-raw" = emptyBucket "prerouting" "raw";
          };
          effectiveSubChainsByBucket = {
            "prerouting-at-raw" = { };
          };
          mergedZones = { };
          zoneSets = { };
        };
      in
      builtins.length chains."prerouting-at-raw".rules;
    # User chain runs through `mkBaseChain` only; with no
    # boilerplate-eligible settings + no zone jumps, the chain
    # is empty. Crucially, the rpfilter fib-drop is NOT injected.
    expected = 0;
  };

  testMkBaseChainsEmpty = {
    expr = mkBaseChains {
      family = "inet";
      settings = defaultSettings;
      chainBuckets = { };
      effectiveSubChainsByBucket = { };
      mergedZones = { };
      zoneSets = { };
    };
    expected = { };
  };

  testMkBaseChainsPerBucket = {
    expr = pkgs.lib.sort (a: b: a < b) (
      builtins.attrNames (mkBaseChains {
        family = "inet";
        settings = defaultSettings;
        chainBuckets = {
          "input-at-filter" = emptyBucket "input" "filter";
          "forward-at-filter" = emptyBucket "forward" "filter";
          "postrouting-at-srcnat" = emptyBucket "postrouting" "srcnat";
        };
        effectiveSubChainsByBucket = {
          "input-at-filter" = { };
          "forward-at-filter" = { };
          "postrouting-at-srcnat" = { };
        };
        mergedZones = { };
        zoneSets = { };
      })
    );
    expected = [
      "forward-at-filter"
      "input-at-filter"
      "postrouting-at-srcnat"
    ];
  };

  # ===== emitTable — base chain + per-pair sub-chain land in output.chains =====

  testEmitTableHasChains = {
    expr =
      builtins.attrNames
        (runEmit {
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }).output.chains;
    expected = [
      "forward-at-filter"
      "forward-at-filter__lan-to-wan"
    ];
  };

  testEmitTableChainHeader = {
    expr =
      let
        chain =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
            };
          }).output.chains.forward-at-filter;
      in
      {
        inherit (chain)
          type
          hook
          prio
          policy
          ;
      };
    expected = {
      type = "filter";
      hook = "forward";
      prio = 0;
      policy = "drop";
    };
  };

  testEmitTableChainOverride = {
    expr =
      let
        chains =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.rpfilter-rule = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ ];
              chain = {
                hook = "prerouting";
                priority = "raw";
              };
            };
          }).output.chains;
        chain = chains.prerouting-at-raw;
      in
      {
        keys = builtins.attrNames chains;
        inherit (chain) type hook prio;
        hasPolicy = chain ? policy;
      };
    expected = {
      keys = [
        "prerouting-at-raw"
        "prerouting-at-raw__wan-to-local"
      ];
      type = "filter";
      hook = "prerouting";
      prio = -300;
      hasPolicy = false;
    };
  };

  testEmitTableRpfilterEnabled = {
    expr =
      let
        chains =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            settings.rpfilter = true;
            filters.f = {
              from = [ "lan" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).output.chains;
      in
      {
        keys = pkgs.lib.sort (a: b: a < b) (builtins.attrNames chains);
        rpfilterRuleCount = builtins.length chains.prerouting-at-raw.rules;
      };
    expected = {
      keys = [
        "input-at-filter"
        "input-at-filter__lan-to-local"
        "prerouting-at-raw"
      ];
      rpfilterRuleCount = 1;
    };
  };

  # ===== mkRuleBody — filter cell (rule already a list) =====

  testMkRuleBodyFilter = {
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
      comment = null;
    };
    expected = [
      (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
      nftypes.dsl.accept
    ];
  };

  testMkRuleBodySnatAddr = {
    expr = mkRuleBody {
      rule.snat = {
        addr = "203.0.113.5";
        port = 8080;
      };
      comment = null;
    };
    expected = [
      (nftypes.dsl.snat {
        addr = "203.0.113.5";
        port = 8080;
      })
    ];
  };

  testMkRuleBodySnatMasquerade = {
    expr = mkRuleBody {
      rule.masquerade = { };
      comment = null;
    };
    expected = [ (nftypes.dsl.masquerade { }) ];
  };

  testMkRuleBodyDnat = {
    expr = mkRuleBody {
      rule = {
        match = [ (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 443) ];
        action.dnat = {
          addr = "10.0.0.5";
          port = 443;
        };
      };
      comment = null;
    };
    expected = [
      (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 443)
      (nftypes.dsl.dnat {
        addr = "10.0.0.5";
        port = 443;
      })
    ];
  };

  testMkRuleBodyDnatRedirect = {
    expr = mkRuleBody {
      rule = {
        match = [ ];
        action.redirect = {
          port = 22;
        };
      };
      comment = null;
    };
    expected = [ (nftypes.dsl.redirect { port = 22; }) ];
  };

  testMkRuleBodySroute = {
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100)
      ];
      comment = null;
    };
    expected = [
      (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100)
    ];
  };

  testMkRuleBodyPolicyAccept = {
    expr = mkRuleBody {
      verdict = "accept";
      comment = null;
    };
    expected = [ nftypes.dsl.accept ];
  };

  testMkRuleBodyPolicyDrop = {
    expr = mkRuleBody {
      verdict = "drop";
      comment = null;
    };
    expected = [ nftypes.dsl.drop ];
  };

  # ===== mkRuleBody — non-null comment wraps the statement list =====

  testMkRuleBodyFilterWithComment = {
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
      comment = "ssh from anywhere";
    };
    expected = {
      expr = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
      comment = "ssh from anywhere";
    };
  };

  testMkRuleBodyPolicyWithComment = {
    expr = mkRuleBody {
      verdict = "accept";
      comment = "lan->wan default-allow";
    };
    expected = {
      expr = [ nftypes.dsl.accept ];
      comment = "lan->wan default-allow";
    };
  };

  testMkRuleBodySnatMasqueradeWithComment = {
    expr = mkRuleBody {
      rule.masquerade = { };
      comment = "nat lan to wan";
    };
    expected = {
      expr = [ (nftypes.dsl.masquerade { }) ];
      comment = "nat lan to wan";
    };
  };

  testMkRuleBodyDnatWithComment = {
    expr = mkRuleBody {
      rule = {
        match = [ (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80) ];
        action.dnat = {
          addr = "10.0.0.5";
          port = 8080;
        };
      };
      comment = "web port forward";
    };
    expected = {
      expr = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80)
        (nftypes.dsl.dnat {
          addr = "10.0.0.5";
          port = 8080;
        })
      ];
      comment = "web port forward";
    };
  };

  # ===== mkSubChain — single cell, no children =====

  testMkSubChainSingleCell = {
    expr = mkSubChain {
      hook = "forward";
      subChain = {
        from = "lan";
        to = "wan";
        preChildCells = [ ];
        postChildCells = [
          {
            rule = [ nftypes.dsl.accept ];
            comment = null;
          }
        ];
      };
      baseChainName = "forward-at-filter";
      childrenOf = { };
      effectiveSubChains = { };
      mergedZones = mergedZonesFor [
        "lan"
        "wan"
      ];
      zoneSets = { };
      localZone = "local";
    };
    expected = {
      rules = [
        [ nftypes.dsl.accept ]
      ];
    };
  };

  # ===== mkSubChain — pre-child cells emit before child dispatch =====

  testMkSubChainOrder = {
    # preChildCells (priority < 100) emit first, then child-dispatch
    # jumps, then postChildCells (priority >= 100) — in this test
    # there are no children, so just pre then post.
    expr = mkSubChain {
      hook = "forward";
      subChain = {
        from = "lan";
        to = "wan";
        preChildCells = [
          {
            rule = [ nftypes.dsl.accept ];
            comment = null;
          }
        ];
        postChildCells = [
          {
            rule = [ nftypes.dsl.drop ];
            comment = null;
          }
        ];
      };
      baseChainName = "forward-at-filter";
      childrenOf = { };
      effectiveSubChains = { };
      mergedZones = mergedZonesFor [
        "lan"
        "wan"
      ];
      zoneSets = { };
      localZone = "local";
    };
    expected = {
      rules = [
        [ nftypes.dsl.accept ]
        [ nftypes.dsl.drop ]
      ];
    };
  };

  # ===== mkSubChains — empty input =====

  testMkSubChainsEmpty = {
    expr = mkSubChains {
      chainBuckets = { };
      effectiveSubChainsByBucket = { };
      childrenOf = { };
      mergedZones = { };
      zoneSets = { };
      localZone = "local";
    };
    expected = { };
  };

  testMkSubChainsBidirectional = {
    expr =
      let
        bucket = {
          hook = "forward";
          priority = "filter";
          subChains = {
            "lan-to-wan" = {
              from = "lan";
              to = "wan";
              preChildCells = [ ];
              postChildCells = [
                {
                  rule = [ nftypes.dsl.accept ];
                  comment = null;
                }
              ];
            };
          };
        };
      in
      builtins.attrNames (mkSubChains {
        chainBuckets."forward-at-filter" = bucket;
        effectiveSubChainsByBucket."forward-at-filter" = bucket.subChains;
        childrenOf = { };
        mergedZones = mergedZonesFor [
          "lan"
          "wan"
        ];
        zoneSets = { };
        localZone = "local";
      });
    expected = [ "forward-at-filter__lan-to-wan" ];
  };

  testMkSubChainsSingleDirection = {
    expr =
      let
        bucket = {
          hook = "prerouting";
          priority = "dstnat";
          subChains = {
            "wan" = {
              from = "wan";
              preChildCells = [ ];
              postChildCells = [ ];
            };
          };
        };
      in
      builtins.attrNames (mkSubChains {
        chainBuckets."prerouting-at-dstnat" = bucket;
        effectiveSubChainsByBucket."prerouting-at-dstnat" = bucket.subChains;
        childrenOf = { };
        mergedZones = mergedZonesFor [ "wan" ];
        zoneSets = { };
        localZone = "local";
      });
    expected = [ "prerouting-at-dstnat__wan" ];
  };

  # ===== emitTable — sub-chain body contains the cell rule =====

  testEmitTableSubChainHasRule = {
    expr =
      let
        sub =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.allow = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ nftypes.dsl.accept ];
            };
          }).output.chains."forward-at-filter__lan-to-wan";
      in
      sub.rules;
    expected = [
      [ nftypes.dsl.accept ]
    ];
  };

  # ===== emitTable — preDispatch-priority cells land in sub-chain pre slot =====

  testEmitTablePreDispatchInSubChain = {
    # Under the new model, priority="first" (1 < 100) lands in the
    # sub-chain's preChildCells — NOT in the base chain pre slot.
    # Base chain only carries boilerplate + jumps now.
    expr =
      let
        out =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.early = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ nftypes.dsl.accept ];
              priority = "first";
            };
          }).output;
        baseChain = out.chains."forward-at-filter";
        subChain = out.chains."forward-at-filter__lan-to-wan";
      in
      {
        # Base chain: stateful (2) + jump (1).
        baseRuleCount = builtins.length baseChain.rules;
        # Sub-chain: the early rule (priority < 100 → pre slot).
        subRuleCount = builtins.length subChain.rules;
      };
    expected = {
      baseRuleCount = 3;
      subRuleCount = 1;
    };
  };

  # ===== emitTable — filter + policy in same pair: policy is tail rule =====

  testEmitTableFilterAndPolicyInSubChain = {
    expr =
      let
        sub =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.allow-https = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ nftypes.dsl.accept ];
            };
            policies.lan-to-wan = {
              from = [ "lan" ];
              to = [ "wan" ];
              verdict = "drop";
            };
          }).output.chains."forward-at-filter__lan-to-wan";
      in
      {
        ruleCount = builtins.length sub.rules;
        lastRuleStmt = builtins.head (builtins.elemAt sub.rules 1);
      };
    expected = {
      ruleCount = 2;
      lastRuleStmt = nftypes.dsl.drop;
    };
  };

  testEmitTableSnatSubChain = {
    expr =
      let
        sub =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            snats.lan-out = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule.masquerade = { };
            };
          }).output.chains."postrouting-at-srcnat__lan-to-wan";
      in
      sub.rules;
    expected = [
      [ (nftypes.dsl.masquerade { }) ]
    ];
  };

  # ===== mkDirectionVariants — localZone sentinel =====

  testMkDirectionVariantsLocalZone = {
    expr = mkDirectionVariants {
      hook = "input";
      direction = "to";
      zoneName = "local";
      active = { };
      mergedZones = { };
      zoneSets = { };
      localZone = "local";
    };
    expected = [ [ ] ];
  };

  testMkDirectionVariantsNullDirection = {
    expr = mkDirectionVariants {
      hook = "prerouting";
      direction = "to";
      zoneName = null;
      active = { };
      mergedZones = { };
      zoneSets = { };
      localZone = "local";
    };
    expected = [ [ ] ];
  };

  testMkDirectionVariantsInterfaceOnly = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        interfaces = [ "lan0" ];
      };
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs")) ]
    ];
  };

  testMkDirectionVariantsUnreachable = {
    expr = mkDirectionVariants {
      hook = "output";
      direction = "from";
      zoneName = "wan";
      active = { };
      mergedZones.wan = {
        interfaces = [ "wan0" ];
      };
      zoneSets = {
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [ ];
  };

  testMkDirectionVariantsV4Only = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        cidrs = [ "10.0.0.0/24" ];
      };
      zoneSets = {
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
    ];
  };

  testMkDirectionVariantsV4AndV6 = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        cidrs = [
          "10.0.0.0/24"
          "fd00::/64"
        ];
      };
      zoneSets = {
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
        lan_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6")) ]
    ];
  };

  testMkDirectionVariantsIfPlusV4V6 = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        interfaces = [ "lan0" ];
        cidrs = [
          "10.0.0.0/24"
          "fd00::/64"
        ];
      };
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
        lan_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4"))
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6"))
      ]
    ];
  };

  /*
    Own/inherited gate composition — the sets carry descendant
    content (transitive union), but only sections anchored by the
    zone's own raw fields may AND together. Pins the fix for the
    cross-family narrowing bug (see
    `tests/integration/scenarios/parent-mixed-sections.nix`).
  */

  # Interface-only zone with a descendant-contributed v4 set
  # (address-only node under it): the gate stays the
  # family-agnostic interface match — no `ip saddr` AND clause.
  testMkDirectionVariantsInheritedFamilySuppressed = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        interfaces = [ "lan0" ];
      };
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs")) ]
    ];
  };

  # Mirror shape: cidrs-only zone with a descendant-contributed
  # interface set. The own v4 variant stays un-narrowed and the
  # inherited interfaces ride a standalone family-agnostic
  # variant so the descendant's traffic still enters.
  testMkDirectionVariantsInheritedIfsStandalone = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        cidrs = [ "10.0.0.0/24" ];
      };
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "guest0" ];
        };
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs")) ]
    ];
  };

  # Family-anchored zone (iface + v4) with a descendant-only v6
  # set: the own anchors are family-blind, so the inherited v6
  # widens the gate with its own variant behind the own prefix.
  testMkDirectionVariantsInheritedFamilyWidens = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = { };
      mergedZones.lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
        lan_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4"))
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6"))
      ]
    ];
  };

  # Grouping zone (no own match at all): every section is
  # descendant-contributed and stands alone — ANDing sections
  # from different descendants would match their intersection.
  testMkDirectionVariantsGroupingZone = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "internal";
      active = { };
      mergedZones.internal = { };
      zoneSets = {
        internal_iifs = {
          type = "ifname";
          elements = [ "guest0" ];
        };
        internal_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "internal_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "internal_iifs")) ]
    ];
  };

  # ===== mkRootJumpRules — empty =====

  testMkRootJumpRulesEmpty = {
    expr = mkRootJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      effectiveSubChains = { };
      mergedZones = { };
      zoneSets = { };
      localZone = "local";
    };
    expected = [ ];
  };

  testMkRootJumpRulesBidirectional = {
    # Root from-zone (lan with parent==null) → emits a base-chain jump.
    expr = mkRootJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      effectiveSubChains = {
        "lan-to-wan" = {
          from = "lan";
          to = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
        };
      };
      mergedZones = mergedZonesFor [
        "lan"
        "wan"
      ];
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.setRef "wan_iifs"))
        (nftypes.dsl.jump "forward-at-filter__lan-to-wan")
      ]
    ];
  };

  testMkRootJumpRulesSingleDirection = {
    expr = mkRootJumpRules {
      hook = "prerouting";
      baseChainName = "prerouting-at-dstnat";
      effectiveSubChains = {
        "wan" = {
          from = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
        };
      };
      mergedZones = mergedZonesFor [ "wan" ];
      zoneSets = {
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "wan_iifs"))
        (nftypes.dsl.jump "prerouting-at-dstnat__wan")
      ]
    ];
  };

  # ===== mkRootJumpRules — non-root from-zone is skipped =====

  testMkRootJumpRulesNonRootSkipped = {
    # web-server (parent dmz) is not a root → no base-chain jump.
    # Only `dmz-to-wan` (root) emits one.
    expr = mkRootJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      effectiveSubChains = {
        "dmz-to-wan" = {
          from = "dmz";
          to = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
        };
        "web-server-to-wan" = {
          from = "web-server";
          to = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
        };
      };
      mergedZones = {
        dmz = mockZone;
        web-server = mockZone // {
          parent = "dmz";
        };
        wan = mockZone;
      };
      zoneSets = {
        dmz_iifs = {
          type = "ifname";
          elements = [ "dmz0" ];
        };
        web-server_v4 = { };
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "dmz_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.setRef "wan_iifs"))
        (nftypes.dsl.jump "forward-at-filter__dmz-to-wan")
      ]
    ];
  };

  # ===== mkRootJumpRules — cartesian product drops cross-family pairs =====

  testMkRootJumpRulesCartesian = {
    # With both lan and wan exposing v4 *and* v6 sets, the
    # cartesian product is 4 (lan_v4×wan_v4, lan_v4×wan_v6,
    # lan_v6×wan_v4, lan_v6×wan_v6). nft rejects mixed-family
    # match in `inet`, so emit drops the 2 cross-family pairs
    # and keeps the 2 matching-family pairs. Assert on the
    # actual jump bodies, not just the count — a regression
    # that kept the cross-family pairs (and dropped the matching
    # ones) would still produce length 2 and pass a count-only
    # assertion.
    expr = mkRootJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      effectiveSubChains = {
        "lan-to-wan" = {
          from = "lan";
          to = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
        };
      };
      mergedZones = mergedZonesFor [
        "lan"
        "wan"
      ];
      zoneSets = {
        lan_v4 = { };
        lan_v6 = { };
        wan_v4 = { };
        wan_v6 = { };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.daddr (nftypes.dsl.expr.setRef "wan_v4"))
        (nftypes.dsl.jump "forward-at-filter__lan-to-wan")
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.daddr (nftypes.dsl.expr.setRef "wan_v6"))
        (nftypes.dsl.jump "forward-at-filter__lan-to-wan")
      ]
    ];
  };

  # ===== mkChildDispatchJumpRules — emits jumps for matching children =====

  testMkChildDispatchJumpsBasic = {
    # parent dmz with one child web-server. Child's from-side
    # variant becomes the jump rule's match.
    expr = mkChildDispatchJumpRules {
      hook = "input";
      parentFromZone = "dmz";
      toZone = "local";
      baseChainName = "input-at-filter";
      childrenOf.dmz = [ "web-server" ];
      effectiveSubChains = {
        "dmz-to-local" = {
          from = "dmz";
          to = "local";
          preChildCells = [ ];
          postChildCells = [ ];
        };
        "web-server-to-local" = {
          from = "web-server";
          to = "local";
          preChildCells = [ ];
          postChildCells = [ ];
        };
      };
      mergedZones = {
        dmz = mockZone;
        web-server = mockZone // {
          parent = "dmz";
        };
      };
      zoneSets = {
        web-server_v4 = { };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "web-server_v4"))
        (nftypes.dsl.jump "input-at-filter__web-server-to-local")
      ]
    ];
  };

  # ===== mkChildDispatchJumpRules — child without effective sub-chain is skipped =====

  testMkChildDispatchJumpsNoTarget = {
    # web-server is a child but has no entry in effectiveSubChains
    # for this (baseChainName, toZone). No jump emitted.
    expr = mkChildDispatchJumpRules {
      hook = "input";
      parentFromZone = "dmz";
      toZone = "local";
      baseChainName = "input-at-filter";
      childrenOf.dmz = [ "web-server" ];
      effectiveSubChains = { };
      mergedZones = {
        dmz = mockZone;
        web-server = mockZone // {
          parent = "dmz";
        };
      };
      zoneSets = { };
      localZone = "local";
    };
    expected = [ ];
  };

  # ===== emitTable — jump rule lands in base chain =====

  testEmitTableJumpRule = {
    expr =
      let
        out =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
            };
          }).output;
        baseRules = out.chains."forward-at-filter".rules;
        # After stateful (2 rules), the jump.
        jumpRule = builtins.elemAt baseRules 2;
      in
      jumpRule;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.setRef "wan_iifs"))
      (nftypes.dsl.jump "forward-at-filter__lan-to-wan")
    ];
  };

  testEmitTableDnatJump = {
    expr =
      let
        out =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            dnats.fwd = {
              from = [ "wan" ];
              rule = {
                match = [ ];
                action.dnat = {
                  addr = "10.0.0.5";
                  port = 80;
                };
              };
            };
          }).output;
        baseRules = out.chains."prerouting-at-dstnat".rules;
      in
      builtins.head baseRules;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "wan_iifs"))
      (nftypes.dsl.jump "prerouting-at-dstnat__wan")
    ];
  };

  testEmitTableJumpToLocalZone = {
    expr =
      let
        out =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.allow-ssh = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).output;
        # input chain: stateful (2) + loopback (1) + jump (1) = 4 rules
        baseRules = out.chains."input-at-filter".rules;
        jumpRule = builtins.elemAt baseRules 3;
      in
      jumpRule;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "wan_iifs"))
      (nftypes.dsl.jump "input-at-filter__wan-to-local")
    ];
  };

  # ===== emitTable — base chain rule order =====

  testEmitTableBaseChainRuleOrder = {
    # Under the new model, base chain has only:
    #   stateful (2) + loopback (1) + jump (1) = 4 rules.
    # The early/normal/late cells all live inside the sub-chain.
    expr =
      let
        out =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters = {
              early = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
                priority = "first";
              };
              normal = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
              };
              late = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
                priority = "last";
              };
            };
          }).output;
        baseRules = out.chains."input-at-filter".rules;
        subRules = out.chains."input-at-filter__wan-to-local".rules;
      in
      {
        baseRuleCount = builtins.length baseRules;
        subRuleCount = builtins.length subRules;
      };
    expected = {
      baseRuleCount = 4; # stateful (2) + loopback (1) + jump (1)
      subRuleCount = 3; # early, normal, late
    };
  };

  testEmitTableDrouteChain = {
    expr =
      let
        chains =
          (runEmit {
            zones.lan.interfaces = [ "lan0" ];
            droutes.mark-lan = {
              to = [ "lan" ];
              rule = [ ];
            };
          }).output.chains;
      in
      {
        keys = pkgs.lib.sort (a: b: a < b) (builtins.attrNames chains);
        baseType = chains."output-at-mangle".type;
      };
    expected = {
      keys = [
        "output-at-mangle"
        "output-at-mangle__lan"
      ];
      baseType = "route";
    };
  };

  testEmitTableSrouteChain = {
    # sroute lands at prerouting+mangle as `type filter` (route
    # chains are output-only — see `testMkBaseChainSroute`).
    expr =
      let
        chains =
          (runEmit {
            zones.wan.interfaces = [ "wan0" ];
            sroutes.mark-wan = {
              from = [ "wan" ];
              rule = [ ];
            };
          }).output.chains;
      in
      {
        keys = pkgs.lib.sort (a: b: a < b) (builtins.attrNames chains);
        baseType = chains."prerouting-at-mangle".type;
      };
    expected = {
      keys = [
        "prerouting-at-mangle"
        "prerouting-at-mangle__wan"
      ];
      baseType = "filter";
    };
  };

  testEmitTableEmptyObjects = {
    expr =
      let
        out =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
          }).output;
      in
      pkgs.lib.attrNames out;
    expected = [
      "__nftTable"
      "family"
      "name"
      "sets"
    ];
  };

  testEmitTableCounterPassthrough = {
    expr =
      let
        out =
          (runEmit {
            objects.counters.web-hits = { };
          }).output;
      in
      pkgs.lib.attrNames out.counters;
    expected = [ "web-hits" ];
  };

  testEmitTableMultipleKinds = {
    expr =
      let
        out =
          (runEmit {
            objects = {
              counters.hits = { };
              quotas.bw = {
                bytes = 1000000;
              };
              ctHelpers.ftp = {
                type = "ftp";
                protocol = "tcp";
              };
            };
          }).output;
      in
      pkgs.lib.sort (a: b: a < b) (
        builtins.filter (
          k:
          builtins.elem k [
            "counters"
            "quotas"
            "ctHelpers"
          ]
        ) (pkgs.lib.attrNames out)
      );
    expected = [
      "counters"
      "ctHelpers"
      "quotas"
    ];
  };

  testEmitTableUserSetMergesWithZoneSets = {
    expr =
      let
        out =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            objects.sets.blocklist_v4 = {
              type = "ipv4_addr";
              flags = [ "interval" ];
            };
          }).output;
      in
      pkgs.lib.sort (a: b: a < b) (pkgs.lib.attrNames out.sets);
    expected = [
      "blocklist_v4"
      "lan_iifs"
    ];
  };

  testEmitTableEmptyKindsSkipped = {
    expr =
      let
        out =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
          }).output;
      in
      builtins.any (k: builtins.elem k (pkgs.lib.attrNames out)) [
        "counters"
        "quotas"
        "limits"
        "ctHelpers"
        "ctTimeouts"
        "ctExpectations"
        "secmarks"
        "synproxies"
        "tunnels"
        "maps"
        "flowtables"
      ];
    expected = false;
  };

  testMkDirectionVariantsExtraSection = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "vpn-users";
      active = {
        extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
      };
      mergedZones.vpn-users = {
        cidrs = [
          "10.8.0.0/24"
          "fd42::/64"
        ];
      };
      zoneSets = {
        vpn-users_v4 = { };
        vpn-users_v6 = { };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256)
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "vpn-users_v4"))
      ]
      [
        (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256)
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "vpn-users_v6"))
      ]
    ];
  };

  testMkDirectionVariantsExtraOnly = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "marked";
      active = {
        extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
      };
      mergedZones.marked = { };
      zoneSets = { };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ]
    ];
  };

  testMkDirectionVariantsIpv4Override = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      active = {
        ipv4 = [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "user-v4")) ];
      };
      mergedZones.lan = {
        cidrs = [ "fd00::/64" ];
      };
      zoneSets = {
        lan_v4 = { };
        lan_v6 = { };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "user-v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6")) ]
    ];
  };

  testMkDirectionVariantsInterfacesGatedByHook = {
    expr = mkDirectionVariants {
      hook = "output";
      direction = "from";
      zoneName = "lan";
      active = {
        interfaces = [
          (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "user-iifs"))
        ];
      };
      mergedZones.lan = {
        cidrs = [ "10.0.0.0/24" ];
      };
      zoneSets = {
        lan_v4 = { };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
    ];
  };

  # ===== emitTable — parent hierarchy: child sub-chain receives jump from parent =====

  testEmitTableParentBasic = {
    # web-server (node, parent dmz) has its own rule. The dmz
    # sub-chain is synthesized as a transparent dispatcher; base
    # chain jumps only to dmz; dmz jumps to web-server.
    expr =
      let
        out =
          (runEmit {
            zones.dmz = {
              interfaces = [ "dmz0" ];
              cidrs = [ "10.0.0.0/24" ];
            };
            nodes.web-server = {
              zone = "dmz";
              address.ipv4 = "10.0.0.5";
            };
            filters.allow-http = {
              from = [ "web-server" ];
              to = [ "local" ];
              rule = [
                (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80)
                nftypes.dsl.accept
              ];
            };
          }).output;
        chains = out.chains;
      in
      {
        chainKeys = pkgs.lib.sort (a: b: a < b) (builtins.attrNames chains);
        # Base chain (input-at-filter): stateful (2) + loopback (1) +
        # jump-to-dmz (multiple variants if iifs+v4) = 5 rules.
        # The base chain only jumps to root from-zones (dmz), not
        # web-server.
        baseRulesCount = builtins.length chains."input-at-filter".rules;
        # dmz transparent dispatcher: only the child-dispatch jump
        # to web-server.
        dmzRules = chains."input-at-filter__dmz-to-local".rules;
        # web-server sub-chain: the actual rule.
        webRules = chains."input-at-filter__web-server-to-local".rules;
      };
    expected = {
      chainKeys = [
        "input-at-filter"
        "input-at-filter__dmz-to-local"
        "input-at-filter__web-server-to-local"
      ];
      # 2 stateful + 1 loopback + 1 dmz jump (iif AND v4 ANDed in
      # one variant; to-side is localZone → empty variant) = 4.
      baseRulesCount = 4;
      # One child-dispatch jump (web-server has only v4, not iifs).
      dmzRules = [
        [
          (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "web-server_v4"))
          (nftypes.dsl.jump "input-at-filter__web-server-to-local")
        ]
      ];
      webRules = [
        [
          (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80)
          nftypes.dsl.accept
        ]
      ];
    };
  };
}
