/*
  Unit tests for `lib/internal/compile.nix` (exposed as
  `nftzones.internal.compile`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.compile)
    compile
    mkTable
    mkRuleset
    ;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;
in
{
  # ===== compile — runs all four phases, ctx carries every artifact =====

  testCompileFullCtx = {
    # Shape, not just presence: a regression that set, e.g.,
    # `errors = "broken"` (string instead of list) would pass a
    # bare `ctx ? errors` check. Asserting on the type of each
    # value catches structural regressions while still being cheap
    # — the actual content is exercised by the per-phase tests in
    # `tests/unit/internal/<phase>.nix`.
    expr =
      let
        ctx =
          (compile (evalTable {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
          })).ctx;
      in
      {
        # Phase 1 artifacts
        mergedZones = builtins.isAttrs ctx.mergedZones;
        allZoneNames = builtins.isList ctx.allZoneNames;
        expandedGroups = builtins.isAttrs ctx.expandedGroups;
        resolvedPriorities = builtins.isAttrs ctx.resolvedPriorities;
        zoneRefs = builtins.isList ctx.zoneRefs;
        errors = builtins.isList ctx.errors;
        warnings = builtins.isList ctx.warnings;
        # Phase 2 artifact
        cells = builtins.isAttrs ctx.cells;
        # Phase 3 artifacts
        groupedByChain = builtins.isAttrs ctx.groupedByChain;
        chainBuckets = builtins.isAttrs ctx.chainBuckets;
        # Phase 4 artifacts
        zoneSets = builtins.isAttrs ctx.zoneSets;
        baseChains = builtins.isAttrs ctx.baseChains;
        subChains = builtins.isAttrs ctx.subChains;
        userObjects = builtins.isAttrs ctx.userObjects;
        output = builtins.isAttrs ctx.output;
      };
    expected = {
      mergedZones = true;
      allZoneNames = true;
      expandedGroups = true;
      resolvedPriorities = true;
      zoneRefs = true;
      errors = true;
      warnings = true;
      cells = true;
      groupedByChain = true;
      chainBuckets = true;
      zoneSets = true;
      baseChains = true;
      subChains = true;
      userObjects = true;
      output = true;
    };
  };

  # ===== compile — Phase 1 errors propagate as a thrown message =====

  testCompileThrowsOnPhase1Error = {
    # `from = [ "missing" ]` references an unknown zone — Phase 1's
    # `checkZoneRefs` flags it; `normalizeTable` aggregates errors
    # and throws.
    expr =
      let
        attempt = builtins.tryEval (
          compile (evalTable {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "missing" ];
              to = [ "lan" ];
              rule = [ ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== mkTable — extracts ctx.output =====

  testMkTableExtractsOutput = {
    # The output is a `nftypes.dsl.table` value, which carries a
    # marker attribute. Family + name must propagate from the
    # input table.
    expr =
      let
        out = mkTable (evalTable {
          family = "ip";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        });
      in
      {
        inherit (out) family name;
        hasMarker = out ? __nftTable;
      };
    expected = {
      family = "ip";
      name = "fw";
      hasMarker = true;
    };
  };

  # ===== mkRuleset — wraps mkTable's output in a ruleset envelope =====

  testMkRulesetWrapsTable = {
    # `nftypes.dsl.ruleset` produces the canonical
    # `{ nftables = [ <commands>... ]; }` shape. The first command
    # in our case is the `add table` for our compiled table.
    expr =
      let
        rs = mkRuleset (evalTable {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        });
        firstCmd = builtins.head rs.nftables;
      in
      {
        hasNftables = rs ? nftables;
        nftablesIsList = builtins.isList rs.nftables;
        firstIsAddTable = firstCmd ? add && firstCmd.add ? table;
      };
    expected = {
      hasNftables = true;
      nftablesIsList = true;
      firstIsAddTable = true;
    };
  };

  # ===== mkRuleset — JSON output contains a table command =====

  testMkRulesetJSONShape = {
    # End-to-end: the produced ruleset, when rendered, must yield
    # the canonical `{ nftables = [ ... ] }` shape with at least
    # one `add table` command.
    expr =
      let
        json = builtins.fromJSON (
          nftypes.toJson (
            mkRuleset (evalTable {
              zones.lan = {
                interfaces = [ "lan0" ];
              };
            })
          )
        );
        firstCmd = builtins.head json.nftables;
      in
      {
        hasNftables = json ? nftables;
        firstIsAddTable = firstCmd ? add && firstCmd.add ? table;
        firstTableName = firstCmd.add.table.name;
        firstTableFamily = firstCmd.add.table.family;
      };
    expected = {
      hasNftables = true;
      firstIsAddTable = true;
      firstTableName = "fw";
      firstTableFamily = "inet";
    };
  };

  # ===== Public API — nftzones.mkTable name body =====

  testPublicMkTableAcceptsRawBody = {
    # The lib/default.nix wrapper does `evalModules` internally so
    # users can pass an unevaluated body straight in. Name is a
    # separate positional arg (mirrors `nftypes.dsl.table`).
    expr =
      let
        out = nftzones.mkTable "fw" {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        };
      in
      {
        inherit (out) family name;
      };
    expected = {
      family = "inet";
      name = "fw";
    };
  };

  # ===== Public API — name argument flows through to output =====

  testPublicMkTableUsesArgName = {
    # The user's `name` arg becomes the evalModules option key, so the
    # table's `default = name` derives the emitted nftables table name
    # from it. The `apply` guard on `types.table.name` then holds
    # `name == key`, so a body that sets a *different* `name` is
    # rejected rather than silently diverging.
    expr = (nftzones.mkTable "production-fw" { }).name;
    expected = "production-fw";
  };

  # ===== Public API — nftzones.mkRuleset name body =====

  testPublicMkRulesetAcceptsRawBody = {
    expr =
      let
        rs = nftzones.mkRuleset "fw" {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        };
      in
      {
        hasNftables = rs ? nftables;
        commandCount = builtins.length rs.nftables;
      };
    # 2 commands: 1 table declaration + 1 set declaration for lan_iifs.
    expected = {
      hasNftables = true;
      commandCount = 2;
    };
  };

  # ===== Multi-table composition — two mkTable values in one ruleset =====
  # The README documents `dsl.ruleset [ tableA tableB ]` as the
  # multi-table path. Verify both tables appear in the rendered
  # output with their declared families intact.

  testMkTableMultiTableComposition = {
    expr =
      let
        v4 = nftzones.mkTable "fw-v4" {
          family = "ip";
          zones.lan.interfaces = [ "lan0" ];
        };
        v6 = nftzones.mkTable "fw-v6" {
          family = "ip6";
          zones.lan.interfaces = [ "lan0" ];
        };
        rs = nftypes.dsl.ruleset [
          v4
          v6
        ];
        json = builtins.fromJSON (nftypes.toJson rs);
        tableCommands = builtins.filter (c: c ? add && c.add ? table) json.nftables;
        tableTuples = map (c: {
          inherit (c.add.table) name family;
        }) tableCommands;
      in
      pkgs.lib.sort (a: b: a.name < b.name) tableTuples;
    expected = [
      {
        name = "fw-v4";
        family = "ip";
      }
      {
        name = "fw-v6";
        family = "ip6";
      }
    ];
  };

  # ===== mkRuleset — chain commands appear when there are filter rules =====
  # The "2 commands" counted in `testPublicMkRulesetAcceptsRawBody`
  # is the empty case. With actual rules, the ruleset must also emit
  # add-chain commands per base + sub-chain. This catches a regression
  # where chain wiring drops out of the ruleset.

  testMkRulesetEmitsChainCommands = {
    expr =
      let
        json = builtins.fromJSON (
          nftypes.toJson (
            nftzones.mkRuleset "fw" {
              zones = {
                lan.interfaces = [ "lan0" ];
                wan.interfaces = [ "wan0" ];
              };
              filters.f = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
              };
            }
          )
        );
        chainNames = pkgs.lib.sort (a: b: a < b) (
          map (c: c.add.chain.name) (builtins.filter (c: c ? add && c.add ? chain) json.nftables)
        );
      in
      chainNames;
    expected = [
      "forward-at-filter"
      "forward-at-filter__lan-to-wan"
    ];
  };
}
