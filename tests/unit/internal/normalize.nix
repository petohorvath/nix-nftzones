/*
  Unit tests for `lib/internal/normalize.nix` (exposed as
  `nftzones.internal.normalize`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.normalize)
    convertNodesToZones
    computeZoneSets
    checkChainPlacement
    checkRpfilterOverride
    checkChainOverrideSemantics
    checkExtraSectionFields
    checkWildcardZoneMix
    checkNodeAddresses
    checkNatBodies
    checkParentRefs
    checkParentCycles
    computeChildrenOf
    computeRootZoneNames
    checkNameCollisions
    checkPolicyUniqueness
    checkSettings
    collectAllZoneNames
    expandWildcardZones
    resolvePriorities
    collectZoneRefs
    checkZoneRefs
    checkZoneMatchable
    checkChainOverridePlacement
    checkSetNameCollisions
    checkInterfaceOverlap
    checkCidrOverlap
    checkCrossAxisOverlap
    checkObjectRefs
    normalizeTable
    ;

  inherit (pkgs) lib;

  dsl = nftypes.dsl;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  /*
    Minimal table fixture for direct (non-`evalTable`) phase tests.
    Carries every field the phases destructure; tests overlay what
    they need.
  */
  emptyTable = {
    zones = { };
    nodes = { };
    filters = { };
    policies = { };
    snats = { };
    dnats = { };
    sroutes = { };
    droutes = { };
    settings = {
      wildcardZone = "all";
      localZone = "local";
    };
  };

  emptyCtx = {
    errors = [ ];
    warnings = [ ];
  };

  /*
    Run a phase against the supplied (or `emptyTable`) table with a
    fresh `emptyCtx`, returning just the resulting `ctx`
    attrset — what every phase test wants to inspect.
  */
  runPhase =
    phase: table:
    (phase {
      inherit table;
      ctx = emptyCtx;
    }).ctx;

  /*
    Run a sequence of phases, threading the context. Returns the
    final `ctx`. Used to test phases that depend on prior
    phases' outputs (e.g., `expandWildcardZones` reads
    `ctx.mergedZones`).
  */
  runPipeline =
    phases: table:
    (pkgs.lib.pipe {
      inherit table;
      ctx = emptyCtx;
    } phases).ctx;

  /*
    Same as `runPipeline` but accepts a `body` and runs it through
    the table submodule first (via `evalTable`). Use when phases
    rely on submodule-evaluated defaults (e.g. `matchOverride`'s
    nullable fields filled in from defaults).
  */
  runEvalPipeline = phases: body: runPipeline phases (evalTable body);
in
{
  # ===== convertNodesToZones — empty input =====

  testConvertNodesToZonesEmpty = {
    expr = (runPhase convertNodesToZones emptyTable).mergedZones;
    expected = { };
  };

  # ===== convertNodesToZones — dual-stack node =====

  testConvertNodesToZonesDualStack = {
    expr =
      let
        web =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              nodes.web = {
                name = "web";
                zone = "dmz";
                address = {
                  ipv4 = "10.0.0.5";
                  ipv6 = "fe80::1";
                };
              };
            }
          )).mergedZones.web;
      in
      {
        inherit (web)
          name
          parent
          interfaces
          cidrs
          matchOverride
          ;
      };
    expected = {
      name = "web";
      parent = "dmz";
      interfaces = [ ];
      cidrs = [
        "10.0.0.5/32"
        "fe80::1/128"
      ];
      matchOverride = {
        ingress = { };
        egress = { };
      };
    };
  };

  # ===== convertNodesToZones — keys preserved across multiple nodes =====

  testConvertNodesToZonesMultiple = {
    expr =
      let
        merged =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              nodes = {
                a = {
                  name = "a";
                  zone = "z1";
                  address = {
                    ipv4 = "1.1.1.1";
                    ipv6 = null;
                  };
                };
                b = {
                  name = "b";
                  zone = "z2";
                  address = {
                    ipv4 = null;
                    ipv6 = "fe80::1";
                  };
                };
              };
            }
          )).mergedZones;
      in
      {
        a = {
          inherit (merged.a)
            name
            parent
            interfaces
            cidrs
            ;
        };
        b = {
          inherit (merged.b)
            name
            parent
            interfaces
            cidrs
            ;
        };
      };
    expected = {
      a = {
        name = "a";
        parent = "z1";
        interfaces = [ ];
        cidrs = [ "1.1.1.1/32" ];
      };
      b = {
        name = "b";
        parent = "z2";
        interfaces = [ ];
        cidrs = [ "fe80::1/128" ];
      };
    };
  };

  # ===== convertNodesToZones — declared zones merged with lowered nodes =====

  testConvertNodesToZonesMergesWithDeclared = {
    expr =
      let
        merged =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              zones.dmz = {
                interfaces = [ "eth1" ];
              };
              nodes.web = {
                name = "web";
                zone = "dmz";
                address = {
                  ipv4 = "10.0.0.5";
                  ipv6 = null;
                };
              };
            }
          )).mergedZones;
      in
      {
        # Declared zone passes through as-is (raw fixture, no
        # submodule eval — only what the user wrote).
        dmz = merged.dmz;
        # Lowered node has the full zone shape.
        web = {
          inherit (merged.web)
            name
            parent
            interfaces
            cidrs
            ;
        };
      };
    expected = {
      dmz = {
        interfaces = [ "eth1" ];
      };
      web = {
        name = "web";
        parent = "dmz";
        interfaces = [ ];
        cidrs = [ "10.0.0.5/32" ];
      };
    };
  };

  # ===== convertNodesToZones — node name overlapping a zone silently overwrites =====
  # `mergedZones = zones // mapAttrs toZone nodes` — node lowering
  # always wins on collision. The collision is *separately* flagged
  # by `checkNameCollisions`; this test pins the lowering's
  # last-write-wins semantics so that contract is explicit.

  testConvertNodesToZonesNodeOverwritesZone = {
    expr =
      let
        merged =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              zones.web = {
                interfaces = [ "manual0" ];
              };
              nodes.web = {
                name = "web";
                zone = "lan";
                address = {
                  ipv4 = "10.0.0.5";
                  ipv6 = null;
                };
              };
            }
          )).mergedZones;
      in
      {
        # Lowered node overwrote the declared zone — `interfaces`
        # comes from the node, not from `manual0`.
        interfaces = merged.web.interfaces;
        cidrs = merged.web.cidrs;
        parent = merged.web.parent;
      };
    expected = {
      interfaces = [ ];
      cidrs = [ "10.0.0.5/32" ];
      parent = "lan";
    };
  };

  # ===== convertNodesToZones — table left untouched =====

  testConvertNodesToZonesTableUntouched = {
    expr =
      let
        input = emptyTable // {
          nodes.web = {
            name = "web";
            zone = "dmz";
            address = {
              ipv4 = "10.0.0.5";
              ipv6 = null;
            };
          };
        };
      in
      (convertNodesToZones {
        table = input;
        ctx = emptyCtx;
      }).table == input;
    expected = true;
  };

  # ===== checkNameCollisions — no collisions =====

  testCheckNameCollisionsNone = {
    expr =
      (runPhase checkNameCollisions (
        emptyTable
        // {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "1.1.1.1";
          };
        }
      )).errors;
    expected = [ ];
  };

  # ===== checkNameCollisions — single collision =====

  testCheckNameCollisionsOne = {
    expr =
      (runPhase checkNameCollisions (
        emptyTable
        // {
          zones.web = { };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "1.1.1.1";
          };
        }
      )).errors;
    expected = [
      {
        name = "zoneNameCollision";
        value = "name collision: 'web' is declared as both a zone and a node";
      }
    ];
  };

  # ===== checkNameCollisions — multiple collisions =====

  testCheckNameCollisionsMultiple = {
    expr =
      (runPhase checkNameCollisions (
        emptyTable
        // {
          zones = {
            a = { };
            b = { };
            c = { };
          };
          nodes = {
            a = {
              zone = "x";
              address.ipv4 = "1.1.1.1";
            };
            c = {
              zone = "x";
              address.ipv4 = "2.2.2.2";
            };
          };
        }
      )).errors;
    expected = [
      {
        name = "zoneNameCollision";
        value = "name collision: 'a' is declared as both a zone and a node";
      }
      {
        name = "zoneNameCollision";
        value = "name collision: 'c' is declared as both a zone and a node";
      }
    ];
  };

  # ===== collectAllZoneNames — declared zones + lowered nodes + localZone =====
  # Pins the in-scope set computed for wildcard expansion and
  # zone-ref validation. Note: `wildcardZone` is intentionally NOT
  # in the result — `expandWildcardZones` substitutes it before
  # checking against this list.

  testCollectAllZoneNamesShape = {
    expr =
      pkgs.lib.sort (a: b: a < b)
        (runPipeline
          [
            convertNodesToZones
            collectAllZoneNames
          ]
          (
            emptyTable
            // {
              zones = {
                lan = { };
                wan = { };
              };
              nodes.web = {
                zone = "lan";
                address.ipv4 = "10.0.0.5";
              };
            }
          )
        ).allZoneNames;
    expected = [
      "lan"
      "local"
      "wan"
      "web"
    ];
  };

  # ===== collectAllZoneNames — custom localZone joins the scope =====

  testCollectAllZoneNamesCustomLocal = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
        ]
        (
          emptyTable
          // {
            settings = {
              wildcardZone = "all";
              localZone = "host";
            };
            zones.lan = { };
          }
        )
      ).allZoneNames;
    expected = [
      "lan"
      "host"
    ];
  };

  # ===== checkChainPlacement — inet defaults are accepted =====

  testCheckChainPlacementInetDefaults = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "inet";
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.allow = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
          snats.masq = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainPlacement — bridge family + snat is rejected =====

  testCheckChainPlacementBridgeRejectsSnat = {
    # Bridge family doesn't support `nat` chains
    # (`familiesByChainType.nat = [ip ip6 inet]`); the default
    # snat placement at postrouting+srcnat must be flagged.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "bridge";
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          snats.masq = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
          };
        }
      ).errors;
    expected = [
      {
        name = "invalidChainPlacement";
        value =
          "snats.masq would emit a base chain at "
          + "(family=bridge, hook=postrouting, priority=srcnat) "
          + "— kernel rejects chain type 'nat' on hook 'postrouting' for family 'bridge'";
      }
    ];
  };

  # ===== checkChainPlacement — bridge sroute hits the null chainType branch =====

  testCheckChainPlacementBridgeSrouteUnknownPriority = {
    # Bridge has no `mangle` priority, so `chainTypeFor` returns
    # null — the validator surfaces it as a clear error rather
    # than letting emit throw.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "bridge";
          zones.lan.interfaces = [ "lan0" ];
          sroutes.mark = {
            from = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "invalidChainPlacement";
        value =
          "sroutes.mark would emit a base chain at "
          + "(family=bridge, hook=prerouting, priority=mangle) "
          + "— priority symbol 'mangle' has no value in family 'bridge'";
      }
    ];
  };

  # ===== checkChainPlacement — bridge filter+policy is fine =====

  testCheckChainPlacementBridgeFilter = {
    # Bridge supports filter chains; with no nat/route groups
    # declared the placement check passes.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "bridge";
          zones.lan.interfaces = [ "lan0" ];
          filters.allow = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkRpfilterOverride — rpfilter on, no override → silent =====

  testCheckRpfilterOverrideNoOverride = {
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        settings.rpfilter = true;
        zones.lan.interfaces = [ "lan0" ];
      }).warnings;
    expected = [ ];
  };

  # ===== checkRpfilterOverride — override but rpfilter off → silent =====

  testCheckRpfilterOverrideRpfilterOff = {
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        zones.wan.interfaces = [ "wan0" ];
        filters.early-drop = {
          from = [ "wan" ];
          to = [ "wan" ];
          rule = [ ];
          chain = {
            hook = "prerouting";
            priority = "raw";
          };
        };
      }).warnings;
    expected = [ ];
  };

  # ===== checkRpfilterOverride — both set → warning fires =====

  testCheckRpfilterOverrideConflict = {
    # User chain at (prerouting, raw) suppresses the synthesized
    # rpfilter chain in Phase 4. Validator surfaces a warning so
    # the suppression isn't silent.
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        settings.rpfilter = true;
        zones.wan.interfaces = [ "wan0" ];
        filters.early-drop = {
          from = [ "wan" ];
          to = [ "wan" ];
          rule = [ ];
          chain = {
            hook = "prerouting";
            priority = "raw";
          };
        };
      }).warnings;
    expected = [
      (
        "settings.rpfilter is enabled but a user chain override "
        + "already claims (prerouting, raw); the synthesized rpfilter "
        + "chain is suppressed and the user-authored chain is used "
        + "as-is. Add `fib saddr . iif oif eq 0 drop` to the override "
        + "manually if you want rpfilter behavior in that chain."
      )
    ];
  };

  # ===== checkRpfilterOverride — int form override is detected too =====

  testCheckRpfilterOverrideIntPriority = {
    # `priority = -300` is the int form of `"raw"`; canonicalized
    # via priorityNameOf so the check matches both forms.
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        settings.rpfilter = true;
        zones.wan.interfaces = [ "wan0" ];
        filters.early-drop = {
          from = [ "wan" ];
          to = [ "wan" ];
          rule = [ ];
          chain = {
            hook = "prerouting";
            priority = -300;
          };
        };
      }).warnings;
    expected = [
      (
        "settings.rpfilter is enabled but a user chain override "
        + "already claims (prerouting, raw); the synthesized rpfilter "
        + "chain is suppressed and the user-authored chain is used "
        + "as-is. Add `fib saddr . iif oif eq 0 drop` to the override "
        + "manually if you want rpfilter behavior in that chain."
      )
    ];
  };

  # ===== checkNodeAddresses — node with ipv4 passes =====

  testCheckNodeAddressesV4Only = {
    expr =
      (runEvalPipeline [ checkNodeAddresses ] {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web = {
          zone = "dmz";
          address.ipv4 = "10.0.0.5";
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNodeAddresses — node with ipv6 passes =====

  testCheckNodeAddressesV6Only = {
    expr =
      (runEvalPipeline [ checkNodeAddresses ] {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web = {
          zone = "dmz";
          address.ipv6 = "fe80::1";
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNodeAddresses — both-null rejected =====

  testCheckNodeAddressesBothNull = {
    expr =
      (runEvalPipeline [ checkNodeAddresses ] {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web = {
          zone = "dmz";
          address = { };
        };
      }).errors;
    expected = [
      {
        name = "nodeAddressMissing";
        value =
          "nodes.web: address must set at least one of `ipv4` / `ipv6` — "
          + "a node with no address contributes no CIDR to its lowered zone.";
      }
    ];
  };

  # ===== checkNodeAddresses — aggregates across multiple nodes =====

  testCheckNodeAddressesAggregates = {
    expr =
      builtins.length
        (runEvalPipeline [ checkNodeAddresses ] {
          zones.dmz.interfaces = [ "dmz0" ];
          nodes.a = {
            zone = "dmz";
            address = { };
          };
          nodes.b = {
            zone = "dmz";
            address = { };
          };
          nodes.c = {
            zone = "dmz";
            address.ipv4 = "10.0.0.5";
          };
        }).errors;
    expected = 2;
  };

  # ===== checkNatBodies — well-formed snat passes =====

  testCheckNatBodiesValidSnat = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        snats.outbound = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.snat.addr = "203.0.113.5";
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — masquerade has no addr requirement =====

  testCheckNatBodiesValidMasquerade = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        snats.outbound = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.masquerade = { };
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — empty snat body rejected =====

  testCheckNatBodiesEmptySnat = {
    # `rule.snat = { }` selects the `snat` tag with an all-null
    # body. Type accepts it (every natBody field is nullable);
    # nft rejects `snat to;` with no target at activation. This
    # validator catches it earlier with a clear error.
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        snats.outbound = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.snat = { };
        };
      }).errors;
    expected = [
      {
        name = "natBodyMissingAddr";
        value =
          "snats.outbound: rule.snat.addr is null — `snat` requires a target "
          + "address. Use `rule.masquerade = { }` for auto-target via the "
          + "outgoing interface, or set `rule.snat.addr` explicitly.";
      }
    ];
  };

  # ===== checkNatBodies — well-formed dnat passes =====

  testCheckNatBodiesValidDnat = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.wan.interfaces = [ "wan0" ];
        dnats.web-fwd = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.dnat = {
              addr = "10.0.0.5";
              port = 443;
            };
          };
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — redirect has no addr requirement =====

  testCheckNatBodiesValidRedirect = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.wan.interfaces = [ "wan0" ];
        dnats.ssh-redirect = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.redirect.port = 22;
          };
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — empty dnat action body rejected =====

  testCheckNatBodiesEmptyDnat = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.wan.interfaces = [ "wan0" ];
        dnats.bad-fwd = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.dnat = { };
          };
        };
      }).errors;
    expected = [
      {
        name = "natBodyMissingAddr";
        value =
          "dnats.bad-fwd: rule.action.dnat.addr is null — `dnat` requires a "
          + "target address. Use `rule.action.redirect = { port = N; }` for "
          + "redirect-to-localhost, or set `rule.action.dnat.addr` explicitly.";
      }
    ];
  };

  # ===== checkNatBodies — errors aggregate across both groups =====

  testCheckNatBodiesAggregates = {
    expr =
      builtins.length
        (runEvalPipeline [ checkNatBodies ] {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          snats.bad-s = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.snat = { };
          };
          dnats.bad-d = {
            from = [ "wan" ];
            rule = {
              match = [ ];
              action.dnat = { };
            };
          };
        }).errors;
    expected = 2;
  };

  # ===== checkSettings — defaults are conflict-free =====

  testCheckSettingsNoConflict = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkSettings — wildcardZone equals localZone =====

  testCheckSettingsWildcardEqualsLocal = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            settings = {
              wildcardZone = "any";
              localZone = "any";
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "settingsConflict";
        value = "settings.wildcardZone and settings.localZone are both 'any' — they must differ";
      }
    ];
  };

  # ===== checkSettings — wildcardZone shadows declared zone =====

  testCheckSettingsWildcardShadowsZone = {
    # Default wildcardZone is "all"; declaring zones.all collides.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            zones.all = { };
          }
        )
      ).errors;
    expected = [
      {
        name = "settingsConflict";
        value = "settings.wildcardZone 'all' collides with a declared zone or node";
      }
    ];
  };

  # ===== checkSettings — localZone shadows declared node =====

  testCheckSettingsLocalShadowsNode = {
    # Default localZone is "local"; declaring nodes.local collides.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            nodes.local = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "settingsConflict";
        value = "settings.localZone 'local' collides with a declared zone or node";
      }
    ];
  };

  # ===== checkPolicyUniqueness — no policies =====

  testCheckPolicyUniquenessNoPolicies = {
    expr =
      (runPipeline [
        convertNodesToZones
        computeRootZoneNames
        collectAllZoneNames
        expandWildcardZones
        checkPolicyUniqueness
      ] emptyTable).errors;
    expected = [ ];
  };

  # ===== checkPolicyUniqueness — single policy =====

  testCheckPolicyUniquenessSingle = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            policies.lan-to-wan = {
              from = [ "lan" ];
              to = [ "wan" ];
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkPolicyUniqueness — distinct (from, to) pairs =====

  testCheckPolicyUniquenessDistinct = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
              dmz = {
                interfaces = [ "dmz0" ];
              };
            };
            policies = {
              a = {
                from = [ "lan" ];
                to = [ "wan" ];
              };
              b = {
                from = [ "lan" ];
                to = [ "dmz" ];
              };
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkPolicyUniqueness — direct duplicate (from, to) =====

  testCheckPolicyUniquenessDirectDuplicate = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            policies = {
              allow = {
                from = [ "lan" ];
                to = [ "wan" ];
              };
              deny = {
                from = [ "lan" ];
                to = [ "wan" ];
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "policyConflict";
        value = "duplicate policy for (lan → wan): allow, deny";
      }
    ];
  };

  # ===== checkPolicyUniqueness — wildcard expansion produces conflict =====

  testCheckPolicyUniquenessWildcardConflict = {
    # `broad` fans out to a cell per in-scope source zone for `to = wan`;
    # `specific` produces only the (lan, wan) cell. The two collide on
    # (lan → wan).
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            policies = {
              broad = {
                from = [ "all" ];
                to = [ "wan" ];
              };
              specific = {
                from = [ "lan" ];
                to = [ "wan" ];
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "policyConflict";
        value = "duplicate policy for (lan → wan): broad, specific";
      }
    ];
  };

  # ===== expandWildcardZones — pass-through (no wildcard) =====

  testExpandWildcardsPassThrough = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
        ]
        (
          emptyTable
          // {
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
            };
          }
        )
      ).expandedGroups.filters.f;
    expected = {
      from = [ "lan" ];
      to = [ "wan" ];
    };
  };

  # ===== expandWildcardZones — wildcard expanded with dedup =====

  testExpandWildcardsExpand = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.f = {
              from = [
                "lan"
                "all"
              ];
              to = [ "wan" ];
            };
          }
        )
      ).expandedGroups.filters.f;
    # Scope = { lan, wan } ++ [ "local" ] (default localZone).
    expected = {
      from = [
        "lan"
        "wan"
        "local"
      ];
      to = [ "wan" ];
    };
  };

  # ===== expandWildcardZones — single-direction groups =====

  testExpandWildcardsSingleDir = {
    expr =
      let
        out =
          runPipeline
            [
              convertNodesToZones
              computeRootZoneNames
              collectAllZoneNames
              expandWildcardZones
            ]
            (
              emptyTable
              // {
                zones = {
                  x = { };
                  y = { };
                };
                settings = {
                  wildcardZone = "all";
                  localZone = "ignored";
                };
                dnats.d = {
                  from = [ "all" ];
                };
                sroutes.s = {
                  from = [ "all" ];
                };
                droutes.dr = {
                  to = [ "all" ];
                };
              }
            );
      in
      {
        dnatsFrom = out.expandedGroups.dnats.d.from;
        sroutesFrom = out.expandedGroups.sroutes.s.from;
        droutesTo = out.expandedGroups.droutes.dr.to;
      };
    expected = {
      dnatsFrom = [
        "x"
        "y"
        "ignored"
      ];
      sroutesFrom = [
        "x"
        "y"
        "ignored"
      ];
      droutesTo = [
        "x"
        "y"
        "ignored"
      ];
    };
  };

  # ===== expandWildcardZones — table left untouched =====

  testExpandWildcardsTableUntouched = {
    expr =
      let
        input = emptyTable // {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "all" ];
            to = [ "lan" ];
          };
        };
        result =
          pkgs.lib.pipe
            {
              table = input;
              ctx = emptyCtx;
            }
            [
              convertNodesToZones
              computeRootZoneNames
              collectAllZoneNames
              expandWildcardZones
            ];
      in
      result.table == input;
    expected = true;
  };

  # ===== resolvePriorities — policies group is excluded =====
  # Policies don't carry a `priority` field; resolvePriorities
  # operates on filters / snats / dnats / sroutes / droutes only.
  # Locks the contract so Phase 3 can rely on `cell ? priority` to
  # distinguish policies from priority-bearing kinds.

  testResolvePrioritiesExcludesPolicies = {
    expr = builtins.attrNames (runPhase resolvePriorities emptyTable).resolvedPriorities;
    expected = [
      "dnats"
      "droutes"
      "filters"
      "snats"
      "sroutes"
    ];
  };

  # ===== resolvePriorities — empty groups =====

  testResolvePrioritiesEmpty = {
    expr = (runPhase resolvePriorities emptyTable).resolvedPriorities;
    expected = {
      filters = { };
      snats = { };
      dnats = { };
      sroutes = { };
      droutes = { };
    };
  };

  # ===== resolvePriorities — every symbol resolves to its int =====

  testResolvePrioritiesAllSymbols = {
    expr =
      (runPhase resolvePriorities (
        emptyTable
        // {
          filters = {
            f-first = {
              priority = "first";
            };
            f-pre = {
              priority = "preDispatch";
            };
            f-post = {
              priority = "postDispatch";
            };
            f-default = {
              priority = "default";
            };
            f-last = {
              priority = "last";
            };
          };
        }
      )).resolvedPriorities.filters;
    expected = {
      f-first = 1;
      f-pre = 50;
      f-post = 100;
      f-default = 500;
      f-last = 999;
    };
  };

  # ===== resolvePriorities — int values pass through =====

  testResolvePrioritiesInts = {
    expr =
      (runPhase resolvePriorities (
        emptyTable
        // {
          filters.f = {
            priority = 250;
          };
        }
      )).resolvedPriorities.filters.f;
    expected = 250;
  };

  # ===== resolvePriorities — covers all priority-bearing groups =====

  testResolvePrioritiesAllGroups = {
    expr =
      let
        out =
          (runPhase resolvePriorities (
            emptyTable
            // {
              filters.f = {
                priority = "first";
              };
              snats.s = {
                priority = "default";
              };
              dnats.d = {
                priority = "last";
              };
              sroutes.sr = {
                priority = "preDispatch";
              };
              droutes.dr = {
                priority = "postDispatch";
              };
            }
          )).resolvedPriorities;
      in
      {
        filters = out.filters.f;
        snats = out.snats.s;
        dnats = out.dnats.d;
        sroutes = out.sroutes.sr;
        droutes = out.droutes.dr;
      };
    expected = {
      filters = 1;
      snats = 500;
      dnats = 999;
      sroutes = 50;
      droutes = 100;
    };
  };

  # ===== collectZoneRefs — empty table =====

  testCollectRefsEmpty = {
    expr = (runPhase collectZoneRefs emptyTable).zoneRefs;
    expected = [ ];
  };

  # ===== collectZoneRefs — filter with multi-element from + to =====

  testCollectRefsFilter = {
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          filters.web-out = {
            from = [
              "lan"
              "guest"
            ];
            to = [ "wan" ];
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "lan";
        direction = "from";
        path = "filters.web-out.from[0]";
      }
      {
        zone = "guest";
        direction = "from";
        path = "filters.web-out.from[1]";
      }
      {
        zone = "wan";
        direction = "to";
        path = "filters.web-out.to[0]";
      }
    ];
  };

  # ===== collectZoneRefs — single-direction groups =====

  testCollectRefsSingleDir = {
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          dnats.d = {
            from = [ "wan" ];
          };
          sroutes.s = {
            from = [ "guest" ];
          };
          droutes.dr = {
            to = [ "vpn" ];
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "wan";
        direction = "from";
        path = "dnats.d.from[0]";
      }
      {
        zone = "guest";
        direction = "from";
        path = "sroutes.s.from[0]";
      }
      {
        zone = "vpn";
        direction = "to";
        path = "droutes.dr.to[0]";
      }
    ];
  };

  # ===== collectZoneRefs — node parent references =====

  testCollectRefsNodes = {
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          nodes = {
            api = {
              zone = "dmz";
              address.ipv4 = "1.1.1.1";
            };
            web = {
              zone = "dmz";
              address.ipv4 = "2.2.2.2";
            };
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "dmz";
        path = "nodes.api.zone";
      }
      {
        zone = "dmz";
        path = "nodes.web.zone";
      }
    ];
  };

  # ===== collectZoneRefs — group ordering =====

  testCollectRefsGroupOrder = {
    expr =
      map (r: r.path)
        (runPhase collectZoneRefs (
          emptyTable
          // {
            filters.f = {
              from = [ "z" ];
              to = [ "z" ];
            };
            policies.p = {
              from = [ "z" ];
              to = [ "z" ];
            };
            snats.sn = {
              from = [ "z" ];
              to = [ "z" ];
            };
            dnats.d = {
              from = [ "z" ];
            };
            sroutes.sr = {
              from = [ "z" ];
            };
            droutes.dr = {
              to = [ "z" ];
            };
            nodes.n = {
              zone = "z";
              address.ipv4 = "1.1.1.1";
            };
          }
        )).zoneRefs;
    expected = [
      "filters.f.from[0]"
      "filters.f.to[0]"
      "policies.p.from[0]"
      "policies.p.to[0]"
      "snats.sn.from[0]"
      "snats.sn.to[0]"
      "dnats.d.from[0]"
      "sroutes.sr.from[0]"
      "droutes.dr.to[0]"
      "nodes.n.zone"
    ];
  };

  # ===== collectZoneRefs — wildcard placeholders skipped =====

  testCollectRefsSkipsWildcard = {
    # The wildcard ("all") should not appear in zoneRefs — it's
    # not a reference, it's a directive. Slot indices preserve the
    # user's input positions.
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          filters.f = {
            from = [
              "lan"
              "all"
              "wan"
            ];
            to = [ "all" ];
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "lan";
        direction = "from";
        path = "filters.f.from[0]";
      }
      {
        zone = "wan";
        direction = "from";
        path = "filters.f.from[2]";
      }
    ];
  };

  # ===== checkZoneRefs — all references valid =====

  testCheckZoneRefsAllValid = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          collectZoneRefs
          checkZoneRefs
        ]
        (
          emptyTable
          // {
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
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneRefs — unknown reference produces error =====

  testCheckZoneRefsUnknown = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          collectZoneRefs
          checkZoneRefs
        ]
        (
          emptyTable
          // {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "missing" ];
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "invalidZoneRef";
        value = "filters.f.to[0] references unknown zone 'missing' (known: lan, local)";
      }
    ];
  };

  # ===== checkZoneMatchable — interfaces alone make a zone matchable =====

  testCheckZoneMatchableInterfacesOnly = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
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
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — cidrs alone make a zone matchable =====

  testCheckZoneMatchableCidrsOnly = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            lan = {
              cidrs = [ "10.0.0.0/24" ];
            };
            wan = {
              cidrs = [ "0.0.0.0/0" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — matchOverride on both sides is matchable =====

  testCheckZoneMatchableOverrideBoth = {
    # An `extra` section with a `meta mark` clause makes the zone
    # matchable on both sides without any interfaces / cidrs.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.custom = {
            matchOverride = {
              ingress.extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
              egress.extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
            };
          };
          filters.f = {
            from = [ "custom" ];
            to = [ "custom" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — empty zone used as `from` flags ingress =====

  testCheckZoneMatchableEmptyAsFrom = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            empty = { };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.f = {
            from = [ "empty" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.f.from[0] references zone 'empty' which has no ingress match"
          + " (no interfaces, no CIDRs, and no matchOverride sections set on the ingress side)";
      }
    ];
  };

  # ===== checkZoneMatchable — empty zone used as `to` flags egress =====

  testCheckZoneMatchableEmptyAsTo = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            empty = { };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "empty" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.f.to[0] references zone 'empty' which has no egress match"
          + " (no interfaces, no CIDRs, and no matchOverride sections set on the egress side)";
      }
    ];
  };

  # ===== checkZoneMatchable — asymmetric override flags only the missing side =====

  testCheckZoneMatchableAsymmetricOverride = {
    # Zone has only `ingress` populated (via the `extra` section). Used as
    # `from` (ingress) → no error. Used as `to` (egress) → flagged.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.partial = {
            matchOverride.ingress.extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
          };
          filters.from-ok = {
            from = [ "partial" ];
            to = [ "partial" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.from-ok.to[0] references zone 'partial' which has no egress match"
          + " (no interfaces, no CIDRs, and no matchOverride sections set on the egress side)";
      }
    ];
  };

  # ===== checkZoneMatchable — empty list section doesn't count as contributing =====

  testCheckZoneMatchableEmptySectionDoesntCount = {
    # `matchOverride.egress.extra = [ ]` (empty list) is treated
    # the same as `null` — both mean "no constraint contributed".
    # Zone has no interfaces / cidrs / other sections → unmatchable
    # on egress.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.empty-section = {
            matchOverride.egress.extra = [ ];
          };
          filters.f = {
            from = [ "empty-section" ];
            to = [ "empty-section" ];
            rule = [ ];
          };
        }
      ).errors;
    # Both directions are unmatchable (empty-section has nothing). Two
    # errors: ingress (mapped from `from`) and egress (mapped from `to`).
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.f.from[0] references zone 'empty-section' which has no ingress match"
          + " (no interfaces, no CIDRs, and no matchOverride sections set on the ingress side)";
      }
      {
        name = "zoneNotMatchable";
        value =
          "filters.f.to[0] references zone 'empty-section' which has no egress match"
          + " (no interfaces, no CIDRs, and no matchOverride sections set on the egress side)";
      }
    ];
  };

  # ===== checkZoneMatchable — localZone references are skipped =====

  testCheckZoneMatchableSkipsLocalZone = {
    # `local` is the default localZone sentinel — never declared as a
    # zone, never has a `mergedZones` entry. Phase 4 skips that
    # side's match emission, so this validator must skip it too.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.wan = {
            interfaces = [ "wan0" ];
          };
          filters.in-rule = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
          };
          filters.out-rule = {
            from = [ "local" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — unknown zones are left to checkZoneRefs =====

  testCheckZoneMatchableSkipsUnknownZone = {
    # An unknown zone name is checkZoneRefs's problem; this validator
    # should not double-report.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "missing" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — node parent refs are not direction-bound =====

  testCheckZoneMatchableSkipsParentRefs = {
    # `nodes.<x>.zone` is a parent reference — names a zone for
    # inheritance, doesn't match traffic. No `direction` field on the
    # ref; checkZoneMatchable filters it out.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.empty = { };
          nodes.api = {
            zone = "empty";
            address.ipv4 = "10.0.0.5";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — default placement (no override) =====

  testCheckChainOverridePlacementNoOverride = {
    # No `chain` field set → validator skips the entry.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
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
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — override at default placement =====

  testCheckChainOverridePlacementValidOverride = {
    # User sets `chain = { hook = "forward"; priority = "filter"; }`
    # explicitly. Both directions reachable at hook=forward, no error.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
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
            chain = {
              hook = "forward";
              priority = "filter";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — addr-matchable at restrictive hook =====

  testCheckChainOverridePlacementAddrReachable = {
    # `wan` has CIDRs → `daddr` works at any hook, including
    # prerouting where `oifname` is unavailable. No error.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              cidrs = [ "203.0.113.0/24" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — interface-only zone unreachable at restrictive hook =====

  testCheckChainOverridePlacementUnreachable = {
    # `host` is interface-only; at hook=prerouting, `oifname` is
    # unavailable → `to = host` cannot be matched. Flag.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
            };
            host = {
              interfaces = [ "lo" ];
            };
          };
          filters.early-drop = {
            from = [ "wan" ];
            to = [ "host" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [
      {
        name = "chainOverrideUnreachable";
        value =
          "filters.early-drop.to references zone 'host' which has no egress match expressible at chain"
          + " (hook=prerouting, priority=raw)"
          + " — zone has no daddr CIDRs and no hook-agnostic matchOverride.egress sections"
          + " (ipv4 / ipv6 / extra) set, and oifname is unavailable in prerouting";
      }
    ];
  };

  # ===== checkChainOverridePlacement — localZone is always reachable =====

  testCheckChainOverridePlacementSkipsLocalZone = {
    # `to = local` would naively look unreachable (sentinel has no
    # mergedZones entry), but it's a wildcard. No error.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones.wan = {
            interfaces = [ "wan0" ];
          };
          filters.f = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — hook-agnostic matchOverride section makes the zone reachable =====

  testCheckChainOverridePlacementMatchOverrideTrusted = {
    # `host` has a hook-agnostic `matchOverride.egress.extra`
    # section → reachable at any hook. No error even at restrictive
    # `prerouting` (where `oifname` is unavailable).
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
            };
            host = {
              interfaces = [ "lo" ];
              matchOverride.egress.extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
            };
          };
          filters.f = {
            from = [ "wan" ];
            to = [ "host" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — wildcard expansion checks each resolved zone =====

  testCheckChainOverridePlacementWildcardExpansion = {
    # `to = [ "all" ]` expands to declared zones + localZone.
    # `host` (iif-only) fails at prerouting; `wan` (with CIDRs)
    # passes; `local` (sentinel) skipped. Expect ONE error for host.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeRootZoneNames
          collectAllZoneNames
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
              cidrs = [ "203.0.113.0/24" ];
            };
            host = {
              interfaces = [ "lo" ];
            };
          };
          filters.f = {
            from = [ "wan" ];
            to = [ "all" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [
      {
        name = "chainOverrideUnreachable";
        value =
          "filters.f.to references zone 'host' which has no egress match expressible at chain"
          + " (hook=prerouting, priority=raw)"
          + " — zone has no daddr CIDRs and no hook-agnostic matchOverride.egress sections"
          + " (ipv4 / ipv6 / extra) set, and oifname is unavailable in prerouting";
      }
    ];
  };

  # ===== normalizeTable — empty table =====

  testNormalizeEmpty = {
    expr =
      (normalizeTable (evalTable {
        name = "fw";
      })).ctx.mergedZones;
    expected = { };
  };

  # ===== normalizeTable — nodes lowered into mergedZones =====

  testNormalizeLowersNodes = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones.dmz = {
            interfaces = [ "eth1" ];
          };
          nodes.web = {
            zone = "dmz";
            address.ipv4 = "10.0.0.5";
          };
        });
        web = out.ctx.mergedZones.web;
      in
      {
        zoneNames = pkgs.lib.sort (a: b: a < b) (builtins.attrNames out.ctx.mergedZones);
        webFields = {
          inherit (web)
            name
            parent
            interfaces
            cidrs
            ;
        };
      };
    expected = {
      zoneNames = [
        "dmz"
        "web"
      ];
      webFields = {
        name = "web";
        parent = "dmz";
        interfaces = [ ];
        cidrs = [ "10.0.0.5/32" ];
      };
    };
  };

  # ===== normalizeTable — from-wildcard expands to roots only =====

  testNormalizeResolvesWildcards = {
    # Under hierarchy, `from = [ "all" ]` expands to root zones
    # only — descendants ride into the chain via parent dispatch.
    # The `web` node (parent `lan`) is NOT a root, so it doesn't
    # appear in the expansion.
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "10.0.0.5";
          };
          filters.f = {
            from = [ "all" ];
            to = [ "wan" ];
            rule = [ ];
          };
        });
      in
      pkgs.lib.sort (a: b: a < b) out.ctx.expandedGroups.filters.f.from;
    expected = [
      "lan"
      "local"
      "wan"
    ];
  };

  # ===== normalizeTable — custom localZone joins the wildcard scope =====

  testNormalizeCustomLocalZone = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          settings.localZone = "host";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "all" ];
            to = [ "host" ];
            rule = [ ];
          };
        });
      in
      pkgs.lib.sort (a: b: a < b) out.ctx.expandedGroups.filters.f.from;
    expected = [
      "host"
      "lan"
    ];
  };

  # ===== normalizeTable — table stays untouched =====

  testNormalizeTableUntouched = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "10.0.0.5";
          };
          filters.f = {
            from = [ "all" ];
            to = [ "lan" ];
            rule = [ ];
          };
        });
      in
      {
        filtersFrom = out.table.filters.f.from;
        nodeNames = builtins.attrNames out.table.nodes;
      };
    expected = {
      filtersFrom = [ "all" ];
      nodeNames = [ "web" ];
    };
  };

  # ===== normalizeTable — name collision throws =====

  testNormalizeCollisionThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.web = { };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — unknown zone reference throws =====

  testNormalizeUnknownRefThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "missing" ];
              rule = [ ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — unknown node-parent reference throws =====

  testNormalizeUnknownNodeParentThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            nodes.web = {
              zone = "missing";
              address.ipv4 = "1.1.1.1";
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — settings conflict throws =====

  testNormalizeSettingsConflictThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.all = { };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== computeZoneSets — empty mergedZones produces empty zoneSets =====

  testComputeZoneSetsEmpty = {
    expr =
      (runEvalPipeline [
        convertNodesToZones
        computeChildrenOf
        computeZoneSets
      ] { name = "fw"; }).zoneSets;
    expected = { };
  };

  # ===== computeZoneSets — multi-zone fold produces all expected keys =====

  testComputeZoneSetsMultipleZones = {
    # Three zones with different field combinations exercise
    # all three suffixes; the fold merges per-zone genSets
    # outputs into one flat attrset.
    expr = pkgs.lib.sort (a: b: a < b) (
      builtins.attrNames
        (runEvalPipeline
          [
            convertNodesToZones
            computeChildrenOf
            computeZoneSets
          ]
          {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                cidrs = [ "0.0.0.0/0" ];
              };
              vpn = {
                interfaces = [ "wg0" ];
                cidrs = [ "fd00::/8" ];
              };
            };
          }
        ).zoneSets
    );
    expected = [
      "lan_iifs"
      "vpn_iifs"
      "vpn_v6"
      "wan_v4"
    ];
  };

  # ===== checkSetNameCollisions — no collision produces no errors =====

  testCheckSetNameCollisionsClean = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkSetNameCollisions
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          objects.sets.user-blocklist = {
            type = "ipv4_addr";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkSetNameCollisions — colliding name flagged =====

  testCheckSetNameCollisionsConflict = {
    # Zone `lan` has v4 CIDRs → synthesizes `lan_v4`. User
    # declares `objects.sets.lan_v4` → collision.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkSetNameCollisions
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
                cidrs = [ "10.0.0.0/24" ];
              };
              objects.sets.lan_v4 = {
                type = "ipv4_addr";
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        name = (builtins.head errors).name;
        nm = pkgs.lib.hasInfix "lan_v4" (builtins.head errors).value;
        zone = pkgs.lib.hasInfix "zone 'lan'" (builtins.head errors).value;
        suffix = pkgs.lib.hasInfix "suffix 'v4'" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      name = "setNameCollision";
      nm = true;
      zone = true;
      suffix = true;
    };
  };

  # ===== checkSetNameCollisions — underscore-named zone resolves correctly =====

  testCheckSetNameCollisionsUnderscoreZone = {
    # Zone `web_app` with v4 CIDRs synthesizes `web_app_v4`. User
    # declares `objects.sets.web_app_v4` → collision. The error
    # must name `web_app` (not `web` + suffix `app_v4`).
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkSetNameCollisions
            ]
            {
              name = "fw";
              zones.web_app = {
                interfaces = [ "wa0" ];
                cidrs = [ "10.1.0.0/24" ];
              };
              objects.sets.web_app_v4 = {
                type = "ipv4_addr";
              };
            }
          ).errors;
      in
      {
        zone = pkgs.lib.hasInfix "zone 'web_app'" (builtins.head errors).value;
        suffix = pkgs.lib.hasInfix "suffix 'v4'" (builtins.head errors).value;
      };
    expected = {
      zone = true;
      suffix = true;
    };
  };

  # ===== checkSetNameCollisions — non-zone-derived name accepted =====

  testCheckSetNameCollisionsUnrelatedName = {
    # `objects.sets.lan_other` doesn't match the
    # `<zone>_{iifs,v4,v6}` pattern → no collision.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkSetNameCollisions
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          objects.sets.lan_other = {
            type = "ipv4_addr";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — empty rule bodies produce no errors =====

  testCheckObjectRefsEmpty = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — declared counter resolves =====

  testCheckObjectRefsCounterResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          objects.counters.drops = { };
          filters.f = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [
              (dsl.counter.ref "drops")
              dsl.drop
            ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — undeclared counter flagged =====

  testCheckObjectRefsCounterUnknown = {
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
              };
              filters.f = {
                from = [ "lan" ];
                to = [ "lan" ];
                rule = [ (dsl.counter.ref "missing-counter") ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        name = (builtins.head errors).name;
        path = pkgs.lib.hasInfix "filters.f.rule" (builtins.head errors).value;
        kind = pkgs.lib.hasInfix "counters" (builtins.head errors).value;
        nm = pkgs.lib.hasInfix "missing-counter" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      name = "objectRefUnknown";
      path = true;
      kind = true;
      nm = true;
    };
  };

  # ===== checkObjectRefs — multiple kinds across multiple groups =====

  testCheckObjectRefsMultipleKindsAcrossGroups = {
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones = {
                lan = {
                  interfaces = [ "lan0" ];
                };
                wan = {
                  interfaces = [ "wan0" ];
                };
              };
              filters.bad-counter = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ (dsl.counter.ref "ghost") ];
              };
              dnats.bad-set = {
                from = [ "wan" ];
                rule = {
                  match = [
                    (dsl.inSet nftypes.dsl.fields.ip.saddr (dsl.expr.setRef "ghost-set"))
                  ];
                  action.dnat = {
                    addr = "10.0.0.5";
                    port = 80;
                  };
                };
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        kinds = pkgs.lib.sort (a: b: a < b) (
          map (e: builtins.head (pkgs.lib.match ".* unknown ([a-zA-Z]+) object .*" e.value)) errors
        );
      };
    expected = {
      count = 2;
      kinds = [
        "counters"
        "sets"
      ];
    };
  };

  # ===== checkObjectRefs — zone-derived auto-set names accepted (option a) =====

  testCheckObjectRefsZoneSetAccepted = {
    # Per open question 6 (decision (a)): users can reference
    # zone-derived sets like `lan_v4` directly in match clauses;
    # they're synthesized at Phase 4 but the validator must
    # treat them as known.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          filters.use-zone-set = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [
              (dsl.inSet nftypes.dsl.fields.ip.saddr (dsl.expr.setRef "lan_v4"))
              dsl.accept
            ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — zone-derived names limited to existing zones =====

  testCheckObjectRefsUnknownZoneSetFlagged = {
    # `wan_v6` would only exist if zone `wan` had v6 CIDRs; it
    # doesn't, so the ref is unresolved.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.wan = {
                interfaces = [ "wan0" ];
              };
              filters.f = {
                from = [ "wan" ];
                to = [ "wan" ];
                rule = [
                  (dsl.inSet nftypes.dsl.fields.ip6.saddr (dsl.expr.setRef "wan_v6"))
                  dsl.accept
                ];
              };
            }
          ).errors;
      in
      builtins.length errors;
    expected = 1;
  };

  # ===== checkObjectRefs — matchOverride content is walked =====

  testCheckObjectRefsMatchOverrideUnknown = {
    # A user-supplied matchOverride is also a vector for
    # named-ref typos — checkObjectRefs must walk it just like
    # entry.rule bodies.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
                matchOverride.ingress.ipv4 = [
                  (dsl.inSet nftypes.dsl.fields.ip.saddr (dsl.expr.setRef "ghost-set"))
                ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        path = pkgs.lib.hasInfix "zones.lan.matchOverride.ingress.ipv4" (builtins.head errors).value;
        kind = pkgs.lib.hasInfix "sets" (builtins.head errors).value;
        nm = pkgs.lib.hasInfix "ghost-set" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      path = true;
      kind = true;
      nm = true;
    };
  };

  # ===== checkObjectRefs — object bodies with no refs produce no errors =====

  testCheckObjectRefsObjectBodiesNoFalsePositives = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          objects = {
            counters.drops = { };
            limits.burst-1 = {
              rate = 100;
              per = "second";
            };
            sets.blocklist = {
              type = "ipv4_addr";
              elem = [
                "1.2.3.4"
                "5.6.7.8"
              ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — element-attached stmt ref flagged when unknown =====

  testCheckObjectRefsElementStmtUnknown = {
    # Per-element stateful statements (`add element ip filter
    # tracker { 1.2.3.4 counter "tracker-hits" }`) carry refs
    # that must resolve against `objects.<kind>` keys.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeChildrenOf
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
              };
              objects.sets.tracker = {
                type = "ipv4_addr";
                elem = [
                  (dsl.expr.elem {
                    val = "1.2.3.4";
                    stmt = [ (dsl.counter.ref "ghost-counter") ];
                  })
                ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        path = pkgs.lib.hasInfix "objects.sets.tracker" (builtins.head errors).value;
        kind = pkgs.lib.hasInfix "counters" (builtins.head errors).value;
        nm = pkgs.lib.hasInfix "ghost-counter" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      path = true;
      kind = true;
      nm = true;
    };
  };

  # ===== checkObjectRefs — element-attached stmt ref accepted when known =====

  testCheckObjectRefsElementStmtResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          objects = {
            counters.tracker-hits = { };
            sets.tracker = {
              type = "ipv4_addr";
              elem = [
                (dsl.expr.elem {
                  val = "1.2.3.4";
                  stmt = [ (dsl.counter.ref "tracker-hits") ];
                })
              ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — matchOverride resolved refs accepted =====

  testCheckObjectRefsMatchOverrideResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeChildrenOf
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            matchOverride.egress.ipv4 = [
              (dsl.inSet nftypes.dsl.fields.ip.daddr (dsl.expr.setRef "blocklist"))
            ];
          };
          objects.sets.blocklist = {
            type = "ipv4_addr";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== normalizeTable — unknown object ref throws =====

  testNormalizeUnknownObjectRefThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "lan" ];
              rule = [ (dsl.counter.ref "ghost") ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — multiple validators failing aggregate into one throw =====
  # Phase 1 is fail-aggregating: when multiple validators detect
  # problems, normalizeTable throws ONCE with all messages, not
  # validator-by-validator. The throw must mention every failing
  # category so the user sees the full picture in one shot.

  testNormalizeMultipleErrorsAggregated = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            # Triggers checkNameCollisions: zone+node share "web"
            zones.web = { };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
            # Triggers checkZoneRefs: "missing" is unknown
            filters.f = {
              from = [ "missing" ];
              to = [ "web" ];
              rule = [ ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — full ctx shape after the pipeline =====
  # Pin the keys Phase 2 / 3 / 4 read from `ctx`. A silent rename
  # would cascade into downstream phase failures; this test traps
  # that at the contract boundary.

  testNormalizeCtxShape = {
    expr = pkgs.lib.sort (a: b: a < b) (
      builtins.attrNames
        (normalizeTable (evalTable {
          name = "fw";
          zones.lan.interfaces = [ "lan0" ];
        })).ctx
    );
    expected = [
      "allZoneNames"
      "childrenOf"
      "errors"
      "expandedGroups"
      "mergedZones"
      "resolvedPriorities"
      "rootZoneNames"
      "warnings"
      "zoneRefs"
      "zoneSets"
    ];
  };

  # ===== normalizeTable — declared zones survive intact in mergedZones =====

  testNormalizeZonesPassThrough = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones.lan = {
            interfaces = [ "eth1" ];
            cidrs = [ "10.0.0.0/24" ];
          };
        });
      in
      {
        interfaces = out.ctx.mergedZones.lan.interfaces;
        cidrs = out.ctx.mergedZones.lan.cidrs;
      };
    expected = {
      interfaces = [ "eth1" ];
      cidrs = [ "10.0.0.0/24" ];
    };
  };

  # ===== checkParentRefs — null parent passes =====

  testCheckParentRefsNullPasses = {
    expr =
      (runPipeline [
        convertNodesToZones
        checkParentRefs
      ] emptyTable).errors;
    expected = [ ];
  };

  # ===== checkParentRefs — known parent passes =====

  testCheckParentRefsKnownPasses = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentRefs
        ]
        (
          emptyTable
          // {
            zones = {
              dmz = {
                interfaces = [ "dmz0" ];
              };
              web = {
                parent = "dmz";
                cidrs = [ "10.0.0.5/32" ];
              };
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkParentRefs — unknown parent flagged =====

  testCheckParentRefsUnknown = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentRefs
        ]
        (
          emptyTable
          // {
            zones.web = {
              parent = "ghost";
              cidrs = [ "10.0.0.5/32" ];
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "zoneParentUnknown";
        value = "zones.web.parent references unknown zone 'ghost'";
      }
    ];
  };

  # ===== checkParentRefs — localZone as parent flagged =====

  testCheckParentRefsLocalZone = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentRefs
        ]
        (
          emptyTable
          // {
            zones.web = {
              parent = "local";
              cidrs = [ "10.0.0.5/32" ];
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "zoneParentLocalZone";
        value = "zones.web.parent is 'local' (the localZone sentinel) — localZone cannot be a parent";
      }
    ];
  };

  # ===== checkParentRefs — node lowering propagates parent for validation =====

  testCheckParentRefsNodeLowered = {
    # A node lowers to a zone with `parent = node.zone`. If
    # node.zone is unknown, validator flags it.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentRefs
        ]
        (
          emptyTable
          // {
            nodes.web = {
              name = "web";
              zone = "ghost";
              address = {
                ipv4 = "10.0.0.5";
                ipv6 = null;
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "zoneParentUnknown";
        value = "zones.web.parent references unknown zone 'ghost'";
      }
    ];
  };

  # ===== checkParentCycles — no cycle =====

  testCheckParentCyclesNone = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = { };
              b = {
                parent = "a";
              };
              c = {
                parent = "b";
              };
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkParentCycles — simple cycle flagged exactly once =====

  testCheckParentCyclesSimple = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = {
                parent = "b";
              };
              b = {
                parent = "a";
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "zoneParentCycle";
        value = "zone parent cycle: a → b → a";
      }
    ];
  };

  # ===== checkParentCycles — 3-cycle dedups across all rotations =====

  testCheckParentCyclesThreeNodeDedup = {
    # Cycle `a → c → b → a` (following parent pointers).
    # Walks starting from a, b, c each discover the same cycle
    # from different positions. Canonicalization (rotate to
    # lex-smallest) collapses them into one error.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = {
                parent = "c";
              };
              b = {
                parent = "a";
              };
              c = {
                parent = "b";
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "zoneParentCycle";
        value = "zone parent cycle: a → c → b → a";
      }
    ];
  };

  # ===== checkParentCycles — tail leading into cycle is stripped =====

  testCheckParentCyclesTailStripped = {
    # `d → a → b → c → a`: walk from d hits the cycle but `d`
    # itself isn't part of it. Output should be just the cycle
    # members, canonicalized.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = {
                parent = "b";
              };
              b = {
                parent = "c";
              };
              c = {
                parent = "a";
              };
              d = {
                parent = "a";
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "zoneParentCycle";
        value = "zone parent cycle: a → b → c → a";
      }
    ];
  };

  # ===== computeChildrenOf — empty parent set =====

  testComputeChildrenOfEmpty = {
    expr =
      (runPipeline [
        convertNodesToZones
        computeChildrenOf
      ] emptyTable).childrenOf;
    expected = { };
  };

  # ===== computeChildrenOf — inverse map of parent =====

  testComputeChildrenOfBasic = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeChildrenOf
        ]
        (
          emptyTable
          // {
            zones = {
              dmz = { };
              web = {
                parent = "dmz";
              };
              api = {
                parent = "dmz";
              };
              standalone = { };
            };
          }
        )
      ).childrenOf;
    # Children sorted alphabetically. `standalone` (no parent) is
    # not a key in childrenOf.
    expected = {
      dmz = [
        "api"
        "web"
      ];
    };
  };

  # ===== computeRootZoneNames — only localZone when no zones =====

  testComputeRootZoneNamesEmpty = {
    expr =
      (runPipeline [
        convertNodesToZones
        computeRootZoneNames
      ] emptyTable).rootZoneNames;
    expected = [ "local" ];
  };

  # ===== computeRootZoneNames — roots only + localZone =====

  testComputeRootZoneNamesBasic = {
    # `dmz` is a root (no parent); `web` (parent dmz) is not.
    # `localZone` always appears as a root.
    expr =
      let
        out =
          (runPipeline
            [
              convertNodesToZones
              computeRootZoneNames
            ]
            (
              emptyTable
              // {
                zones = {
                  dmz = { };
                  web = {
                    parent = "dmz";
                  };
                  wan = { };
                };
              }
            )
          ).rootZoneNames;
      in
      pkgs.lib.sort (a: b: a < b) out;
    expected = [
      "dmz"
      "local"
      "wan"
    ];
  };

  # ===== checkInterfaceOverlap — empty zones =====

  testCheckInterfaceOverlapEmpty = {
    expr =
      (runPipeline [
        convertNodesToZones
        checkInterfaceOverlap
      ] emptyTable).errors;
    expected = [ ];
  };

  # ===== checkInterfaceOverlap — disjoint interfaces =====

  testCheckInterfaceOverlapDisjoint = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkInterfaceOverlap
        ]
        {
          zones = {
            lan = {
              interfaces = [ "eth1" ];
            };
            wan = {
              interfaces = [ "eth0" ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkInterfaceOverlap — two unrelated zones share an interface =====

  testCheckInterfaceOverlapUnrelated = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkInterfaceOverlap
        ]
        {
          zones = {
            guest = {
              interfaces = [ "eth1" ];
            };
            lan = {
              interfaces = [ "eth1" ];
            };
          };
        }
      ).errors;
    expected = [
      {
        name = "interfaceOverlap";
        value = "interface 'eth1' is claimed by zones 'guest' and 'lan' (no ancestor/descendant relationship)";
      }
    ];
  };

  # ===== checkInterfaceOverlap — parent and child share an interface =====
  # Hierarchy is intentional overlap; not flagged.

  testCheckInterfaceOverlapHierarchyAllowed = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkInterfaceOverlap
        ]
        {
          zones = {
            lan = {
              interfaces = [ "eth1" ];
            };
            lan-guests = {
              parent = "lan";
              interfaces = [ "eth1" ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkInterfaceOverlap — same zone lists interface twice =====

  testCheckInterfaceOverlapIntraZone = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkInterfaceOverlap
        ]
        {
          zones.lan = {
            interfaces = [
              "eth1"
              "eth1"
            ];
          };
        }
      ).errors;
    expected = [
      {
        name = "interfaceOverlap";
        value = "zone 'lan' lists interface 'eth1' more than once";
      }
    ];
  };

  # ===== checkInterfaceOverlap — three unrelated zones, pair-wise errors =====

  testCheckInterfaceOverlapThreeWay = {
    expr =
      builtins.length
        (runEvalPipeline
          [
            convertNodesToZones
            checkInterfaceOverlap
          ]
          {
            zones = {
              a = {
                interfaces = [ "eth1" ];
              };
              b = {
                interfaces = [ "eth1" ];
              };
              c = {
                interfaces = [ "eth1" ];
              };
            };
          }
        ).errors;
    # Pair-wise: (a,b), (a,c), (b,c) → 3 errors.
    expected = 3;
  };

  # ===== checkCidrOverlap — empty zones =====

  testCheckCidrOverlapEmpty = {
    expr =
      (runPipeline [
        convertNodesToZones
        checkCidrOverlap
      ] emptyTable).errors;
    expected = [ ];
  };

  # ===== checkCidrOverlap — disjoint CIDRs =====

  testCheckCidrOverlapDisjoint = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones = {
            lan = {
              cidrs = [ "10.0.0.0/24" ];
            };
            guest = {
              cidrs = [ "192.168.1.0/24" ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkCidrOverlap — two unrelated zones with overlapping CIDRs =====

  testCheckCidrOverlapUnrelated = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones = {
            lan = {
              cidrs = [ "10.0.0.0/24" ];
            };
            mgmt = {
              cidrs = [ "10.0.0.0/28" ];
            };
          };
        }
      ).errors;
    expected = [
      {
        name = "cidrOverlap";
        value = "zone 'lan' CIDR '10.0.0.0/24' overlaps zone 'mgmt' CIDR '10.0.0.0/28' (no ancestor/descendant relationship)";
      }
    ];
  };

  # ===== checkCidrOverlap — parent /24 contains child /28 =====
  # Intentional hierarchical containment; not flagged.

  testCheckCidrOverlapHierarchyAllowed = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones = {
            dmz = {
              cidrs = [ "10.0.0.0/24" ];
            };
            web = {
              parent = "dmz";
              cidrs = [ "10.0.0.0/28" ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkCidrOverlap — siblings sharing a parent overlap =====

  testCheckCidrOverlapSiblings = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones = {
            dmz = {
              cidrs = [ "10.0.0.0/24" ];
            };
            a = {
              parent = "dmz";
              cidrs = [ "10.0.0.0/28" ];
            };
            b = {
              parent = "dmz";
              cidrs = [ "10.0.0.0/29" ];
            };
          };
        }
      ).errors;
    # Parent ⊇ each sibling (ancestor relation, skipped),
    # but a and b are siblings without ancestor relation → flagged.
    expected = [
      {
        name = "cidrOverlap";
        value = "zone 'a' CIDR '10.0.0.0/28' overlaps zone 'b' CIDR '10.0.0.0/29' (no ancestor/descendant relationship)";
      }
    ];
  };

  # ===== checkCidrOverlap — v4 vs v6 never overlap =====

  testCheckCidrOverlapMixedFamily = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones = {
            a = {
              cidrs = [ "10.0.0.0/24" ];
            };
            b = {
              cidrs = [ "fe80::/64" ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkCidrOverlap — intra-zone overlap =====

  testCheckCidrOverlapIntraZone = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones.lan = {
            cidrs = [
              "10.0.0.0/24"
              "10.0.0.0/28"
            ];
          };
        }
      ).errors;
    expected = [
      {
        name = "cidrOverlap";
        value = "zone 'lan' has overlapping CIDRs '10.0.0.0/24' and '10.0.0.0/28'";
      }
    ];
  };

  # ===== checkCidrOverlap — lowered node CIDR inside parent zone CIDR =====

  testCheckCidrOverlapNodeInsideParent = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCidrOverlap
        ]
        {
          zones.dmz = {
            cidrs = [ "10.0.0.0/24" ];
          };
          nodes.web-server = {
            zone = "dmz";
            address.ipv4 = "10.0.0.5";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverrideSemantics — no overrides, no warnings =====

  testCheckChainOverrideSemanticsDefaults = {
    expr =
      (runPhase checkChainOverrideSemantics (
        emptyTable
        // {
          family = "inet";
          filters.allow-ssh = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
            chain = null;
            priority = "default";
          };
          snats.masq = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
            chain = null;
            priority = "default";
          };
          dnats.fwd = {
            from = [ "wan" ];
            rule = {
              match = [ ];
              action.dnat = {
                addr = "10.0.0.5";
                port = 443;
              };
            };
            chain = null;
            priority = "default";
          };
        }
      )).warnings;
    expected = [ ];
  };

  # ===== checkChainOverrideSemantics — filter at postrouting warns =====

  testCheckChainOverrideSemanticsFilterPostrouting = {
    expr =
      let
        ws =
          (runPhase checkChainOverrideSemantics (
            emptyTable
            // {
              family = "inet";
              filters.late = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
                chain = {
                  hook = "postrouting";
                  priority = "srcnat";
                };
                priority = "default";
              };
            }
          )).warnings;
      in
      {
        count = lib.length ws;
        mentionsHook = lib.any (w: lib.hasInfix "hook=postrouting" w) ws;
        mentionsEntry = lib.any (w: lib.hasInfix "filters.late.chain" w) ws;
      };
    expected = {
      count = 1;
      mentionsHook = true;
      mentionsEntry = true;
    };
  };

  # ===== checkChainOverrideSemantics — dnat at output warns =====

  testCheckChainOverrideSemanticsDnatOutput = {
    expr =
      let
        ws =
          (runPhase checkChainOverrideSemantics (
            emptyTable
            // {
              family = "inet";
              dnats.local-rewrite = {
                from = [ "local" ];
                rule = {
                  match = [ ];
                  action.dnat = {
                    addr = "10.0.0.5";
                    port = 443;
                  };
                };
                chain = {
                  hook = "output";
                  priority = "dstnat";
                };
                priority = "default";
              };
            }
          )).warnings;
      in
      {
        count = lib.length ws;
        mentionsHook = lib.any (w: lib.hasInfix "hook=output" w) ws;
      };
    expected = {
      count = 1;
      mentionsHook = true;
    };
  };

  # ===== checkChainOverrideSemantics — snat at non-srcnat priority warns =====

  testCheckChainOverrideSemanticsSnatNonSrcnat = {
    expr =
      let
        ws =
          (runPhase checkChainOverrideSemantics (
            emptyTable
            // {
              family = "inet";
              snats.early = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule.masquerade = { };
                chain = {
                  hook = "postrouting";
                  priority = "mangle";
                };
                priority = "default";
              };
            }
          )).warnings;
      in
      {
        count = lib.length ws;
        mentionsPriority = lib.any (w: lib.hasInfix "mangle" w && lib.hasInfix "srcnat" w) ws;
      };
    expected = {
      count = 1;
      mentionsPriority = true;
    };
  };

  # ===== checkChainOverrideSemantics — snat at explicit srcnat passes =====

  testCheckChainOverrideSemanticsSnatExplicitSrcnat = {
    # Explicit override at the *correct* priority is fine. Same
    # for the int form (100 = srcnat).
    expr =
      (runPhase checkChainOverrideSemantics (
        emptyTable
        // {
          family = "inet";
          snats.s1 = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
            chain = {
              hook = "postrouting";
              priority = "srcnat";
            };
            priority = "default";
          };
          snats.s2 = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
            chain = {
              hook = "postrouting";
              priority = 100;
            };
            priority = "default";
          };
        }
      )).warnings;
    expected = [ ];
  };

  # ===== checkChainOverrideSemantics — multiple sub-cases aggregate =====

  testCheckChainOverrideSemanticsMultiple = {
    expr =
      lib.length
        (runPhase checkChainOverrideSemantics (
          emptyTable
          // {
            family = "inet";
            filters.f = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
              chain = {
                hook = "postrouting";
                priority = "srcnat";
              };
              priority = "default";
            };
            dnats.d = {
              from = [ "local" ];
              rule = {
                match = [ ];
                action.dnat = {
                  addr = "10.0.0.5";
                  port = 443;
                };
              };
              chain = {
                hook = "output";
                priority = "dstnat";
              };
              priority = "default";
            };
            snats.s = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule.masquerade = { };
              chain = {
                hook = "postrouting";
                priority = "filter";
              };
              priority = "default";
            };
          }
        )).warnings;
    expected = 3;
  };

  # ===== checkExtraSectionFields — extra without iif/oif produces no warnings =====

  testCheckExtraSectionFieldsClean = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkExtraSectionFields
        ]
        {
          zones.lan = {
            interfaces = [ "lan0" ];
            matchOverride.ingress.extra = [
              (dsl.eq dsl.fields.meta.mark 256)
              (dsl.eq dsl.fields.meta.cgroup 100)
            ];
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkExtraSectionFields — iif in extra fires =====

  testCheckExtraSectionFieldsIifWarns = {
    expr =
      let
        ws =
          (runEvalPipeline
            [
              convertNodesToZones
              checkExtraSectionFields
            ]
            {
              zones.lan.matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.iif "lo") ];
            }
          ).warnings;
      in
      {
        count = lib.length ws;
        path = lib.any (w: lib.hasInfix "zones.lan.matchOverride.ingress.extra[0]" w) ws;
        field = lib.any (w: lib.hasInfix "meta.iif" w) ws;
        recommendsInterfaces = lib.any (w: lib.hasInfix "matchOverride.ingress.interfaces" w) ws;
      };
    expected = {
      count = 1;
      path = true;
      field = true;
      recommendsInterfaces = true;
    };
  };

  # ===== checkExtraSectionFields — oifname in extra fires =====

  testCheckExtraSectionFieldsOifWarns = {
    expr =
      let
        ws =
          (runEvalPipeline
            [
              convertNodesToZones
              checkExtraSectionFields
            ]
            {
              zones.wan.matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.oifname "wan0") ];
            }
          ).warnings;
      in
      {
        count = lib.length ws;
        field = lib.any (w: lib.hasInfix "meta.oifname" w) ws;
      };
    expected = {
      count = 1;
      field = true;
    };
  };

  # ===== checkExtraSectionFields — both sides aggregate =====

  testCheckExtraSectionFieldsBothSidesAggregate = {
    expr =
      lib.length
        (runEvalPipeline
          [
            convertNodesToZones
            checkExtraSectionFields
          ]
          {
            zones.lan = {
              matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.iif "lan0") ];
              matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.oif "lan0") ];
            };
          }
        ).warnings;
    expected = 2;
  };

  # ===== checkExtraSectionFields — warnings aggregate across zones =====

  testCheckExtraSectionFieldsMultipleZones = {
    expr =
      let
        ws =
          (runEvalPipeline
            [
              convertNodesToZones
              checkExtraSectionFields
            ]
            {
              zones = {
                lan.matchOverride.ingress.extra = [
                  (dsl.eq dsl.fields.meta.iifname "lan0")
                ];
                wan.matchOverride.egress.extra = [
                  (dsl.eq dsl.fields.meta.oifname "wan0")
                ];
              };
            }
          ).warnings;
        paths = ws;
      in
      {
        count = lib.length ws;
        lan = lib.any (lib.hasInfix "zones.lan.matchOverride.ingress.extra") paths;
        wan = lib.any (lib.hasInfix "zones.wan.matchOverride.egress.extra") paths;
      };
    expected = {
      count = 2;
      lan = true;
      wan = true;
    };
  };

  # ===== checkExtraSectionFields — iif in INTERFACES section is not flagged =====

  testCheckExtraSectionFieldsInterfacesSectionNotFlagged = {
    # The whole point: the `interfaces` section is the *right*
    # place for iif/oif clauses. Hook-gating happens there, so
    # this validator should ignore them.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkExtraSectionFields
        ]
        {
          zones.lan.matchOverride.ingress.interfaces = [
            (dsl.eq dsl.fields.meta.iifname "lan0")
          ];
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkWildcardZoneMix — wildcard-only direction is fine =====

  testCheckWildcardZoneMixCleanWildcard = {
    expr =
      (runEvalPipeline [ checkWildcardZoneMix ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        policies.deny-all = {
          from = [ "all" ];
          to = [ "wan" ];
          verdict = "drop";
        };
      }).warnings;
    expected = [ ];
  };

  # ===== checkWildcardZoneMix — wildcard + explicit zone fires =====

  testCheckWildcardZoneMixFires = {
    expr =
      let
        ws =
          (runEvalPipeline [ checkWildcardZoneMix ] {
            zones.lan.interfaces = [ "lan0" ];
            zones.wan.interfaces = [ "wan0" ];
            policies.confused = {
              from = [
                "all"
                "wan"
              ];
              to = [ "lan" ];
              verdict = "drop";
            };
          }).warnings;
      in
      {
        count = lib.length ws;
        mentionsPath = lib.any (w: lib.hasInfix "policies.confused.from" w) ws;
        mentionsWildcard = lib.any (w: lib.hasInfix "'all'" w) ws;
        mentionsExplicit = lib.any (w: lib.hasInfix "'wan'" w) ws;
      };
    expected = {
      count = 1;
      mentionsPath = true;
      mentionsWildcard = true;
      mentionsExplicit = true;
    };
  };

  # ===== checkWildcardZoneMix — fires across multiple groups + directions =====

  testCheckWildcardZoneMixMultiple = {
    expr =
      lib.length
        (runEvalPipeline [ checkWildcardZoneMix ] {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.f = {
            from = [
              "all"
              "lan"
            ];
            to = [
              "all"
              "wan"
            ];
            rule = [ ];
          };
          dnats.d = {
            from = [
              "all"
              "wan"
            ];
            rule = {
              match = [ ];
              action.dnat = {
                addr = "10.0.0.5";
                port = 443;
              };
            };
          };
        }).warnings;
    # filters.f.from + filters.f.to + dnats.d.from = 3 warnings.
    expected = 3;
  };

  # ===== checkWildcardZoneMix — pure explicit list (no wildcard) is fine =====

  testCheckWildcardZoneMixExplicitOnly = {
    expr =
      (runEvalPipeline [ checkWildcardZoneMix ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        policies.allow = {
          from = [
            "lan"
            "wan"
          ];
          to = [ "wan" ];
          verdict = "accept";
        };
      }).warnings;
    expected = [ ];
  };

  # ===== checkCrossAxisOverlap — all iface-only zones, no warnings =====

  testCheckCrossAxisOverlapAllIfaces = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCrossAxisOverlap
        ]
        {
          zones = {
            lan.interfaces = [ "lan0" ];
            wan.interfaces = [ "wan0" ];
            dmz.interfaces = [ "dmz0" ];
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkCrossAxisOverlap — single iface×cidr pair flagged =====

  testCheckCrossAxisOverlapPairFlagged = {
    # `lan-iface` matches by iif `lan0`; `lan-cidr` matches by saddr
    # 10.0.0.0/24. A packet from 10.0.0.5 on lan0 matches both,
    # dispatch order is alphabetical — silent shadowing.
    expr =
      let
        ws =
          (runEvalPipeline
            [
              convertNodesToZones
              checkCrossAxisOverlap
            ]
            {
              zones = {
                lan-iface.interfaces = [ "lan0" ];
                lan-cidr.cidrs = [ "10.0.0.0/24" ];
              };
            }
          ).warnings;
      in
      {
        count = lib.length ws;
        mentionsBothZones = lib.any (w: lib.hasInfix "lan-iface" w && lib.hasInfix "lan-cidr" w) ws;
      };
    expected = {
      count = 1;
      mentionsBothZones = true;
    };
  };

  # ===== checkCrossAxisOverlap — ancestor/descendant pair skipped =====

  testCheckCrossAxisOverlapHierarchySkipped = {
    # Parent iface-zone + child cidr-zone is the canonical refinement
    # case (node lowered into its parent zone). Overlap is intentional
    # — child traffic dispatches through parent's chain first.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCrossAxisOverlap
        ]
        {
          zones = {
            lan.interfaces = [ "lan0" ];
            web = {
              parent = "lan";
              cidrs = [ "10.0.0.5/32" ];
            };
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkCrossAxisOverlap — parented child vs unrelated zone skipped =====

  testCheckCrossAxisOverlapParentedChildUnrelatedSkipped = {
    # A child is reached only after its parent's interface gate matched,
    # making `web` effectively interface-and-CIDR bound. It must not be
    # compared as a CIDR-only peer of the unrelated `vpn` root zone.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCrossAxisOverlap
        ]
        {
          zones = {
            lan = {
              interfaces = [ "lan0" ];
              cidrs = [ ];
            };
            vpn = {
              interfaces = [ "vpn0" ];
              cidrs = [ ];
            };
            web = {
              parent = "lan";
              interfaces = [ ];
              cidrs = [ "10.0.0.5/32" ];
            };
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkCrossAxisOverlap — lowered node vs unrelated zone skipped =====

  testCheckCrossAxisOverlapLoweredNodeUnrelatedSkipped = {
    # Pin the public `nodes` shape: `convertNodesToZones` lowers `web`
    # to a CIDR-only child of `lan`, whose effective dispatch path is
    # still interface-and-CIDR bound.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCrossAxisOverlap
        ]
        {
          zones = {
            lan = {
              interfaces = [ "lan0" ];
              cidrs = [ ];
            };
            vpn = {
              interfaces = [ "vpn0" ];
              cidrs = [ ];
            };
          };
          nodes.web = {
            name = "web";
            zone = "lan";
            address.ipv4 = "10.0.0.5";
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkCrossAxisOverlap — grandchild inherits transitive axes =====

  testCheckCrossAxisOverlapGrandchildUnrelatedSkipped = {
    # `web` inherits the interface axis through the otherwise-empty `apps`
    # grouping zone, proving that effective-axis classification walks every
    # strict ancestor rather than only the immediate parent.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCrossAxisOverlap
        ]
        {
          zones = {
            lan = {
              interfaces = [ "lan0" ];
              cidrs = [ ];
            };
            vpn = {
              interfaces = [ "vpn0" ];
              cidrs = [ ];
            };
            apps = {
              parent = "lan";
              interfaces = [ ];
              cidrs = [ ];
            };
            web = {
              parent = "apps";
              interfaces = [ ];
              cidrs = [ "10.0.0.5/32" ];
            };
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkCrossAxisOverlap — empty grouping zone stays unclassified =====

  testCheckCrossAxisOverlapEmptyGroupingZoneSkipped = {
    # `apps` contributes no own match axis. Although its parent is
    # interface-bound, classifying the empty intermediate itself would
    # duplicate `lan`'s genuine warning against the unrelated CIDR root.
    expr =
      let
        ws =
          (runEvalPipeline
            [
              convertNodesToZones
              checkCrossAxisOverlap
            ]
            {
              zones = {
                lan = {
                  interfaces = [ "lan0" ];
                  cidrs = [ ];
                };
                apps = {
                  parent = "lan";
                  interfaces = [ ];
                  cidrs = [ ];
                };
                raw-cidr = {
                  interfaces = [ ];
                  cidrs = [ "192.168.0.0/24" ];
                };
                web = {
                  parent = "apps";
                  interfaces = [ ];
                  cidrs = [ "10.0.0.5/32" ];
                };
              };
            }
          ).warnings;
      in
      {
        count = lib.length ws;
        flagsRoots = lib.any (w: lib.hasInfix "lan" w && lib.hasInfix "raw-cidr" w) ws;
        flagsGroupingZone = lib.any (w: lib.hasInfix "apps" w) ws;
      };
    expected = {
      count = 1;
      flagsRoots = true;
      flagsGroupingZone = false;
    };
  };

  # ===== checkCrossAxisOverlap — multiple distinct pairs each flagged =====

  testCheckCrossAxisOverlapMultiplePairs = {
    expr =
      let
        ws =
          (runEvalPipeline
            [
              convertNodesToZones
              checkCrossAxisOverlap
            ]
            {
              zones = {
                a-iface.interfaces = [ "a0" ];
                b-iface.interfaces = [ "b0" ];
                c-cidr.cidrs = [ "10.0.0.0/24" ];
                d-cidr.cidrs = [ "10.1.0.0/24" ];
              };
            }
          ).warnings;
      in
      lib.length ws;
    # a-iface × {c-cidr, d-cidr} = 2; b-iface × {c-cidr, d-cidr} = 2.
    # iface↔iface (a×b) handled by checkInterfaceOverlap; cidr↔cidr
    # (c×d) handled by checkCidrOverlap. Total cross-axis: 4.
    expected = 4;
  };

  # ===== checkCrossAxisOverlap — multi-axis zone is NOT flagged =====

  testCheckCrossAxisOverlapMultiAxisZoneSkipped = {
    # `multi` has BOTH interfaces and cidrs — the typical real-world
    # "this zone is eth0 plus 10.0.0.0/24" pattern, not the audit's
    # accidentally-split-zone case. `iface-only` has only interfaces.
    # The check intentionally skips multi-axis zones to keep the
    # false-positive rate manageable.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          checkCrossAxisOverlap
        ]
        {
          zones = {
            multi = {
              interfaces = [ "multi0" ];
              cidrs = [ "10.0.0.0/24" ];
            };
            iface-only.interfaces = [ "iface0" ];
          };
        }
      ).warnings;
    expected = [ ];
  };

}
