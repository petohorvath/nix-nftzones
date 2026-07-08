/*
  Unit tests for `lib/internal/zone.nix` (exposed as
  `nftzones.internal.zone.genSets`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftypes.dsl) expr;
  inherit (nftzones.internal.zone) genSets getActiveMatchOverrides ownSectionsOf;

  /*
    Convenience for the single-zone (no descendants) case.
    `genSets` now takes the full `(mergedZones, childrenOf, name)`
    triple so it can walk descendants transitively, but most tests
    just want to inspect what one zone emits in isolation. Wrap
    the zone in a one-entry mergedZones and pass an empty
    childrenOf.
  */
  genFor =
    name: zone:
    genSets {
      ${name} = zone;
    } { } name;

  cidrV4 = "10.0.0.0/24";
  cidrV6 = "2001:db8::/32";
  ifs = [
    "eth1"
    "eth2"
  ];

  mockZoneOverride = sections: {
    matchOverride = {
      ingress = sections;
      egress = { };
    };
  };
in
{
  # ===== genSets — empty zone produces no sets =====

  testGenSetsEmpty = {
    expr = genFor "lan" {
      interfaces = [ ];
      cidrs = [ ];
    };
    expected = { };
  };

  # ===== genSets — interface-only zone gets `_iifs` only =====

  testGenSetsIfsOnly = {
    expr = genFor "lan" {
      interfaces = [ "lan0" ];
      cidrs = [ ];
    };
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = [ "lan0" ];
      };
    };
  };

  # ===== genSets — v4-only CIDR zone gets `_v4` only =====

  testGenSetsV4Only = {
    expr = genFor "lan" {
      interfaces = [ ];
      cidrs = [ cidrV4 ];
    };
    expected = {
      lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "10.0.0.0" 24) ];
      };
    };
  };

  # ===== genSets — v6-only CIDR zone gets `_v6` only =====

  testGenSetsV6Only = {
    expr = genFor "lan" {
      interfaces = [ ];
      cidrs = [ cidrV6 ];
    };
    expected = {
      lan_v6 = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "2001:db8::" 32) ];
      };
    };
  };

  # ===== genSets — multiple CIDRs of the same family preserve order =====

  testGenSetsMultipleSameFamily = {
    expr =
      (genFor "lan" {
        interfaces = [ ];
        cidrs = [
          "10.0.0.0/24"
          "192.168.0.0/16"
        ];
      }).lan_v4.elements;
    expected = [
      (expr.prefix "10.0.0.0" 24)
      (expr.prefix "192.168.0.0" 16)
    ];
  };

  # ===== genSets — full dual-stack zone gets all three suffixes (full bodies) =====

  testGenSetsAll = {
    expr = genFor "lan" {
      interfaces = ifs;
      cidrs = [
        cidrV4
        cidrV6
      ];
    };
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = ifs;
      };
      lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "10.0.0.0" 24) ];
      };
      lan_v6 = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "2001:db8::" 32) ];
      };
    };
  };

  # ===== genSets — set names always carry the zone-name prefix =====

  testGenSetsNamePrefix = {
    expr = pkgs.lib.attrNames (
      genFor "guest" {
        interfaces = [ "guest0" ];
        cidrs = [ cidrV4 ];
      }
    );
    expected = [
      "guest_iifs"
      "guest_v4"
    ];
  };

  # ===== genSets — parent zone's _iifs includes child interfaces transitively =====

  testGenSetsParentIncludesChildIfaces = {
    # Models the canonical hierarchy: `lan` (lan0) + `lan-guest`
    # (parent = lan, guest0). The parent's `_iifs` should
    # transitively include guest0 so base-chain dispatch into
    # `lan`'s sub-chain catches guest traffic; the child-dispatch
    # jump inside lan's sub-chain then routes specifically to
    # lan-guest's sub-chain.
    expr =
      genSets
        {
          lan = {
            interfaces = [ "lan0" ];
            cidrs = [ ];
          };
          lan-guest = {
            interfaces = [ "guest0" ];
            cidrs = [ ];
          };
        }
        {
          lan = [ "lan-guest" ];
        }
        "lan";
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = [
          "lan0"
          "guest0"
        ];
      };
    };
  };

  # ===== genSets — descendant's own set covers only itself =====

  testGenSetsChildOwnsItself = {
    # `lan-guest` (no further descendants) emits a set with just
    # its own interfaces. Confirms the transitive walk is rooted
    # at the named zone, not at all roots.
    expr =
      genSets
        {
          lan = {
            interfaces = [ "lan0" ];
            cidrs = [ ];
          };
          lan-guest = {
            interfaces = [ "guest0" ];
            cidrs = [ ];
          };
        }
        {
          lan = [ "lan-guest" ];
        }
        "lan-guest";
    expected = {
      lan-guest_iifs = {
        type = "ifname";
        elements = [ "guest0" ];
      };
    };
  };

  # ===== genSets — multi-level hierarchy walks transitively =====

  testGenSetsMultiLevelHierarchy = {
    # Three-level chain: lan ← lan-trusted ← lan-trusted-admin.
    # `lan`'s set should include all three interfaces;
    # `lan-trusted`'s set should include its own + admin's.
    expr =
      let
        mergedZones = {
          lan = {
            interfaces = [ "lan0" ];
            cidrs = [ ];
          };
          lan-trusted = {
            interfaces = [ "trust0" ];
            cidrs = [ ];
          };
          lan-trusted-admin = {
            interfaces = [ "admin0" ];
            cidrs = [ ];
          };
        };
        childrenOf = {
          lan = [ "lan-trusted" ];
          lan-trusted = [ "lan-trusted-admin" ];
        };
      in
      {
        lan = (genSets mergedZones childrenOf "lan").lan_iifs.elements;
        trusted = (genSets mergedZones childrenOf "lan-trusted").lan-trusted_iifs.elements;
        admin = (genSets mergedZones childrenOf "lan-trusted-admin").lan-trusted-admin_iifs.elements;
      };
    expected = {
      lan = [
        "lan0"
        "trust0"
        "admin0"
      ];
      trusted = [
        "trust0"
        "admin0"
      ];
      admin = [ "admin0" ];
    };
  };

  # ===== genSets — parent with no own interfaces still emits set from descendants =====

  testGenSetsParentWithNoOwnIfaces = {
    # Common pattern: a "group" zone with no interfaces of its
    # own, used only to attach shared rules to its children. The
    # group's `_iifs` should still be emitted (so the group's
    # sub-chain has a base-chain jump that catches descendant
    # traffic) — sourced entirely from descendants.
    expr =
      genSets
        {
          internal = {
            interfaces = [ ];
            cidrs = [ ];
          };
          int-trusted = {
            interfaces = [ "trust0" ];
            cidrs = [ ];
          };
          int-guest = {
            interfaces = [ "guest0" ];
            cidrs = [ ];
          };
        }
        {
          internal = [
            "int-trusted"
            "int-guest"
          ];
        }
        "internal";
    expected = {
      internal_iifs = {
        type = "ifname";
        elements = [
          "trust0"
          "guest0"
        ];
      };
    };
  };

  # ===== genSets — exact-duplicate CIDRs deduped =====

  testGenSetsCidrDedup = {
    # Parent and child both write `10.0.0.0/24` (silly but legal —
    # `checkCidrOverlap` skips ancestor/descendant pairs).
    # `libnet.cidr.summarize` collapses the duplicate at compile
    # time so the rendered set carries one element, not two.
    expr =
      (genSets
        {
          parent = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
          child = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
        }
        {
          parent = [ "child" ];
        }
        "parent"
      ).parent_v4.elements;
    expected = [ (expr.prefix "10.0.0.0" 24) ];
  };

  # ===== genSets — descendant CIDR contained in ancestor's drops out =====

  testGenSetsCidrSubsetCoalesced = {
    # Parent has the broader prefix; child has a CIDR strictly
    # inside it. `summarize`'s `containsCidr` check drops the
    # child's redundant element, leaving just the parent's CIDR
    # in the rendered set — `10.0.0.0/8` covers all of
    # `10.0.0.0/24` so the latter adds no addresses.
    expr =
      (genSets
        {
          big = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/8" ];
          };
          small = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
        }
        {
          big = [ "small" ];
        }
        "big"
      ).big_v4.elements;
    expected = [ (expr.prefix "10.0.0.0" 8) ];
  };

  # ===== genSets — sibling CIDRs fuse into a single supernet =====

  testGenSetsCidrSiblingsFuse = {
    # Two adjacent canonical `/24`s (`10.0.0.0/24` + `10.0.1.0/24`)
    # are siblings of `10.0.0.0/23` and summarize collapses them
    # into that supernet. Edge case worth pinning: the rendered
    # ruleset diverges from user input — this is intentional and
    # semantically equivalent.
    expr =
      (genSets {
        parent = {
          interfaces = [ ];
          cidrs = [
            "10.0.0.0/24"
            "10.0.1.0/24"
          ];
        };
      } { } "parent").parent_v4.elements;
    expected = [ (expr.prefix "10.0.0.0" 23) ];
  };

  # ===== genSets — descendant with no contributions adds nothing =====

  testGenSetsEmptyDescendantContributesNothing = {
    # A parent with one interface and a descendant zone that has
    # no interfaces / CIDRs of its own. The parent's set should be
    # unchanged from the no-descendants case.
    expr =
      genSets
        {
          parent = {
            interfaces = [ "p0" ];
            cidrs = [ ];
          };
          child = {
            interfaces = [ ];
            cidrs = [ ];
          };
        }
        {
          parent = [ "child" ];
        }
        "parent";
    expected = {
      parent_iifs = {
        type = "ifname";
        elements = [ "p0" ];
      };
    };
  };

  # ===== genSets — cycle in childrenOf doesn't stack-overflow =====

  testGenSetsCycleGuard = {
    # `computeZoneSets` runs before `checkParentCycles` in the
    # validator pipeline, so a cyclic `childrenOf` would otherwise
    # exhaust Nix's max-call-depth before the dedicated cycle
    # check reports the error. The `descendantsOf` walker's
    # `visited` guard short-circuits the revisit; the eventual
    # `checkParentCycles` then reports a clean error. This test
    # pins the defense.
    expr =
      let
        ws =
          genSets
            {
              a = {
                interfaces = [ "a0" ];
                cidrs = [ ];
              };
              b = {
                interfaces = [ "b0" ];
                cidrs = [ ];
              };
            }
            {
              a = [ "b" ];
              b = [ "a" ];
            }
            "a";
      in
      ws.a_iifs.elements;
    # Order is parent-first, then descendants discovered during
    # the walk. The cycle is short-circuited before revisit.
    expected = [
      "a0"
      "b0"
    ];
  };

  # ===== genSets — descendant CIDRs union with parent CIDRs via summarize =====

  testGenSetsParentIncludesChildCidrs = {
    # Parent with CIDR `10.0.0.0/24` and a lowered-node child
    # contributing `10.0.0.5/32` (a typical node-in-zone case).
    # The child's `/32` is contained in the parent's `/24`, so
    # `summarize` drops it from the parent's `_v4` set — the
    # rendered set is the minimal cover.
    expr =
      genSets
        {
          dmz = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
          web = {
            interfaces = [ ];
            cidrs = [ "10.0.0.5/32" ];
          };
        }
        {
          dmz = [ "web" ];
        }
        "dmz";
    expected = {
      dmz_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "10.0.0.0" 24) ];
      };
    };
  };

  # ===== getActiveMatchOverrides — empty side produces empty active set =====

  testGetActiveMatchOverridesEmpty = {
    expr = getActiveMatchOverrides (mockZoneOverride { }) "ingress";
    expected = { };
  };

  # ===== getActiveMatchOverrides — null sections filtered out =====

  testGetActiveMatchOverridesNullsFiltered = {
    # All-null sections (the type's default) → empty active set.
    expr = getActiveMatchOverrides (mockZoneOverride {
      interfaces = null;
      ipv4 = null;
      ipv6 = null;
      extra = null;
    }) "ingress";
    expected = { };
  };

  # ===== getActiveMatchOverrides — empty list sections filtered out =====

  testGetActiveMatchOverridesEmptyListsFiltered = {
    # `[ ]` is treated the same as `null` — both mean "no
    # constraint contributed".
    expr = getActiveMatchOverrides (mockZoneOverride {
      ipv4 = [ ];
      extra = [ ];
    }) "ingress";
    expected = { };
  };

  # ===== getActiveMatchOverrides — mixed: some sections active, others null =====

  testGetActiveMatchOverridesMixed = {
    expr = getActiveMatchOverrides (mockZoneOverride {
      interfaces = null;
      ipv4 = [ "v4-clause" ];
      ipv6 = [ ];
      extra = [ "extra-clause" ];
    }) "ingress";
    expected = {
      ipv4 = [ "v4-clause" ];
      extra = [ "extra-clause" ];
    };
  };

  # ===== getActiveMatchOverrides — side parameter selects the right side =====

  testGetActiveMatchOverridesSideSelection = {
    # Construct a zone where ingress and egress have different
    # active sections; verify each side is read independently.
    expr =
      let
        zone = {
          matchOverride = {
            ingress = {
              ipv4 = [ "ing-v4" ];
            };
            egress = {
              extra = [ "egr-extra" ];
            };
          };
        };
      in
      {
        ing = getActiveMatchOverrides zone "ingress";
        egr = getActiveMatchOverrides zone "egress";
      };
    expected = {
      ing = {
        ipv4 = [ "ing-v4" ];
      };
      egr = {
        extra = [ "egr-extra" ];
      };
    };
  };

  # ===== ownSectionsOf — raw fields drive the classification =====

  testOwnSectionsOfDualStack = {
    expr = ownSectionsOf {
      interfaces = [ "lan0" ];
      cidrs = [
        cidrV4
        cidrV6
      ];
    };
    expected = {
      interfaces = true;
      v4 = true;
      v6 = true;
    };
  };

  testOwnSectionsOfIfsOnly = {
    expr = ownSectionsOf {
      interfaces = [ "lan0" ];
      cidrs = [ ];
    };
    expected = {
      interfaces = true;
      v4 = false;
      v6 = false;
    };
  };

  testOwnSectionsOfV6Only = {
    expr = ownSectionsOf {
      interfaces = [ ];
      cidrs = [ cidrV6 ];
    };
    expected = {
      interfaces = false;
      v4 = false;
      v6 = true;
    };
  };

  # ===== ownSectionsOf — missing raw fields classify as contributing nothing =====

  testOwnSectionsOfMissingFields = {
    # Raw fixtures that bypass the type system may omit the
    # fields entirely; `or [ ]` reads make that equivalent to
    # explicit emptiness.
    expr = ownSectionsOf { };
    expected = {
      interfaces = false;
      v4 = false;
      v6 = false;
    };
  };
}
