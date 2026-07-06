/*
  Unit tests for the NixOS module (`modules/nftzones.nix`, exposed
  as `nixosModules.default`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by
  `tests/unit/default.nix`.

  Pure module evaluations — no VM boot. We use `pkgs.nixos` (the
  nixpkgs-provided NixOS evaluator) with the flake's
  `nftzonesModule` plus a minimal-but-valid context (loader /
  filesystems / stateVersion stubs), then read back the resulting
  `config` for assertions. Going through `nftzonesModule` instead
  of importing the module file directly means tests exercise the
  same wiring production consumers see.

  VM tests live elsewhere — `tests/vm/firewall.nix` boots a
  real router under nixosTest and asserts traffic-level behaviour.
*/
{
  pkgs,
  nftzonesModule,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (pkgs) lib;

  minimalContext = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "none";
      fsType = "tmpfs";
    };
    # Derive from the pinned nixpkgs so the test doesn't need a
    # manual bump every NixOS release. Always matches the version
    # of NixOS we're evaluating against.
    system.stateVersion = lib.trivial.release;
    networking.hostName = "test";
  };

  /*
    Build a minimal NixOS system with the nftzones module imported
    and the test-specific config layered on. Returns the evaluated
    `config`.
  */
  evalSystem =
    extraConfig:
    (pkgs.nixos [
      nftzonesModule
      minimalContext
      extraConfig
    ]).config;

  /*
    Convenience for the common shape: nftables enabled,
    nftzones module enabled, with the supplied `tables`.
  */
  evalEnabled =
    tables:
    evalSystem {
      networking.nftables.enable = true;
      networking.nftzones = {
        enable = true;
        inherit tables;
      };
    };

  /*
    Returns the names of any failing assertions for the supplied
    config — bypasses the expensive `system.build.toplevel`
    derivation that NixOS normally uses to surface assertion
    failures. Each test asserts on the count or the message
    content directly.
  */
  failingAssertions = config: lib.filter (a: !a.assertion) config.assertions;
in
{
  # ===== module — disabled produces no nftzones-managed table =====

  testModuleDisabled = {
    # NixOS may inject default tables (e.g. `nixos-fw`); only check
    # the key we declared isn't present.
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = false;
          networking.nftzones.tables.fw = { };
        };
      in
      cfg.networking.nftables.tables ? fw;
    expected = false;
  };

  # ===== module — enabled with empty tables fails the empty-tables assertion =====

  testModuleEnabledEmptyTablesAssertion = {
    # `enable = true` + `tables = { }` previously compiled silently to
    # an empty ruleset — combined with `networking.firewall.enable =
    # false` (the typical nftzones-managed host setup), that's a
    # firewall-less host. The assertion makes the misconfig loud.
    expr =
      let
        failing = failingAssertions (evalSystem {
          networking.nftables.enable = true;
          networking.nftzones.enable = true;
        });
      in
      {
        count = lib.length failing;
        mentionsEmpty = lib.any (a: lib.hasInfix "tables is empty" a.message) failing;
      };
    expected = {
      count = 1;
      mentionsEmpty = true;
    };
  };

  # ===== module — disabled with empty tables passes (assertion is mkIf-gated) =====

  testModuleDisabledEmptyTablesNoAssertion = {
    expr = failingAssertions (evalSystem {
      networking.nftables.enable = false;
      networking.nftzones.enable = false;
    });
    expected = [ ];
  };

  # ===== module — warns when nftzones coexists with networking.firewall =====

  testModuleWarnsOnFirewallCoexistence = {
    # Both `networking.firewall.enable` and `networking.nftzones.enable`
    # true causes two `inet filter` base chains to fire at the same
    # priority — effective policy is union-of-accepts. Warning surfaces
    # the conflict.
    expr =
      let
        ws =
          (evalSystem {
            networking.nftables.enable = true;
            networking.firewall.enable = true;
            networking.nftzones = {
              enable = true;
              tables.fw.zones.lan.interfaces = [ "lan0" ];
            };
          }).warnings;
      in
      {
        count = lib.length (lib.filter (w: lib.hasInfix "networking.nftzones" w) ws);
        mentionsFirewall = lib.any (w: lib.hasInfix "networking.firewall.enable" w) ws;
      };
    expected = {
      count = 1;
      mentionsFirewall = true;
    };
  };

  # ===== module — no firewall-coexistence warning when firewall disabled =====

  testModuleNoFirewallCoexistenceWarn = {
    # nixpkgs defaults `networking.firewall.enable` to true, so the
    # test must explicitly disable it to verify the warning DOESN'T
    # fire when firewall is off.
    expr =
      lib.filter (w: lib.hasInfix "networking.nftzones" w)
        (evalSystem {
          networking.nftables.enable = true;
          networking.firewall.enable = false;
          networking.nftzones = {
            enable = true;
            tables.fw.zones.lan.interfaces = [ "lan0" ];
          };
        }).warnings;
    expected = [ ];
  };

  # ===== module — single table compiles to block-form content =====

  testModuleSingleTable = {
    expr =
      let
        table =
          (evalEnabled {
            fw.zones.lan.interfaces = [ "lan0" ];
          }).networking.nftables.tables.fw;
      in
      {
        family = table.family;
        hasLanIifs = lib.hasInfix "set lan_iifs" table.content;
        hasLan0 = lib.hasInfix "lan0" table.content;
      };
    expected = {
      family = "inet";
      hasLanIifs = true;
      hasLan0 = true;
    };
  };

  # ===== module — pretty mode flips renderer to multi-line =====

  testModulePrettyMode = {
    # The pretty flag only controls which nftypes renderer is
    # applied — `mkDirectionVariants` and the rest of the compile
    # pipeline produce the same output. So we don't need to spin
    # up two NixOS evaluations: render the once-compiled table
    # both ways and compare.
    expr =
      let
        body = {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.allow-ssh = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
          };
        };
        table = nftzones.mkTable "fw" body;
        compact = nftypes.toTextBlock table;
        pretty = nftypes.toTextBlockPretty table;
      in
      {
        prettyHasMoreLines =
          lib.length (lib.splitString "\n" pretty) > lib.length (lib.splitString "\n" compact);
      };
    expected = {
      prettyHasMoreLines = true;
    };
  };

  # ===== module — pretty option is actually wired through to content =====
  # The bypass-evaluation test above proves the renderers behave
  # differently. This one proves the module's `pretty` option
  # actually selects between them — same body, two real
  # evaluations, content must differ.

  testModulePrettyWiring = {
    expr =
      let
        body.fw = {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.allow-ssh = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
          };
        };
        compact =
          (evalSystem {
            networking.nftables.enable = true;
            networking.nftzones = {
              enable = true;
              pretty = false;
              tables = body;
            };
          }).networking.nftables.tables.fw.content;
        pretty =
          (evalSystem {
            networking.nftables.enable = true;
            networking.nftzones = {
              enable = true;
              pretty = true;
              tables = body;
            };
          }).networking.nftables.tables.fw.content;
      in
      {
        differ = compact != pretty;
        prettyLonger = lib.length (lib.splitString "\n" pretty) > lib.length (lib.splitString "\n" compact);
      };
    expected = {
      differ = true;
      prettyLonger = true;
    };
  };

  # ===== module — multi-table produces an entry per name =====

  testModuleMultipleTables = {
    expr =
      let
        ours =
          (evalEnabled {
            fw-v4 = {
              family = "ip";
              zones.lan.interfaces = [ "lan0" ];
            };
            fw-v6 = {
              family = "ip6";
              zones.lan.interfaces = [ "lan0" ];
            };
          }).networking.nftables.tables;
      in
      {
        hasV4 = ours ? fw-v4;
        hasV6 = ours ? fw-v6;
        v4Family = ours.fw-v4.family;
        v6Family = ours.fw-v6.family;
      };
    expected = {
      hasV4 = true;
      hasV6 = true;
      v4Family = "ip";
      v6Family = "ip6";
    };
  };

  # ===== module — a facade `table` option forwards cleanly into tables.<key> =====
  # Reproduction from the `name`-projection fix: a standalone option
  # of type `nftzones.types.table` (whose `name` defaults to the
  # option path `myfw`) forwarded into `networking.nftzones.tables.fw`
  # under a *different* key. Pre-fix this threw — the table's `name`
  # `apply` compared the facade option path against the tables key
  # ('myfw' != 'fw'). Post-fix the module projects the on-wire name
  # from the real attr key, so the whole evaluated table compiles
  # under `fw` without copying it field-by-field.

  testModuleFacadeForward = {
    expr =
      let
        cfg = evalSystem (
          { config, ... }:
          {
            options.myfw = lib.mkOption {
              type = nftzones.types.table;
              default = { };
            };
            config = {
              networking.nftables.enable = true;
              networking.firewall.enable = false;
              myfw.zones.lan.interfaces = [ "lan0" ];
              myfw.filters.web = {
                from = [ "lan" ];
                to = [ "local" ];
                rule = [ ];
              };
              networking.nftzones = {
                enable = true;
                tables.fw = config.myfw;
              };
            };
          }
        );
        # Forcing the content surfaces any boundary / Phase-1 throw —
        # this is exactly what threw on the pre-fix code.
        content = cfg.networking.nftables.tables.fw.content;
      in
      {
        noFailingAssertions = (failingAssertions cfg) == [ ];
        compiles = builtins.isString content && content != "";
        hasLanIifs = lib.hasInfix "set lan_iifs" content;
        # The `tables` option's `apply` projects the forwarded value's
        # `name` ('myfw') onto its attr key, so every reader — not just
        # the compiled ruleset — sees the key.
        optionNameProjected = cfg.networking.nftzones.tables.fw.name;
      };
    expected = {
      noFailingAssertions = true;
      compiles = true;
      hasLanIifs = true;
      optionNameProjected = "fw";
    };
  };

  # ===== module — hand-written nftables.tables.<other> coexists =====

  testModuleHandWrittenCoexists = {
    # Users mixing zone-managed and hand-written tables under
    # different names should hit no assertion. The collision check
    # only fires on same-name conflicts (see the next test); raw
    # tables under any other key flow through nixpkgs' own
    # `networking.nftables.tables` machinery untouched.
    expr =
      let
        cfg = evalSystem {
          networking.nftables = {
            enable = true;
            tables.legacy-raw = {
              family = "inet";
              content = "# manual content";
            };
          };
          networking.nftzones = {
            enable = true;
            tables.zonefw.zones.lan.interfaces = [ "lan0" ];
          };
        };
      in
      {
        noFailingAssertions = (failingAssertions cfg) == [ ];
        hasZonefw = cfg.networking.nftables.tables ? zonefw;
        hasLegacyRaw = cfg.networking.nftables.tables ? legacy-raw;
        legacyContent = cfg.networking.nftables.tables.legacy-raw.content;
      };
    expected = {
      noFailingAssertions = true;
      hasZonefw = true;
      hasLegacyRaw = true;
      legacyContent = "# manual content";
    };
  };

  # ===== module — collision with networking.nftables.tables.<n> trips assertion =====

  testModuleCollisionAssertion = {
    # Pin the exact assertion message, not just an "infix" match —
    # an `hasInfix "collides with"` test passes as long as the
    # substring appears anywhere, so a rephrasing that dropped the
    # specific `tables.fw` reference (or the "exactly one module"
    # remediation hint) would silently regress the user-facing
    # diagnostic.
    expr =
      let
        cfg = evalSystem {
          networking.nftables = {
            enable = true;
            tables.fw = {
              family = "inet";
              content = "# manual content";
            };
          };
          networking.nftzones = {
            enable = true;
            tables.fw = { };
          };
        };
        expectedMessage = ''
          networking.nftzones.tables.fw collides with networking.nftables.tables.fw.
          Declare each table in exactly one module.
        '';
      in
      lib.any (a: a.message == expectedMessage) (failingAssertions cfg);
    expected = true;
  };

  # ===== module — requires networking.nftables.enable =====

  testModuleRequiresNftablesEnabled = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = false;
          networking.nftzones = {
            enable = true;
            tables.fw = { };
          };
        };
      in
      lib.any (a: lib.hasInfix "requires networking.nftables.enable" a.message) (failingAssertions cfg);
    expected = true;
  };

  # ===== module — table-level `flags` rendered as block prefix =====
  # `nftypes.toTextBlock` drops the `add table` self-command (the
  # nixpkgs wrapper supplies `table <fam> <name> { ... }`), so the
  # module prepends `flags` / `comment` to the block content
  # itself. Verifies the prefix actually lands in the rendered
  # text.

  testModuleRendersTableFlags = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              flags = [ "owner" ];
              zones.lan.interfaces = [ "lan0" ];
            };
          };
        };
      in
      lib.hasInfix "flags owner;" cfg.networking.nftables.tables.fw.content;
    expected = true;
  };

  testModuleRendersTableFlagsMulti = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              flags = [
                "dormant"
                "owner"
              ];
              zones.lan.interfaces = [ "lan0" ];
            };
          };
        };
      in
      lib.hasInfix "flags dormant, owner;" cfg.networking.nftables.tables.fw.content;
    expected = true;
  };

  testModuleRendersTableComment = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              comment = "main firewall";
              zones.lan.interfaces = [ "lan0" ];
            };
          };
        };
      in
      lib.hasInfix ''comment "main firewall";'' cfg.networking.nftables.tables.fw.content;
    expected = true;
  };

  # ===== module — Phase 1 validator throws surface at module eval =====
  # Pins that the module path doesn't swallow Phase 1 throws.
  # Integration rejections prove `mkRuleset` itself throws on
  # bad bodies; this proves the throw still bubbles out when
  # the body is reached via the NixOS option machinery (the
  # module routes through `internal.compile.mkTable` directly,
  # bypassing the public `mkTable` wrapper — see
  # `lib/default.nix` and `modules/nftzones.nix`).
  #
  # Trigger: two zones declaring overlapping interfaces, which
  # `checkInterfaceOverlap` rejects.
  testModulePhase1ValidatorPropagates = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              zones.lan-a.interfaces = [ "lan0" ];
              zones.lan-b.interfaces = [ "lan0" ];
            };
          };
        };
        attempt = builtins.tryEval (builtins.deepSeq cfg.networking.nftables.tables.fw.content null);
      in
      attempt.success;
    expected = false;
  };

  # Default values must not leak into the content — verifies the
  # prefix is empty when neither field is set.
  testModuleNoMetadataPrefixByDefault = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw.zones.lan.interfaces = [ "lan0" ];
          };
        };
        content = cfg.networking.nftables.tables.fw.content;
      in
      {
        hasFlags = lib.hasInfix "flags" content;
        hasComment = lib.hasInfix "comment " content;
      };
    expected = {
      hasFlags = false;
      hasComment = false;
    };
  };
}
