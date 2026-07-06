/*
  Unit tests for the `name == <attribute key>` invariant across the
  object types under `lib/types/`.

  Two properties, both consequences of dropping `readOnly` from each
  type's `name` sub-option:

    1. Copy-safe: an *evaluated* submodule can be copied between two
       `attrsOf <type>` options (the facade-wrapper pattern — see the
       downstream context in the fix) and its `.name` forced without
       the module system rejecting the copied, key-derived definition.
       This is the regression guard: it throws on the pre-fix
       `readOnly = true` code and passes now.

    2. Invariant preserved: for the keyed object types, an explicit
       `name` that differs from the enclosing key is rejected by
       `internal.normalize.checkNameKeyMismatch`. The table's name is
       instead a projection of its real attr key, derived at the
       module / `mkTable` boundary — a divergent `name` is overridden
       by the key, not rejected, so a facade can forward a whole
       evaluated table under any key.

  Same `testFoo = { expr; expected; }` shape as every other unit
  test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (pkgs) lib;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalFails;

  inherit (nftzones.types)
    zone
    node
    filter
    policy
    snat
    dnat
    sroute
    droute
    table
    ;

  /*
    Reproduce the downstream facade-wrapper collision: declare two
    `attrsOf <type>` options, copy the first into the second, then
    force the copied entry's `.name`. Returns that forced name.

    On the pre-fix `readOnly = true` code this throws ("… is
    read-only, but it's set multiple times"); after the fix the two
    equal key-derived values merge and it resolves to the key ("z").

    Only `.name` is forced, so required sibling fields (e.g.
    `node.zone`) are never evaluated and an empty body suffices for
    every type.
  */
  copySafeName =
    type: body:
    (lib.evalModules {
      modules = [
        {
          options.a = lib.mkOption {
            type = lib.types.attrsOf type;
            default = { };
          };
          options.b = lib.mkOption {
            type = lib.types.attrsOf type;
            default = { };
          };
        }
        (
          { config, ... }:
          {
            a.z = body;
            b = config.a;
          }
        )
      ];
    }).config.b.z.name;
in
{
  # ===== copy-safe: every object type survives the facade copy =====

  testCopySafeZone = {
    expr = copySafeName zone { };
    expected = "z";
  };

  testCopySafeNode = {
    expr = copySafeName node { };
    expected = "z";
  };

  testCopySafeFilter = {
    expr = copySafeName filter { };
    expected = "z";
  };

  testCopySafePolicy = {
    expr = copySafeName policy { };
    expected = "z";
  };

  testCopySafeSnat = {
    expr = copySafeName snat { };
    expected = "z";
  };

  testCopySafeDnat = {
    expr = copySafeName dnat { };
    expected = "z";
  };

  testCopySafeSroute = {
    expr = copySafeName sroute { };
    expected = "z";
  };

  testCopySafeDroute = {
    expr = copySafeName droute { };
    expected = "z";
  };

  testCopySafeTable = {
    expr = copySafeName table { };
    expected = "z";
  };

  # A whole evaluated table forwarded between two *differently-keyed*
  # `attrsOf table` options (the facade / copy pattern). Pre-fix, the
  # table `name` `apply` compared the source's key-derived name
  # ('src') against the destination key ('dst') and threw; post-fix
  # (apply dropped) the copy resolves. A plain `attrsOf` is not a
  # compile boundary, so no key-projection happens here — the
  # source's `.name` survives — but resolving without a throw is the
  # property under test. The module / `mkTable` boundary is what
  # re-projects the name to the key (see the table tests below).
  testCopySafeTableDifferentKey = {
    expr =
      (lib.evalModules {
        modules = [
          {
            options.a = lib.mkOption {
              type = lib.types.attrsOf table;
              default = { };
            };
            options.b = lib.mkOption {
              type = lib.types.attrsOf table;
              default = { };
            };
          }
          (
            { config, ... }:
            {
              a.src = { };
              b.dst = config.a.src;
            }
          )
        ];
      }).config.b.dst.name;
    expected = "src";
  };

  # ===== invariant: keyed object types reject explicit name != key =====

  # Keyed object types — caught by `checkNameKeyMismatch` in Phase 1.
  testNameKeyMismatchZoneThrows = {
    expr = evalFails (
      nftzones.mkTable "fw" {
        zones.lan = {
          interfaces = [ "eth0" ];
          name = "other";
        };
      }
    );
    expected = true;
  };

  testNameKeyMismatchPolicyThrows = {
    expr = evalFails (
      nftzones.mkTable "fw" {
        zones = {
          lan.interfaces = [ "eth0" ];
          wan.interfaces = [ "eth1" ];
        };
        policies.lan-to-wan = {
          from = [ "lan" ];
          to = [ "wan" ];
          verdict = "accept";
          name = "other";
        };
      }
    );
    expected = true;
  };

  # A matching explicit name still compiles — proves the guard fires
  # on the mismatch specifically, not on any explicit `name`.
  testNameKeyMatchZoneCompiles = {
    expr = evalFails (
      nftzones.mkTable "fw" {
        zones.lan = {
          interfaces = [ "eth0" ];
          name = "lan";
        };
      }
    );
    expected = false;
  };

  # ===== invariant: table name is a projection of its attr key =====

  # Unlike the keyed object types above, the table's on-wire name is
  # derived at the `mkTable` boundary rather than enforced per
  # submodule. An explicit `name` that differs from the key is
  # overridden by the key (so forwarding a whole evaluated table
  # "just works"), not rejected.
  testTableNameProjectedFromKey = {
    expr = (nftzones.mkTable "fw" { name = "other"; }).name;
    expected = "fw";
  };

  # A matching explicit name is equally fine — same projected result.
  testTableNameMatchingKeyCompiles = {
    expr = (nftzones.mkTable "fw" { name = "fw"; }).name;
    expected = "fw";
  };
}
