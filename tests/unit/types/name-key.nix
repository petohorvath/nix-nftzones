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

    2. Invariant preserved: an explicit `name` that differs from the
       enclosing key is rejected — by
       `internal.normalize.checkNameKeyMismatch` for the keyed object
       types, and by the `apply` on `types.table.name` for the table.

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

  # ===== invariant: explicit name != key is rejected =====

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

  # Table — caught by the `apply` on `types.table.name` (the table
  # has no enclosing key by the time the pipeline sees it).
  testNameKeyMismatchTableThrows = {
    expr = evalFails (nftzones.mkTable "fw" { name = "other"; });
    expected = true;
  };

  testNameKeyMatchTableCompiles = {
    expr = evalFails (nftzones.mkTable "fw" { name = "fw"; });
    expected = false;
  };
}
