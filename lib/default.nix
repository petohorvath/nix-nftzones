{ inputs }:
let
  inherit (inputs) lib;

  /*
    Internal building blocks — leaf helpers, per-phase orchestrators,
    and the top-level compile orchestrator. `lib/internal/default.nix`
    returns one attrset per source module; each module's exports stay
    under that submodule key, so callers reach functions as
    `nftzones.internal.<module>.<fn>` (e.g.
    `nftzones.internal.zone.genSets`,
    `nftzones.internal.compile.mkTable`).

    Stability: `nftzones.internal.*` carries no semver guarantee.
    Names, signatures, and the per-module split can change in
    any release — the namespace is exposed for our own unit
    tests and for advanced users who explicitly opt in. Public
    consumers should reach for `mkTable` / `mkRuleset` / the
    NixOS module, or for `types` / `snippets`.
  */
  internal = import ./internal { inherit inputs; };

  /*
    NixOS option types for the public surface. `lib/types/default.nix`
    returns one attrset per source module; we flatten their values
    onto a single `types` namespace (unlike `internal`, which keeps
    the per-module sub-namespaces).
  */
  typeModules = import ./types { inherit inputs; };
  types = lib.mergeAttrsList (lib.attrValues typeModules);

  /*
    Rule-body shorthand under `nftzones.snippets.*`. Each leaf is
    a function returning an `nftypes.dsl.*` statement list ready
    to splice into `filters.<name>.rule = ...`. Inert until used —
    the compile pipeline never sees these helpers; the returned
    statements are validated by the same primitive type as any
    hand-written body.
  */
  snippets = import ./snippets.nix { inherit inputs; };

  /*
    Validate a raw user `body` (an attrset) against `types.table`
    by running it through `lib.evalModules`, using `name` as the
    option attribute key so the table's `name` field derives from
    the user's chosen value (the submodule's `default = name`
    mechanism). The `name` arg is the authoritative on-wire table
    name (this function is a compile boundary), so any `name` the
    body itself carried is overridden with it — mirroring how the
    NixOS module derives the on-wire name from its real attr key.
    That makes forwarding a whole evaluated table straight into
    `mkTable` / `mkRuleset` "just work".

    Returns the evaluated `nftzones.types.table` value with all
    submodule defaults filled in. Internal helper for the public
    `mkTable` / `mkRuleset` — NixOS-module consumers who already
    have an evaluated value should reach `internal.compile.mkTable`
    directly to skip this redundant re-eval (the value is already
    validated, and the module applies the same key-derived `name`
    override at its own boundary).
  */
  evalTableBody =
    name: body:
    (lib.evalModules {
      modules = [
        { options.${name} = lib.mkOption { type = types.table; }; }
        { config.${name} = body; }
      ];
    }).config.${name}
    // {
      name = name;
    };

  mkTable = name: body: internal.compile.mkTable (evalTableBody name body);
  mkRuleset = name: body: internal.compile.mkRuleset (evalTableBody name body);
in
{
  # Library version. Bumped manually per release.
  version = "0.1.0";

  inherit
    internal
    types
    snippets
    mkTable
    mkRuleset
    ;
}
