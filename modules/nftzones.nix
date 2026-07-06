/*
  NixOS module that compiles `nftzones`-shaped table bodies into
  block-form nftables text and feeds them through nixpkgs'
  `networking.nftables.tables.<name>.content` option. nixpkgs owns
  the systemd unit, the per-table deletion tracking, the atomic
  ruleset reload, and the build-time `nft --check` pipeline; this
  module is the typed translator.

  Two-stage function: the outer takes the `nftzones` and `nftypes`
  libs (applied by `flake.nix` from the host system's `libBySystem`
  and the `nftypes` flake input); the inner is the standard NixOS
  module function. Keeping these libs out of `_module.args` means
  user-facing modules never see them as injected arguments — both
  are reached via their own flake inputs.
*/
{
  nftzones,
  nftypes,
}:
{
  lib,
  config,
  options,
  ...
}:
let
  cfg = config.networking.nftzones;

  renderTable = if cfg.pretty then nftypes.toTextBlockPretty else nftypes.toTextBlock;

  # `nftypes.toTextBlock` drops the `add table` self-command (its
  # consumer — here nixpkgs' `networking.nftables.tables` — supplies
  # the `table <fam> <name> { ... }` wrapper itself). That self-
  # command is where `flags` and `comment` live, so the block
  # renderer silently strips them. nftables block syntax permits
  # both inside the braces, so we prepend them ourselves.
  #
  # No escaping needed for the comment: `nftzones.types.comment`
  # restricts the input to nft-safe characters (no `"`, no `\`, no
  # control chars, ≤128 bytes) at eval time. nft has no escape
  # grammar so render-escaping isn't an option anyway.
  renderTableMetadata =
    table:
    let
      flagsLine = lib.optional (table.flags != [ ]) "flags ${lib.concatStringsSep ", " table.flags};";
      commentLine = lib.optional (table.comment != null) ''comment "${table.comment}";'';
      lines = flagsLine ++ commentLine;
    in
    lib.optionalString (lines != [ ]) (lib.concatStringsSep "\n" lines + "\n");

  compiledTables = lib.mapAttrs (
    _name: tableValue:
    let
      table = nftzones.internal.compile.mkTable tableValue;
    in
    {
      inherit (table) family;
      # `tableValue` carries the user-shape with submodule defaults
      # filled in (its `name` already projected onto the attr key by
      # the `tables` option's `apply`); `table` is the compiled
      # nftypes value which drops empty / null fields. Reading
      # metadata from the user-shape keeps the prefix renderer
      # predictable.
      content = renderTableMetadata tableValue + renderTable table;
    }
  ) cfg.tables;
in
{
  options.networking.nftzones = {
    enable = lib.mkEnableOption "nftzones-managed nftables tables";

    tables = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.table;
      default = { };
      # Project every table's `name` onto its attribute key — the
      # single source of truth for the table's identity. `name`
      # defaults to the key already, but a whole evaluated table
      # forwarded from a differently-keyed facade option
      # (`options.myfw = mkOption { type = nftzones.types.table; };`
      # then `tables.fw = config.myfw;`) carries the source's `name`
      # ('myfw') as an explicit definition that would otherwise beat
      # the key-derived default. Overriding here keeps
      # `tables.<key>.name == <key>` for every reader — the compile
      # pipeline, the on-wire ruleset, and introspection tools — so
      # facades and whole-table copies "just work" without a
      # per-submodule `apply` guard on the type (which couldn't see
      # the real key). This is the `mapAttrs (key: t: t // { name =
      # key; })` boundary the grouped object types get for free from
      # their enclosing `attrsOf` key.
      apply = lib.mapAttrs (key: tableValue: tableValue // { name = key; });
      description = ''
        Table bodies keyed by nftables table name. Each entry is
        compiled and translated into `networking.nftables.tables.<name>`
        for activation. A table's `name` is always its attribute key:
        a value forwarded from a differently-keyed option is recompiled
        under the key.
      '';
    };

    pretty = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Emit block-form text in multi-line indented form instead of
        compact. Useful for inspecting the generated ruleset; compact
        keeps `nix store` diffs smaller.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.networking.nftables.enable;
        message = ''
          networking.nftzones.enable requires networking.nftables.enable = true.
          The nftzones module piggy-backs on the nftables module's systemd unit
          and per-table deletion tracking; without it, the compiled tables
          won't be activated.
        '';
      }
      {
        # An enabled nftzones with no tables compiles to no chains. Combined
        # with the typical `networking.firewall.enable = false` that
        # nftzones-managed hosts run with, this silently leaves the host
        # with no firewall at all. Reject the empty-tables case so the
        # user has to opt out explicitly (via `enable = false`) rather
        # than by omission.
        assertion = cfg.tables != { };
        message = ''
          networking.nftzones.enable is true but networking.nftzones.tables is empty.
          This compiles to no nftables chains, which — combined with
          networking.firewall.enable = false — leaves the host with no
          firewall at all. Either declare at least one table under
          networking.nftzones.tables, or set networking.nftzones.enable = false.
        '';
      }
    ]
    # `networking.firewall` installs its own `inet filter` table
    # hooked at `(input, filter)`; nftzones tables typically claim
    # the same hook slot. nftables runs both base chains at the
    # same priority and the effective policy is the union of
    # accepts, which is rarely the user's intent. Warn (don't
    # error) — there are edge cases where a user genuinely wants
    # the stock firewall alongside zone-managed rules.
    ++ lib.mapAttrsToList (name: _: {
      # The nftzones module's own contribution (assigned a few
      # lines below) shows up in `options.networking.nftables.
      # tables.definitions` alongside any user-supplied ones, so
      # the naive "is the key present?" check on the merged
      # config always fires for every table this module owns.
      # Counting contributors of this specific key against the
      # pre-merge definitions list lets us flag the *real*
      # collision: more than one source supplying the same name.
      assertion =
        (builtins.length (
          builtins.filter (def: def ? ${name}) options.networking.nftables.tables.definitions
        )) <= 1;
      message = ''
        networking.nftzones.tables.${name} collides with networking.nftables.tables.${name}.
        Declare each table in exactly one module.
      '';
    }) cfg.tables;

    networking.nftables.tables = compiledTables;

    warnings = lib.optional config.networking.firewall.enable ''
      Both networking.firewall.enable and networking.nftzones.enable are true.
      networking.firewall installs its own `inet filter` table at hook
      `(input, filter)`; nftzones tables typically claim the same hook slot.
      Both base chains fire on every packet at the same priority and the
      effective policy is the union of their accepts — opening more ports
      than either source declared. Set networking.firewall.enable = false
      when nftzones owns the input chain.
    '';
  };
}
