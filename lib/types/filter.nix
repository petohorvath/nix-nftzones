/*
  types/filter — exposes filter-related types under `nftzones.types`.

  Exported types:
    - `filter`         — submodule for one filter definition
    - `filterName`     — string identifier for a filter
    - `filterRule`     — list of nftypes DSL statements (rule body)
    - `filterPriority` — symbol-or-int entry sort key (lower runs first)
    - `filterComment`  — optional free-form comment

  A filter is a directed `from → to` zone-pair rule. It carries a
  rule body (matches plus a verdict, expressed as nftypes
  statements), an ordering key, and an optional free-form comment.
  Consumers wire it as `lib.mkOption { type = lib.types.attrsOf
  nftzones.types.filter; }`.

  `from` / `to` use the shared `zoneNames` type (non-empty list
  of `zoneName` strings) — see `lib/types/zone.nix`. Whether each
  entry resolves to a declared zone, `settings.localZone`, or
  `settings.wildcardZone` is a cross-cutting check that belongs in
  module assertions on the enclosing `filters` attrset.

  `filterRule` entries pass through nftypes' attrTag validation, so
  consumers cannot smuggle hand-rolled libnftables-json shapes. The
  list spans both match conditions (e.g. `eq tcp.dport 22`) and the
  verdict (e.g. `accept`); entries are spliced conjunctively into a
  single nftables rule.

  `filterPriority` orders rules sharing the same `(from, to)` pair
  — an nftzones-internal sort key, NOT the nftables chain priority.
  Either a symbol (`first` / `preDispatch` / `postDispatch` /
  `default` / `last`) or any int. Default `"default"` (= 500).
  Cells are emitted in `(priority asc, name asc)` order. The
  cutoff at 100 splits cells into pre-dispatch (< 100, emitted
  before per-zone matchers) and post-dispatch (>= 100, after).

  The `chain` field is the shared `primitives.chainOverride`
  (optional `{ hook; priority; }` submodule). By default
  (`chain = null`), the entry is dispatched to `input`,
  `forward`, or `output` based on `settings.localZone`:
    - `to` references `settings.localZone` → `input`
    - `from` references `settings.localZone` → `output`
    - neither → `forward`
  Setting `chain` pins the entry to a specific base chain (useful
  for rpfilter at `prerouting + raw`). At a non-default hook, `to`
  and `from` may not have their usual match semantics (notably
  `to` is meaningless in `prerouting` since routing hasn't
  happened yet); the compiler treats them as match expressions
  where applicable and skips them otherwise.

  Example:
    options.filters = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.filter;
      default = { };
    };

    config.filters.allow-ssh = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
      comment = "ssh from anywhere";
    };
    config.filters.web-out = {
      from = [ "lan" ];
      to = [ "wan" "vpn" ];
      rule = [
        (eq tcp.dport 443)
        accept
      ];
    };
*/
{
  inputs,
  primitives,
  zone,
}:
let
  inherit (inputs) lib;
  inherit (zone) zoneNames;
  inherit (primitives) chainOverride;

  filterName = primitives.identifier;

  filterComment = primitives.comment;

  filterRule = primitives.rule;

  filterPriority = primitives.entryPriority;

  filter = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = filterName;
          default = name;
          example = "allow-ssh";
          description = ''
            The filter's name. Defaults to the attribute name in the
            enclosing `filters` attrset, e.g.
            `filters.allow-ssh.name == "allow-ssh"`.
          '';
        };

        from = lib.mkOption {
          type = zoneNames;
          example = [ "wan" ];
          description = ''
            Source zones for the filter — non-empty. Each entry is
            either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`); resolution
            is enforced at module level, not by the type.
          '';
        };

        to = lib.mkOption {
          type = zoneNames;
          example = [
            "wan"
            "vpn"
          ];
          description = ''
            Destination zones for the filter. Same shape rules as
            `from`.
          '';
        };

        rule = lib.mkOption {
          type = filterRule;
          example = lib.literalExpression ''
            [
              (eq tcp.dport 22)
              accept
            ]
          '';
          description = ''
            Body of the nftables rule, expressed as a list of
            nftypes DSL statements. Spans both match conditions and
            the verdict; entries are spliced conjunctively into a
            single nftables rule.
          '';
        };

        priority = lib.mkOption {
          type = filterPriority;
          default = "default";
          example = "first";
          description = ''
            Sort key for ordering rules within their chain.
            Either a symbol (`first` / `preDispatch` /
            `postDispatch` / `default` / `last`) or any int.
            Cells are emitted in `(priority asc, name asc)` order.
            See `primitives.entryPriority` for symbol → int
            mapping. NOT the nftables chain priority — that's
            `hook.priority`.
          '';
        };

        chain = lib.mkOption {
          type = chainOverride;
          default = null;
          example = {
            hook = "prerouting";
            priority = "raw";
          };
          description = ''
            Override the chain placement. `null` (the default)
            dispatches to `input` / `forward` / `output` based on
            whether `from` / `to` reference `settings.localZone`.
            A submodule pins the entry to a specific base chain —
            useful for placements like rpfilter
            (`chain = { hook = "prerouting"; priority = "raw"; }`).
            At non-default hooks, `to` / `from` may lose their
            usual match meaning (notably `to` in `prerouting`);
            the compiler emits matches where applicable.
          '';
        };

        comment = lib.mkOption {
          type = filterComment;
          default = null;
          example = "ssh from anywhere";
          description = ''
            Free-form comment, propagated to the generated nftables
            rule. `null` (the default) emits no comment.
          '';
        };
      };
    }
  );
in
{
  inherit
    filterName
    filterRule
    filterPriority
    filterComment
    filter
    ;
}
