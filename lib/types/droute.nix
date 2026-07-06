/*
  types/droute — exposes droute-related types under `nftzones.types`.

  Exported types:
    - `droute`         — submodule for one droute definition
    - `drouteName`     — string identifier for a droute
    - `drouteRule`     — list of nftypes statements (mangle / match
                         body)
    - `droutePriority` — symbol-or-int entry sort key (lower runs first)
    - `drouteComment`  — optional free-form comment

  A droute is a destination-zone-keyed route-mangling rule that
  applies in output (`type route hook output priority mangle`). It
  marks or mangles locally-generated outbound packets based on
  destination zone, triggering a routing re-evaluation when the
  chain exits — used for mark-based policy routing of local
  traffic (e.g. multi-WAN selection by destination). Consumers
  wire it as `lib.mkOption { type = lib.types.attrsOf
  nftzones.types.droute; }`.

  Why no `from`: output-hook chains fire only on locally-generated
  packets, so the source zone is always `settings.localZone`.
  Including `from = [ <localZone> ]` as boilerplate would add
  noise without informing dispatch.

  `to` uses the shared `zoneNames` type and the same wildcard /
  localZone behaviour as filter / snat / dnat / sroute — see
  `types/filter.nix` for the full discussion.

  `drouteRule` is a flat list of nftypes statements — typically
  match conditions plus mangle statements like `meta mark set N`.
  No verdict is expected; the chain triggers routing
  re-evaluation, not a verdict.

  `droutePriority` orders rules sharing the same `to` zone: lower
  values run first.

  Example:
    options.droutes = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.droute;
      default = { };
    };

    config.droutes.lan-via-vpn = {
      to = [ "lan-remote" ];
      rule = [
        (mangle meta.mark 200)
      ];
      comment = "local traffic to remote-lan via VPN";
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

  drouteName = primitives.identifier;

  drouteComment = primitives.comment;

  drouteRule = primitives.rule;

  droutePriority = primitives.entryPriority;

  droute = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = drouteName;
          default = name;
          example = "lan-via-vpn";
          description = ''
            The droute's name. Defaults to the attribute name in
            the enclosing `droutes` attrset, e.g.
            `droutes.lan-via-vpn.name == "lan-via-vpn"`.
          '';
        };

        to = lib.mkOption {
          type = zoneNames;
          example = [ "lan-remote" ];
          description = ''
            Destination zones for the droute — non-empty. Each
            entry is either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`); resolution
            is enforced at module level, not by the type.
          '';
        };

        rule = lib.mkOption {
          type = drouteRule;
          default = [ ];
          example = lib.literalExpression ''
            [ (mangle meta.mark 200) ]
          '';
          description = ''
            Flat list of nftypes statements — typically match
            conditions plus mangle / mark operations. No verdict
            expected; the chain triggers a routing re-evaluation
            when it exits, not a verdict-based decision.
          '';
        };

        priority = lib.mkOption {
          type = droutePriority;
          default = "default";
          example = "first";
          description = ''
            Sort key for ordering rules within their chain.
            Either a symbol (`first` / `preDispatch` /
            `postDispatch` / `default` / `last`) or any int.
          '';
        };

        comment = lib.mkOption {
          type = drouteComment;
          default = null;
          example = "local traffic to remote-lan via VPN";
          description = ''
            Free-form comment, propagated to the generated
            nftables rule. `null` (the default) emits no comment.
          '';
        };
      };
    }
  );
in
{
  inherit
    drouteName
    drouteRule
    droutePriority
    drouteComment
    droute
    ;
}
