/*
  types/dnat — exposes dnat-related types under `nftzones.types`.

  Exported types:
    - `dnat`         — submodule for one dnat definition
    - `dnatName`     — string identifier for a dnat
    - `dnatRule`     — submodule with `match` (required) and
                       `action` (attrTag of `dnat` / `redirect`)
    - `dnatPriority` — symbol-or-int entry sort key (`first` /
                       `preDispatch` / `default` / …)
    - `dnatComment`  — optional free-form comment

  A dnat is a directed `from` zone NAT rule that applies in
  prerouting (`type nat hook prerouting priority dstnat`). It
  carries match conditions on the original packet, a structured
  rewrite spec, an ordering key, and an optional comment. Consumers
  wire it as `lib.mkOption { type = lib.types.attrsOf
  nftzones.types.dnat; }`.

  Why no `to`: prerouting runs before the routing decision, so the
  destination zone (which depends on routing) isn't determined when
  the entry's emitted rules fire. The "target" of the rewrite is
  part of the rule body (`rule.action.dnat.addr`, …), not a zone
  match. Filter and snat both have `to` because they fire after
  routing — dnat is the structural exception.

  `from` uses the shared `zoneNames` type and the same wildcard
  / localZone behaviour as filter and snat — see
  `types/filter.nix` for the full discussion. Cross-cutting
  checks belong in module assertions on the enclosing `dnats`
  attrset. The `chain` field is the shared
  `primitives.chainOverride`.

  `dnatRule` has two fields:
    - `match`  — a list of nftypes statements matched against the
                 original (pre-DNAT) packet, e.g.
                 `[ (eq tcp.dport 443) ]`. Defaults to `[ ]`
                 (unfiltered DNAT from the source zone); typical
                 port-forwarding rules should set this
                 explicitly.
    - `action` — exactly one of:
                 - `dnat`     — full address translation; reuses
                                `nftypes.types.statements.natBody`.
                 - `redirect` — auto-target (redirect to localhost);
                                reuses
                                `nftypes.types.statements.masqueradeBody`.

  Reusing nftypes' shapes keeps flag enums (`natFlag`,
  `natTypeFlag`) and field validation in lock-step with
  libnftables-json.

  `dnatPriority` is the entry sort key — symbol or int, default
  `"default"` (= 500). NOT the nftables chain priority (that's
  the `chain.priority` field on the submodule). See
  `primitives.entryPriority` for the symbol → int mapping.

  The default chain placement is prerouting at `dstnat` priority.
  Setting the `chain` field pins the entry to a specific base
  chain instead — useful for output-hook DNAT on locally-generated
  traffic.

  Example:
    options.dnats = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.dnat;
      default = { };
    };

    config.dnats.web-fwd = {
      from = [ "wan" ];
      rule = {
        match = [ (eq tcp.dport 443) ];
        action.dnat = { addr = "10.0.0.5"; port = 443; };
      };
      comment = "expose internal web on :443";
    };
    config.dnats.ssh-redirect = {
      from = [ "wan" ];
      rule = {
        match = [ (eq tcp.dport 2222) ];
        action.redirect = { port = 22; };
      };
    };
*/
{
  inputs,
  primitives,
  zone,
}:
let
  inherit (inputs) lib nftypes;
  inherit (zone) zoneNames;
  inherit (primitives) chainOverride;

  dnatName = primitives.identifier;

  dnatComment = primitives.comment;

  /*
    Two fields: `match` (required) and `action` (the rewrite). The
    `action` wrapper exists because `attrTag` requires its attrset
    to contain exactly one tagged key from its fixed set with no
    extras — putting `match` next to `dnat` / `redirect` directly
    would violate that. So `action` carries the attrTag alone,
    with `match` as its sibling at the parent level. The cost is
    one extra dot at the user's write site
    (`rule.action.dnat = …` instead of `rule.dnat = …`); the
    benefit is type-level enforcement of "exactly one of
    dnat / redirect".
  */
  dnatRule = lib.types.submodule {
    options = {
      match = lib.mkOption {
        type = primitives.rule;
        default = [ ];
        example = lib.literalExpression ''
          [ (eq tcp.dport 443) ]
        '';
        description = ''
          Match conditions on the original (pre-DNAT) packet.
          Defaults to `[ ]` (unfiltered DNAT from the source
          zone); typical port-forwarding rules should set this
          explicitly, e.g. `[ (eq tcp.dport 443) ]`.
        '';
      };
      action = lib.mkOption {
        type = lib.types.attrTag {
          dnat = lib.mkOption {
            type = nftypes.types.statements.natBody;
          };
          redirect = lib.mkOption {
            type = nftypes.types.statements.masqueradeBody;
          };
        };
        description = ''
          Rewrite spec — exactly one of `dnat` (full address
          translation) or `redirect` (auto-target localhost).
          Inner submodule shapes are reused from nftypes'
          `natBody` and `masqueradeBody`.
        '';
      };
    };
  };

  dnatPriority = primitives.entryPriority;

  dnat = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = dnatName;
          default = name;
          example = "web-fwd";
          description = ''
            The dnat's name. Defaults to the attribute name in the
            enclosing `dnats` attrset, e.g.
            `dnats.web-fwd.name == "web-fwd"`.
          '';
        };

        from = lib.mkOption {
          type = zoneNames;
          example = [ "wan" ];
          description = ''
            Source zones for the dnat — non-empty. Each entry is
            either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`); resolution
            is enforced at module level, not by the type.
          '';
        };

        rule = lib.mkOption {
          type = dnatRule;
          example = lib.literalExpression ''
            {
              match = [ (eq tcp.dport 443) ];
              action.dnat = { addr = "10.0.0.5"; port = 443; };
            }
          '';
          description = ''
            Match conditions and the rewrite. See `dnatRule` for
            the field layout.
          '';
        };

        priority = lib.mkOption {
          type = dnatPriority;
          default = "default";
          example = "first";
          description = ''
            Sort key for ordering rules within their chain.
            Either a symbol (`first` / `preDispatch` /
            `postDispatch` / `default` / `last`) or any int. NOT
            the nftables chain priority — that's `chain.priority`.
          '';
        };

        chain = lib.mkOption {
          type = chainOverride;
          default = null;
          example = {
            hook = "output";
            priority = "dstnat";
          };
          description = ''
            Override the chain placement. `null` (the default)
            uses prerouting at `dstnat` priority. A submodule
            pins the entry to a specific base chain — useful for
            output-hook DNAT on locally-generated traffic.
          '';
        };

        comment = lib.mkOption {
          type = dnatComment;
          default = null;
          example = "expose internal web on :443";
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
    dnatName
    dnatRule
    dnatPriority
    dnatComment
    dnat
    ;
}
