/*
  types/snat — exposes snat-related types under `nftzones.types`.

  Exported types:
    - `snat`         — submodule for one snat definition
    - `snatName`     — string identifier for an snat
    - `snatRule`     — attrTag union of `snat` and `masquerade`
                       bodies (the rule body)
    - `snatPriority` — symbol-or-int entry sort key (`first` /
                       `preDispatch` / `default` / …)
    - `snatComment`  — optional free-form comment

  An snat is a directed `from → to` zone-pair NAT rule that applies
  in postrouting (`type nat hook postrouting priority srcnat`). It
  carries a structured rewrite spec, an ordering key, and an
  optional comment. Consumers wire it as `lib.mkOption {
  type = lib.types.attrsOf nftzones.types.snat; }`.

  `from` / `to` use the shared `zoneNames` type and the same
  wildcard / localZone behaviour as filter — see
  `types/filter.nix` for the full discussion. Cross-cutting
  checks belong in module assertions on the enclosing `snats`
  attrset. The `chain` field is the shared
  `primitives.chainOverride`.

  `snatRule` is an `attrTag` of two nftypes-derived submodules:
    - `snat`       — full address translation; fields `addr`,
                     `port?`, `family?`, `flags?`, `type_flags?`.
                     Reuses `nftypes.types.statements.natBody`.
    - `masquerade` — auto-target via outgoing interface; fields
                     `port?`, `flags?`. Reuses
                     `nftypes.types.statements.masqueradeBody`.

  Reusing nftypes' shapes keeps flag enums (`natFlag`,
  `natTypeFlag`) and field validation in lock-step with
  libnftables-json.

  `snatPriority` is the entry sort key — symbol or int, default
  `"default"` (= 500). NOT the nftables chain priority (that's
  the `chain.priority` field on the submodule). See
  `primitives.entryPriority` for the symbol → int mapping.

  The default chain placement is postrouting at `srcnat` priority.
  Setting the `chain` field pins the entry to a specific base
  chain instead — useful for output-hook SNAT on locally-generated
  traffic.

  Example:
    options.snats = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.snat;
      default = { };
    };

    config.snats.lan-masquerade = {
      from = [ "lan" "guest" ];
      to = [ "wan" ];
      rule.masquerade = { };
      comment = "outbound NAT";
    };
    config.snats.web-snat = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule.snat = {
        addr = "203.0.113.5";
        port = 8080;
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

  snatName = primitives.identifier;

  snatComment = primitives.comment;

  /*
    Tagged union of the two postrouting-NAT body shapes. `attrTag`
    enforces "exactly one of {snat, masquerade}" at the type level.
    Both inner submodules are reused from nftypes, so flag enums
    and field validation stay in lock-step with libnftables-json.
  */
  snatRule = lib.types.attrTag {
    snat = lib.mkOption {
      type = nftypes.types.statements.natBody;
    };
    masquerade = lib.mkOption {
      type = nftypes.types.statements.masqueradeBody;
    };
  };

  snatPriority = primitives.entryPriority;

  snat = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = snatName;
          default = name;
          example = "lan-masquerade";
          description = ''
            The snat's name. Defaults to the attribute name in the
            enclosing `snats` attrset, e.g.
            `snats.lan-masquerade.name == "lan-masquerade"`.
          '';
        };

        from = lib.mkOption {
          type = zoneNames;
          example = [ "lan" ];
          description = ''
            Source zones for the snat — non-empty. Each entry is
            either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`); resolution
            is enforced at module level, not by the type.
          '';
        };

        to = lib.mkOption {
          type = zoneNames;
          example = [ "wan" ];
          description = ''
            Destination zones for the snat. Same shape rules as
            `from`.
          '';
        };

        rule = lib.mkOption {
          type = snatRule;
          example = lib.literalExpression ''
            { masquerade = { }; }
          '';
          description = ''
            Rewrite spec — exactly one of `snat` (full address
            translation) or `masquerade` (auto-target via the
            outgoing interface). Inner submodule shapes are
            reused from nftypes' `natBody` and `masqueradeBody`.
          '';
        };

        priority = lib.mkOption {
          type = snatPriority;
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
            priority = "srcnat";
          };
          description = ''
            Override the chain placement. `null` (the default)
            uses postrouting at `srcnat` priority. A submodule
            pins the entry to a specific base chain — useful for
            output-hook SNAT on locally-generated traffic.
          '';
        };

        comment = lib.mkOption {
          type = snatComment;
          default = null;
          example = "outbound NAT";
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
    snatName
    snatRule
    snatPriority
    snatComment
    snat
    ;
}
