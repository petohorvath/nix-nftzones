/*
  types/policy — exposes policy-related types under `nftzones.types`.

  Exported types:
    - `policy`        — submodule for one policy definition
    - `policyName`    — string identifier for a policy
    - `policyVerdict` — `"accept"` or `"drop"` (reuses
                        `nftypes.types.policy`)
    - `policyComment` — optional free-form comment

  A policy is the default verdict for a directed `from → to`
  zone-pair when no specific filter matches. Per-pair, not
  per-chain — each pair gets its own default, allowing asymmetric
  defaults like `lan -> wan accept` / `wan -> lan drop` (the
  defining feature of zone-based firewalls).

  Compile target: a tail rule in the pair's sub-chain (after all
  filter rules for that pair have been considered). The nftables
  chain-level `policy drop` on each base chain remains as the
  absolute catch-all when no per-pair policy fires (e.g., packets
  not matching any declared zone).

  No `rule`, `priority`, or `chain` fields:
    - **No `rule`** — policies are verdict-only; no match
                      conditions. Match conditions live on filters.
    - **No `priority`** — policies are always the *tail rule* of
                          their sub-chain (effectively
                          `priority = "last"`).
    - **No `chain`** — policies always live in the per-pair
                       sub-chain; they can't override placement.

  Cardinality:
    At most one policy per directed `(from, to)` pair. Two
    policies for the same pair is a configuration error; the
    check is enforced at module level (not by the type itself).

    Wildcard policies (`policies.catchall = { from = [ "all" ];
    to = [ "all" ]; verdict = "drop"; }`) rely on upstream
    wildcard resolution: `settings.wildcardZone` (default `"all"`)
    expands to all declared zones plus `settings.localZone` before
    per-pair compilation, with explicit policies winning over
    wildcard fills.

  `from` / `to` use the shared `zoneNames` type and the same
  wildcard / localZone behaviour as filter / snat / dnat — see
  `types/filter.nix` for the full discussion.

  `policyVerdict` is `enum [ "accept" "drop" ]` — the two
  verdicts nftables permits in a chain-level `policy <X>;`
  clause, applied here at the per-pair level. Defined locally
  rather than reused from `nftypes.types.policy` because the
  compile pipeline's `policyVerdictStmts` dispatch only knows
  `accept` / `drop`; if upstream ever broadens its policy enum
  the local constraint keeps Phase 4 from crashing on an
  unrecognized value. The pipeline turns `"accept"` into
  `{ accept = null; }` and `"drop"` into `{ drop = null; }`
  (`nftypes.dsl.<verdict>`) for the emitted tail rule.

  Example:
    options.policies = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.policy;
      default = { };
    };

    config.policies.lan-to-wan = {
      from = [ "lan" ];
      to = [ "wan" ];
      verdict = "accept";
      comment = "LAN can reach the internet";
    };
    config.policies.wan-to-lan = {
      from = [ "wan" ];
      to = [ "lan" ];
      verdict = "drop";
      comment = "no inbound to LAN by default";
    };
    config.policies.catchall = {
      from = [ "any" ];
      to = [ "any" ];
      verdict = "drop";
      comment = "deny all unmatched";
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

  policyName = primitives.identifier;

  policyVerdict = lib.types.enum [
    "accept"
    "drop"
  ];

  policyComment = primitives.comment;

  policy = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = policyName;
          default = name;
          example = "lan-to-wan";
          description = ''
            The policy's name. Defaults to the attribute name in
            the enclosing `policies` attrset, e.g.
            `policies.lan-to-wan.name == "lan-to-wan"`.
          '';
        };

        from = lib.mkOption {
          type = zoneNames;
          example = [ "lan" ];
          description = ''
            Source zones for the policy — non-empty. Each entry
            is either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`); resolution
            is enforced at module level, not by the type.
          '';
        };

        to = lib.mkOption {
          type = zoneNames;
          example = [ "wan" ];
          description = ''
            Destination zones for the policy. Same shape rules as
            `from`.
          '';
        };

        verdict = lib.mkOption {
          type = policyVerdict;
          example = "accept";
          description = ''
            Default verdict for the `(from, to)` pair when no
            filter matches. Either `"accept"` or `"drop"`. Same
            enum as the nftables chain-level policy
            (`nftypes.types.policy`), used here at the per-pair
            level.
          '';
        };

        comment = lib.mkOption {
          type = policyComment;
          default = null;
          example = "LAN can reach the internet";
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
    policyName
    policyVerdict
    policyComment
    policy
    ;
}
