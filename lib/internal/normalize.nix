/*
  internal/normalize — Phase 1 of the compile pipeline, exposed
  under `nftzones.internal.normalize`.

  Lowers nodes into zones, resolves wildcards in rule groups'
  `from` / `to`, and runs cross-reference validations to produce a
  single normalized table value consumed by downstream phases
  (expand, dispatch+sort, emit).

  Pipeline pattern: each phase takes `{ table; ctx }` and
  returns the same shape. `table` is the original
  `nftzones.types.table` value and stays *untouched* through the
  pipeline; phases only contribute keys to `ctx`. The
  orchestrator (`normalizeTable`) pipes the phases and then
  assembles the final normalized table from `table` + `ctx`.

  Phase pipeline:

      { table; ctx = { errors = [ ]; warnings = [ ]; }; }
        ↓ convertNodesToZones           ctx.mergedZones
        ↓ computeChildrenOf             ctx.childrenOf
        ↓ computeZoneSets               ctx.zoneSets
        ↓ computeRootZoneNames          ctx.rootZoneNames
        ↓ collectAllZoneNames           ctx.allZoneNames
        ↓ expandWildcardZones           ctx.expandedGroups
        ↓ resolvePriorities             ctx.resolvedPriorities
        ↓ collectZoneRefs               ctx.zoneRefs
        ↓ checkParentRefs               ctx.errors   (appends)
        ↓ checkParentCycles             ctx.errors   (appends)
        ↓ checkNameCollisions           ctx.errors   (appends)
        ↓ checkNameKeyMismatch          ctx.errors   (appends)
        ↓ checkSettings                 ctx.errors   (appends)
        ↓ checkZoneRefs                 ctx.errors   (appends)
        ↓ checkZoneMatchable            ctx.errors   (appends)
        ↓ checkChainOverridePlacement   ctx.errors   (appends)
        ↓ checkChainPlacement           ctx.errors   (appends)
        ↓ checkRpfilterOverride         ctx.warnings (appends)
        ↓ checkChainOverrideSemantics   ctx.warnings (appends)
        ↓ checkExtraSectionFields       ctx.warnings (appends)
        ↓ checkWildcardZoneMix          ctx.warnings (appends)
        ↓ checkNodeAddresses            ctx.errors   (appends)
        ↓ checkNatBodies                ctx.errors   (appends)
        ↓ checkPolicyUniqueness         ctx.errors   (appends)
        ↓ checkSetNameCollisions        ctx.errors   (appends)
        ↓ checkInterfaceOverlap         ctx.errors   (appends)
        ↓ checkCidrOverlap              ctx.errors   (appends)
        ↓ checkCrossAxisOverlap         ctx.warnings (appends)
        ↓ checkObjectRefs               ctx.errors   (appends)
      { table;
        ctx = {
          mergedZones; zoneSets; childrenOf; rootZoneNames;
          allZoneNames; expandedGroups; resolvedPriorities;
          zoneRefs; errors; warnings;
        };
      }

  Output: `normalizeTable` returns the final pipeline context
    `{ table; ctx }` directly — no assembly. `table` is the
    untouched user input; `ctx` contains everything Phase 1
    computed. Downstream phases (Phase 2 expand, Phase 3 dispatch,
    Phase 4 emit) consume both. The final nftables table shape is
    assembled at Phase 4.

  Path stability: `collectZoneRefs` walks the *original* table.
  Reference paths in error messages therefore point at the user's
  input slot, not at indices in the post-expansion list.

  Wired into the surface from `lib/internal/default.nix`.

  Output shape note: lowered nodes are completed to the full
  `nftzones.types.zone` submodule shape (`name`, `parent`,
  `interfaces`, `cidrs`, `matchOverride`), mirroring the
  submodule's defaults. Declared zones already have this shape
  from submodule evaluation, so `ctx.mergedZones` is uniformly
  shaped — downstream phases can consume it without re-evaluation.

  Per-function docstring convention used throughout this file
  (and `internal/expand.nix`, `internal/dispatch.nix`,
  `internal/emit.nix`): each `===== fnName =====` section uses
  `Reads:` / `Writes:` lines naming the ctx and table fields the
  function consumes and produces. Pure leaf helpers (e.g. in
  `internal/zone.nix`, `internal/placement.nix`) use `Inputs:` /
  `Output:` instead, since they don't touch the pipeline ctx.
  The two-form split is intentional: phase orchestrators thread
  `{ table; ctx }`, so listing `Reads:` / `Writes:` clarifies
  which ctx fields the orchestrator touches; leaves take and
  return ordinary values.

  ===== computeZoneSets =====

  Reads:  ctx.mergedZones, ctx.childrenOf
  Writes: ctx.zoneSets

  Folds `internal.zone.genSets` over every merged zone. Each
  zone's emitted sets contain the union of its own
  interfaces/CIDRs plus every descendant's (transitive); see
  `internal.zone.genSets` for the rationale. Depends on
  `ctx.childrenOf` so it runs after `computeChildrenOf` in the
  pipeline.

  The resulting attrset is the single source of truth for
  zone-derived set names and bodies, consumed by:
    - `checkSetNameCollisions` (just keys)
    - `checkObjectRefs` (just keys, for the resolution union)
    - Phase 4 emit (full bodies, for `assembleOutput`)

  Materializing once in Phase 1 avoids redundant evaluation in
  three downstream consumers.

  ===== convertNodesToZones =====

  Reads:  table.zones, table.nodes
  Writes: ctx.mergedZones

  Lowers each node via `node.toZone`, completes it to the full
  `nftzones.types.zone` submodule shape (filling in `name`,
  `matchOverride` defaults), then merges into the declared zones.
  Result is a uniformly-shaped attrset.

  ===== checkParentRefs =====

  Reads:  ctx.mergedZones, table.settings.localZone
  Writes: ctx.errors (appends)

  Verifies every non-null `zone.parent` resolves to a key in
  `ctx.mergedZones`. The `localZone` sentinel is forbidden as a
  parent — it isn't a real zone, has no ingress match, and can't
  participate in chain dispatch. Each error is
  `lib.nameValuePair "zoneParentUnknown" <message>` for unresolved
  parents, or `"zoneParentLocalZone" <message>` for the localZone
  case.

  ===== checkParentCycles =====

  Reads:  ctx.mergedZones
  Writes: ctx.errors (appends)

  Walks each zone's parent chain; if a name is revisited within
  the same walk, emits a cycle error. Each cycle is canonicalized
  by rotating its node list so the lex-smallest member leads,
  then formatted — so the same cycle discovered from different
  starting points produces one error per cycle rather than one
  per starting point.

  Each error is `lib.nameValuePair "zoneParentCycle" <message>`
  with the cycle path joined by `" → "`.

  ===== computeChildrenOf =====

  Reads:  ctx.mergedZones
  Writes: ctx.childrenOf

  Inverse map of `parent`: for each parent name that appears in
  any `zone.parent` field, lists the children that point at it.
  Roots (zones with `parent == null`) are not present in
  `childrenOf`'s keys; consumers read with `or [ ]`. Children
  lists are alphabetically sorted for stable jump emission order
  in Phase 4 emit.

  ===== computeRootZoneNames =====

  Reads:  ctx.mergedZones, table.settings.localZone
  Writes: ctx.rootZoneNames

  Computes the list of root zones: zones in `mergedZones` whose
  `parent == null`, plus the `localZone` sentinel. Used in two
  places:
    - Wildcard from-side expansion (`from = [ "all" ]`) substitutes
      this list rather than every zone, since descendants reach
      traffic via parent dispatch.
    - Phase 4 emit's `mkBaseChain` jump-rule construction emits
      base-chain jumps only for root from-zones whose subtree has
      content for the relevant to-zone.

  ===== checkNameCollisions =====

  Reads:  table.zones, table.nodes
  Writes: ctx.errors (appends)

  Detects names declared as both a zone and a node — node-to-zone
  lowering would silently overwrite the zone otherwise. Each error
  is `lib.nameValuePair "zoneNameCollision" <message>`.

  ===== checkNameKeyMismatch =====

  Reads:  table.{zones,nodes,filters,policies,snats,dnats,sroutes,
          droutes} (per `keyedNameGroups`)
  Writes: ctx.errors (appends)

  Guards the `name == <attribute key>` invariant for every object
  that lives in a keyed attrset. The `name` sub-option on these
  types dropped `readOnly` so evaluated submodules stay copy-safe
  (copying one into another `attrsOf <type>` option no longer
  re-defines a read-only field — see the type modules under
  `lib/types/`). `name` still defaults to the enclosing key, but a
  user can now set it explicitly, which would desync it from the
  key the pipeline keys everything off: dispatch sort and reference
  resolution, generated set names, and the paths in these very
  error messages all derive from the attr key, while external
  introspection (nix-topology, `deepSeq`) reads `.name`. Flagging
  the divergence makes the misuse fail loudly here instead of
  silently splitting the two.

  The table type is not covered — it has no enclosing key by the
  time the pipeline sees it (`compile` receives an already-
  evaluated value). Its `name == key` invariant is instead kept by
  the module / `mkTable` boundary, which overrides the table's
  `name` with the real `networking.nftzones.tables` attr key. An
  `apply` on `types.table`'s `name` couldn't stand in: it sees the
  lexical submodule key, which for a standalone / facade table is
  the option path, not the tables key it compiles under.

  Each error is `lib.nameValuePair "nameKeyMismatch" <message>`.

  ===== collectAllZoneNames =====

  Reads:  ctx.mergedZones, table.settings.localZone
  Writes: ctx.allZoneNames

  Computes the in-scope zone-name list — declared zones, lowered
  nodes, and `settings.localZone`. Consumed by both
  `expandWildcardZones` and `checkZoneRefs`.

  ===== expandWildcardZones =====

  Reads:  ctx.allZoneNames, table.{filters,...,droutes},
          table.settings.wildcardZone
  Writes: ctx.expandedGroups

  Produces the wildcard-expanded `from` / `to` per
  (group, entry, direction). Substitution + dedup is inlined as a
  local helper since this is the only consumer.

  Output shape:
    expandedGroups = {
      filters  = { <entry-name> = { from = [...]; to = [...]; }; ... };
      policies = { ... };
      snats    = { ... };
      dnats    = { <entry-name> = { from = [...]; }; ... };
      sroutes  = { <entry-name> = { from = [...]; }; ... };
      droutes  = { <entry-name> = { to   = [...]; }; ... };
    };

  ===== resolvePriorities =====

  Reads:  table.{filters, snats, dnats, sroutes, droutes}
  Writes: ctx.resolvedPriorities

  Resolves each entry's `priority` (which is `either int symbol`)
  to a plain int via `internal.priority.resolvePriority`.
  Stored per-group, per-entry. Consumed by Phase 3 (dispatch + sort)
  so sorting compares ints, not mixed values. Policies skip this
  phase because they don't carry a `priority` field — they are
  always tail rules.

  Output shape:
    resolvedPriorities = {
      filters = { <entry-name> = <int>; … };
      snats   = { <entry-name> = <int>; … };
      dnats   = { <entry-name> = <int>; … };
      sroutes = { <entry-name> = <int>; … };
      droutes = { <entry-name> = <int>; … };
    };

  ===== collectZoneRefs =====

  Reads:  table.{filters,...,droutes,nodes,settings.wildcardZone}
  Writes: ctx.zoneRefs

  Walks the *original* table and emits one record per zone-name
  reference, skipping wildcard placeholders (those are not
  unresolved references — they're a directive). Paths use
  user-input slot indices.

  Record shapes:
    - Group-side ref:  `{ zone; path; direction; }`
                       (`direction` ∈ `{ "from" "to" }`)
    - Node parent ref: `{ zone; path; }` (no `direction`)

  `direction` lets `checkZoneMatchable` know which side of the
  zone's `matchOverride` (and raw `interfaces` / `cidrs`) to
  validate against.

  ===== checkSettings =====

  Reads:  table.settings.{wildcardZone, localZone}, ctx.mergedZones
  Writes: ctx.errors (appends)

  Sanity checks on the settings-driven zone names:
    - `settings.wildcardZone` and `settings.localZone` must differ
      (otherwise dispatch and wildcard expansion conflict).
    - Neither may shadow a declared zone or node name (the declared
      name would be unreachable by user rules).
  Each error is `lib.nameValuePair "settingsConflict" <message>`.

  ===== checkZoneRefs =====

  Reads:  ctx.zoneRefs, ctx.allZoneNames
  Writes: ctx.errors (appends)

  Verifies every collected zone reference resolves to a known
  zone (declared zone, lowered node, or `settings.localZone`).
  Each error is `lib.nameValuePair "invalidZoneRef" <message>`.

  ===== checkZoneMatchable =====

  Reads:  ctx.zoneRefs, ctx.mergedZones, table.settings.localZone
  Writes: ctx.errors (appends)

  Verifies that every group-side zone reference (`from` / `to` on
  filter / policy / snat / dnat / sroute / droute entries) hits a
  zone whose match is non-empty *on the side actually used*:
  `from` → ingress, `to` → egress.

  Inspects raw `zone.interfaces` / `cidrs` / `matchOverride`
  directly. Phase 4 emit reads the same raw fields via
  `internal.zone.genSets`.

  Without this check, a zone declared as `zones.foo = { };` (empty
  interfaces, empty CIDRs, no `matchOverride`) — or one with an
  asymmetric `matchOverride` that populates only one side — would
  silently produce unconditional jumps in Phase 4, almost certainly
  not what the user wanted.

  Skipped:
    - Refs without `direction` (node parent refs — naming, not
      matching).
    - Refs to `settings.localZone` (sentinel, no `mergedZones`
      entry by design — Phase 4 skips that side's match too).
    - Refs to unknown zones (already flagged by `checkZoneRefs`,
      no need to double-error).

  Each error is `lib.nameValuePair "zoneNotMatchable" <message>`.

  ===== checkChainOverridePlacement =====

  Reads:  ctx.expandedGroups, ctx.mergedZones,
          table.{filters, snats, dnats, settings.localZone}
  Writes: ctx.errors (appends)

  Verifies that filter / snat / dnat entries with a `chain`
  override land at a hook where their `from` / `to` zones can
  actually be matched. Without this check, an entry overridden to
  e.g. `(prerouting, raw)` with a `to` zone that's interface-only
  would silently emit a jump *without* any to-direction constraint
  (oifname is unavailable in prerouting), broadening the entry's
  scope far beyond what the user wrote.

  A zone direction is reachable at hook H if any of:
    - the zone is `localZone` (always wildcard);
    - `zone.cidrs` is non-empty (addr matching always works);
    - `zone.matchOverride.<side>.{ipv4,ipv6,extra}` has a
      contributing section (always reachable — these sections are
      hook-agnostic by construction);
    - `zone.matchOverride.<side>.interfaces` is contributing
      AND the relevant interface field is valid at H (the
      interfaces section is treated as iif/oif content by
      convention);
    - `zone.interfaces` is non-empty AND the relevant interface
      field (`iifname` for `from`, `oifname` for `to`) is valid
      at H. `oifname` validity uses
      `nftypes.compatibility.hooksWithOifname`; `iifname` is
      valid at every hook except `output`.

  "Contributing" means the section is non-null AND non-empty.

  Operates on `ctx.expandedGroups` so wildcard expansions like
  `from = [ "all" ]` are checked per resolved zone.

  Each error is `lib.nameValuePair "chainOverrideUnreachable"
  <message>`.

  ===== checkPolicyUniqueness =====

  Reads:  ctx.expandedGroups.policies
  Writes: ctx.errors (appends)

  At most one policy may apply per `(from, to)` cell after
  expansion. A policy entry like `from = [ "all" ]; to = [ "wan" ]`
  fans out to a cell per in-scope source zone; if a second, more
  specific policy targets one of those same `(from, to)` pairs,
  the resulting nftables ruleset's tail rule for that pair would
  have an undefined winner. This validator catches the conflict
  at compile time by enumerating `(entryName, from, to)` triples
  from `ctx.expandedGroups.policies` and flagging any `(from, to)`
  pair claimed by more than one entry.

  Each error is `lib.nameValuePair "policyConflict" <message>`,
  with the message naming the `(from, to)` pair and every entry
  whose expansion produced a cell for it.

  ===== checkSetNameCollisions =====

  Reads:  table.objects.sets, ctx.mergedZones
  Writes: ctx.errors (appends)

  Catches collisions between user-declared `objects.sets.<name>`
  and auto-generated zone-derived set names (`<zone>_iifs` /
  `<zone>_v4` / `<zone>_v6` from `internal.zone.genSets`). Phase 4
  emit merges the two namespaces under `body.sets` and the user's
  body wins on collision — silently overwriting the zone-derived
  set, breaking every jump rule that referenced it.

  Runs before `checkObjectRefs` so that validator can resolve
  refs against the union of both namespaces without ambiguity:
  by the time `checkObjectRefs` runs, no collision exists.

  Each error is `lib.nameValuePair "setNameCollision" <message>`.

  ===== checkInterfaceOverlap =====

  Reads:  ctx.mergedZones
  Writes: ctx.errors (appends)

  Two distinct zones declaring the same interface produce
  ambiguous dispatch — packets matching `@<zoneA>_iifs` also
  match `@<zoneB>_iifs`, and whichever zone's jump fires first
  wins. The losing zone's rules never apply, silently breaking
  the intended policy.

  Pair-wise comparison over every (zoneName, iface) pair from
  `ctx.mergedZones`. Skips pairs whose zones are in an
  ancestor/descendant relation (parent/child sharing an
  interface is intentional — child traffic is dispatched into
  the parent's chain first, then the parent's chain dispatches
  to the child). Same-zone duplicates in the `interfaces` list
  are also flagged as a separate misconfiguration class.

  Each error is `lib.nameValuePair "interfaceOverlap" <message>`.

  ===== checkCidrOverlap =====

  Reads:  ctx.mergedZones
  Writes: ctx.errors (appends)

  Same ambiguous-dispatch failure mode as `checkInterfaceOverlap`,
  for CIDR prefixes. Pair-wise comparison over every
  (zoneName, cidr) entry from `ctx.mergedZones`. Skips zone pairs
  in an ancestor/descendant relation — a child zone's CIDR is
  intentionally inside its parent's (the canonical case is a
  node lowered into its parent zone, e.g. `web-server` with
  address `10.0.0.5` inside `dmz` with `10.0.0.0/24`).

  Family-aware via `libnet.cidr.overlaps`: v4 vs v6 prefixes
  always return false. Intra-zone overlaps (e.g.
  `cidrs = [ "10.0.0.0/24" "10.0.0.0/28" ]`) are also flagged
  as a separate misconfiguration class.

  Each error is `lib.nameValuePair "cidrOverlap" <message>`.

  ===== checkCrossAxisOverlap =====

  Reads:  ctx.mergedZones
  Writes: ctx.warnings (appends)

  Warns when two distinct zones may match the same packet across
  *different* matching axes — one zone bound by interface, the
  other by CIDR. `checkInterfaceOverlap` and `checkCidrOverlap`
  only compare same-axis pairs (iface↔iface, cidr↔cidr); a packet
  from `10.0.0.5` arriving on `eth0` matches both
  `zone-iface = { interfaces = [ "eth0" ]; }` and
  `zone-cidr = { cidrs = [ "10.0.0.0/24" ]; }`, but neither
  same-axis validator flags it.

  When both zones appear in dispatch rules in the same chain, the
  jump rules fire in alphabetical sub-chain-key order (a
  side-effect of `lib.mapAttrs` enumeration). The losing zone's
  rules are silently shadowed. Renaming `zone-iface` to
  `aaa-iface` flips the behavior. Verified PoC: an SSH-allow on
  the iface-zone is shadowed by a drop on the cidr-zone because
  the cidr-zone sorts first.

  Pair-wise comparison. Classifies each zone by its effective
  dispatch axes: its own raw fields plus every strict ancestor's.
  Two grounds, one structural and one declarative:

  Structural — from-side dispatch is hierarchical. Phase 4's
  `mkRootJumpRules` emits base-chain jumps only for root *from*
  zones, and `mkChildDispatchJumpRules` reaches from-side
  descendants through their ancestors' sub-chains, so every
  ancestor's own match ANDs into the path before the descendant's
  own match applies. A CIDR-only node lowered into an
  interface-bound parent is effectively interface-and-CIDR bound
  on that side. To-side dispatch is flat: a descendant referenced
  as `to` is gated at the base chain by its own sections alone
  (ancestor content never flows down into the `@<zone>_*` sets),
  so a cross-axis packet can still shadow there — e.g. a packet
  egressing the unrelated zone's interface toward the node's
  address matches both jump gates.

  Declarative — parenting states intent. A zone declared (or
  lowered) under an ancestor is a deliberate refinement of that
  ancestor's network, so it cannot be the *accidental* split of an
  unrelated zone this audit hunts; the same reading is why
  `checkInterfaceOverlap` / `checkCidrOverlap` skip related pairs.
  The residual to-side shadowing above is accepted: warning on it
  would re-flag every node against every unrelated interface-only
  zone — the false positive effective-axis classification exists
  to remove.

  Flags any pair where one effective path is *strictly*
  interface-only and the other is *strictly* CIDR-only (vice
  versa), excluding pairs in an ancestor/descendant relation as a
  belt-and-braces guard. Roots reduce to their own raw fields, so
  the original split-root PoC remains flagged. Multi-axis zones
  are not flagged: they're the typical real-world pattern ("lan =
  eth1 plus 10.0.0.0/24") rather than the audit's
  accidentally-split-zone failure mode. A consequence: siblings
  under one parent go unflagged even when their own axes are
  split — the CIDR child inherits the shared ancestor's interface
  axis. Key-order shadowing can still occur among the
  child-dispatch jumps inside the ancestor's sub-chain; a finer
  model would compare axes accumulated below the deepest common
  ancestor (it degenerates to this one for unrelated roots).
  Accepted for now as a rare pattern in a warning-only audit.

  A zone must contribute at least one own raw axis to participate.
  Empty grouping zones stay unclassified: their dispatch variants
  come from descendant-inherited sections, while any overlap from
  an ancestor's own gate is already reported against that ancestor.
  Treating the grouping zone as single-axis would duplicate that
  warning under a misleading zone name.

  matchOverride sections are not inspected — users who replace the
  auto match path have opted out of the auto axis and are
  responsible for their own overlap audit. The flag fires on the
  bare `zone.interfaces` / `zone.cidrs` content only.

  Each warning lists the two zone names, the axes involved, and
  the recommended action (restructure into a single axis, or use
  hierarchy if one zone is a refinement of the other).

  ===== checkObjectRefs =====

  Reads:  table.{filters,snats,dnats,sroutes,droutes}.<entry>.rule,
          ctx.mergedZones.<zone>.matchOverride.{ingress,egress},
          table.objects.<kind>.<name> (full bodies, recursively),
          table.objects.<kind> (key list, for resolution)
  Writes: ctx.errors (appends)

  Walks every place where a user can supply nftables-DSL content
  with named refs:
    - entry rule bodies (all five rule groups)
    - non-null zone matchOverride content (ingress + egress)
    - object bodies (sets / maps may carry refs in element-
      attached stateful statements via `dsl.expr.elem { val;
      stmt; }`; other object kinds are config-only leaves and
      contribute no refs)

  Each ref is resolved against `table.objects.<kind>` (plus
  zone-derived set names for `kind == "sets"`). Unknowns become
  `objectRefUnknown` errors with the source path; users see
  typos at compile time instead of at `nft load` time.

  Not covered: chain refs from raw `dsl.jump <name>` /
  `dsl.goto <name>` inside rule bodies. nftzones generates chain
  names internally (`<hook>-at-<priority>__<key>`) and does not
  document them as a stable surface, so manually-written jumps
  to those names are not validated. See follow-up #1 in
  `docs/compile-pipeline.md` for the design discussion.

  Resolves names against the union of two namespaces:
    - `table.objects.<kind>` keys (user-declared named objects)
    - For `kind == "sets"` only: predictable zone-derived set
      names (`<zone>_iifs` / `<zone>_v4` / `<zone>_v6`) emitted
      by Phase 4. This lets users write raw `match` clauses
      against zone membership when `from` / `to` mechanics
      aren't expressive enough — see open question 6 (decision
      (a)) in `docs/compile-pipeline.md`.

  Each error is `lib.nameValuePair "objectRefUnknown" <message>`.

  ===== normalizeTable =====

  Input:  A `nftzones.types.table` value.

  Output: `{ table; ctx }` — the pipeline context. `table` is
          the original input; `ctx` carries every artifact
          Phase 1 computed (`mergedZones`, `allZoneNames`,
          `expandedGroups`, `zoneRefs`, `errors`). Consumed by
          downstream phases.

  Errors: `ctx.errors` is a list of `{ name; value; }` records
          where `name` is the error tag (e.g. `"zoneNameCollision"`,
          `"invalidZoneRef"`) and `value` is the human-readable
          message. If non-empty after the pipeline, throws a single
          aggregated message listing every error.
*/
{ inputs, internal }:
let
  inherit (inputs) lib libnet nftypes;
  inherit (internal.node) toZone;
  inherit (internal.zone) genSets getActiveMatchOverrides;
  inherit (internal.placement) walkParents hooksWithIifname;

  /*
    Build the pipeline's initial `{ table; ctx }` from a fresh
    table value. The `ctx` is seeded with empty `errors` and
    `warnings` lists so validating phases can append
    unconditionally without `or [ ]` defensiveness. Errors abort
    the build via `throw`; warnings surface via `lib.warn` and
    let evaluation continue.
  */
  mkInitialState = table: {
    inherit table;
    ctx = {
      errors = [ ];
      warnings = [ ];
    };
  };

  /*
    Maps a group-side direction (`from` / `to`) to the zone's
    matchOverride side it consults. `from` matches inbound
    packets → ingress; `to` matches outbound → egress. Used by
    `checkChainOverridePlacement` and `checkZoneMatchable`.
  */
  directionToSide = {
    from = "ingress";
    to = "egress";
  };

  # Rule-bearing groups paired with the direction fields each one
  # carries (`from` and/or `to`). Single source of truth for the
  # per-group direction config — `expandWildcardZones`,
  # `resolvePriorities`, `checkChainOverridePlacement`, and
  # `collectZoneRefs` all consume it. Adding a new group means
  # updating this one constant; previously the same per-group
  # mapping was open-coded across three call sites.
  groupDirections = {
    filters = [
      "from"
      "to"
    ];
    policies = [
      "from"
      "to"
    ];
    snats = [
      "from"
      "to"
    ];
    dnats = [ "from" ];
    sroutes = [ "from" ];
    droutes = [ "to" ];
  };

  groupNames = builtins.attrNames groupDirections;

  # Subset of `groupNames` whose entry types expose a `chain`
  # override field (filters / snats / dnats). Sroutes, droutes,
  # policies have fixed placements with no override path.
  chainOverrideGroups = [
    "filters"
    "snats"
    "dnats"
  ];

  collectAllZoneNames =
    { table, ctx }:
    let
      allZoneNames = (builtins.attrNames ctx.mergedZones) ++ [ table.settings.localZone ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit allZoneNames;
      };
    };

  convertNodesToZones =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        mergedZones = table.zones // lib.mapAttrs (_: toZone) table.nodes;
      };
    };

  computeZoneSets =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        zoneSets = lib.foldlAttrs (
          acc: name: _zone:
          acc // genSets ctx.mergedZones ctx.childrenOf name
        ) { } ctx.mergedZones;
      };
    };

  /*
    `parentOf zone` reads `zone.parent or null` — accommodating
    raw test fixtures that bypass the type system. Submodule-
    evaluated zones always have `parent` defaulted to null.
  */
  parentOf = zone: zone.parent or null;

  /*
    Are zones `a` and `b` in an ancestor/descendant relation in
    `mergedZones`? True iff one is in the other's strict ancestor
    chain. Used by overlap validators to skip pairs whose overlap
    is intentional (parent CIDR contains child CIDR). Strict
    ancestor walks live in `internal.placement.walkParents`.
  */
  relatedByHierarchy =
    mergedZones: a: b:
    builtins.elem a (walkParents mergedZones b) || builtins.elem b (walkParents mergedZones a);

  checkParentRefs =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones;

      newErrors = lib.foldlAttrs (
        acc: zoneName: zone:
        let
          p = parentOf zone;
        in
        if p == null then
          acc
        else if p == localZone then
          acc
          ++ [
            (lib.nameValuePair "zoneParentLocalZone" "zones.${zoneName}.parent is '${p}' (the localZone sentinel) — localZone cannot be a parent")
          ]
        else if !(mergedZones ? ${p}) then
          acc
          ++ [
            (lib.nameValuePair "zoneParentUnknown" "zones.${zoneName}.parent references unknown zone '${p}'")
          ]
        else
          acc
      ) [ ] mergedZones;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkParentCycles =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      indexOf =
        needle: list:
        let
          matches = builtins.filter (e: e.v == needle) (lib.imap0 (i: v: { inherit i v; }) list);
        in
        (builtins.head matches).i;

      /*
        Walk the parent chain starting at `start`. Returns the
        cycle proper (just the cycle members, no leading tail and
        no closing duplicate) iff a cycle is found, empty list
        otherwise. The walk stops at unresolved or null parents —
        those are handled by `checkParentRefs` and are not cycles.
      */
      walkChain =
        start:
        let
          step =
            visited: name:
            let
              zone = mergedZones.${name} or null;
              parent = if zone == null then null else parentOf zone;
            in
            if parent == null || !(mergedZones ? ${parent}) then
              [ ]
            else if builtins.elem parent visited then
              # Drop the leading tail (anything before parent's
              # first occurrence) so callers see only the cycle
              # members.
              lib.drop (indexOf parent visited) visited
            else
              step (visited ++ [ parent ]) parent;
        in
        step [ start ] start;

      /*
        Rotate `nodes` so the lex-smallest member leads. Two
        walks of the same cycle (e.g., `[a, b, c]` and `[b, c, a]`)
        canonicalize to the same list, so `lib.unique` collapses
        them after formatting.
      */
      canonicalRotation =
        nodes:
        let
          minNode = lib.foldl' lib.min (builtins.head nodes) nodes;
          minIdx = indexOf minNode nodes;
        in
        (lib.drop minIdx nodes) ++ (lib.take minIdx nodes);

      formatCycle = nodes: lib.concatStringsSep " → " (nodes ++ [ (builtins.head nodes) ]);

      cycles = lib.pipe (builtins.attrNames mergedZones) [
        (map walkChain)
        (builtins.filter (chain: chain != [ ]))
        (map canonicalRotation)
        (map formatCycle)
        lib.unique
      ];

      newErrors = map (msg: lib.nameValuePair "zoneParentCycle" "zone parent cycle: ${msg}") cycles;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  computeChildrenOf =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      childrenOf = lib.mapAttrs (_: lib.sort (a: b: a < b)) (
        lib.foldlAttrs (
          acc: zoneName: zone:
          let
            p = parentOf zone;
          in
          if p == null then
            acc
          else
            acc
            // {
              ${p} = (acc.${p} or [ ]) ++ [ zoneName ];
            }
        ) { } mergedZones
      );
    in
    {
      inherit table;
      ctx = ctx // {
        inherit childrenOf;
      };
    };

  computeRootZoneNames =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones;

      rootsFromZones = lib.pipe mergedZones [
        (lib.filterAttrs (_: zone: parentOf zone == null))
        builtins.attrNames
      ];

      rootZoneNames = rootsFromZones ++ [ localZone ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit rootZoneNames;
      };
    };

  expandWildcardZones =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;
      inherit (ctx) allZoneNames rootZoneNames;

      /*
        From-side wildcard expands to root zones only: descendants
        receive traffic via parent dispatch (Phase 4 emits child
        sub-chain jumps inside each parent's sub-chain). Expanding
        to every zone would emit redundant cells in every leaf.

        To-side wildcard keeps the full zone list because to-side
        hierarchy is not modelled — `to = [ "all" ]` means "any
        destination zone" and each unique destination needs its
        own sub-chain.
      */
      expandFrom =
        zones: lib.unique (lib.concatMap (z: if z == wildcardZone then rootZoneNames else [ z ]) zones);
      expandTo =
        zones: lib.unique (lib.concatMap (z: if z == wildcardZone then allZoneNames else [ z ]) zones);

      expandDirection =
        direction: entry: if direction == "from" then expandFrom entry.from else expandTo entry.to;

      expandEntry =
        directions: entry: lib.genAttrs directions (direction: expandDirection direction entry);

      expandGroup = directions: lib.mapAttrs (_: expandEntry directions);

      expandedGroups = lib.mapAttrs (group: dirs: expandGroup dirs table.${group}) groupDirections;
    in
    {
      inherit table;
      ctx = ctx // {
        inherit expandedGroups;
      };
    };

  resolvePriorities =
    { table, ctx }:
    let
      inherit (internal.priority) resolvePriority;

      resolveGroup = lib.mapAttrs (_: entry: resolvePriority entry.priority);

      # Every group except policies — policies have no `priority`
      # field (they're tail rules with implicit `last` priority).
      priorityGroups = lib.removeAttrs groupDirections [ "policies" ];

      resolvedPriorities = lib.mapAttrs (group: _: resolveGroup table.${group}) priorityGroups;
    in
    {
      inherit table;
      ctx = ctx // {
        inherit resolvedPriorities;
      };
    };

  collectZoneRefs =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;

      collectDirectionRefs =
        groupName: direction: entryName: entry:
        let
          prefix = "${groupName}.${entryName}.${direction}";
        in
        lib.concatLists (
          lib.imap0 (
            i: zone:
            if zone == wildcardZone then
              [ ]
            else
              [
                {
                  inherit zone direction;
                  path = "${prefix}[${toString i}]";
                }
              ]
          ) entry.${direction}
        );

      collectEntryRefs =
        groupName: directions: entryName: entry:
        lib.concatMap (direction: collectDirectionRefs groupName direction entryName entry) directions;

      collectGroupRefs =
        groupName: directions: group:
        lib.concatLists (
          lib.mapAttrsToList (entryName: entry: collectEntryRefs groupName directions entryName entry) group
        );

      collectNodeParentRefs =
        nodes:
        lib.mapAttrsToList (entryName: entry: {
          inherit (entry) zone;
          path = "nodes.${entryName}.zone";
        }) nodes;

      zoneRefs = lib.concatLists [
        (collectGroupRefs "filters" [ "from" "to" ] table.filters)
        (collectGroupRefs "policies" [ "from" "to" ] table.policies)
        (collectGroupRefs "snats" [ "from" "to" ] table.snats)
        (collectGroupRefs "dnats" [ "from" ] table.dnats)
        (collectGroupRefs "sroutes" [ "from" ] table.sroutes)
        (collectGroupRefs "droutes" [ "to" ] table.droutes)
        (collectNodeParentRefs table.nodes)
      ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit zoneRefs;
      };
    };

  checkNameCollisions =
    { table, ctx }:
    let
      collisions = lib.intersectLists (builtins.attrNames table.zones) (builtins.attrNames table.nodes);
      newErrors = map (
        n:
        lib.nameValuePair "zoneNameCollision" "name collision: '${n}' is declared as both a zone and a node"
      ) collisions;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  # Object groups keyed by attribute name, each entry carrying a
  # key-derived `name`: the two zone-namespace groups (`zones` /
  # `nodes`) plus every rule group. Reusing `groupNames` (derived
  # from `groupDirections`) rather than re-listing the rule groups
  # keeps this in step with that single source of truth — a new rule
  # group is name-checked automatically. The table type is absent by
  # design: it has no enclosing key by the time the pipeline sees it
  # (see `checkNameKeyMismatch`).
  keyedNameGroups = [
    "zones"
    "nodes"
  ]
  ++ groupNames;

  checkNameKeyMismatch =
    { table, ctx }:
    let
      checkGroup =
        group:
        lib.concatLists (
          lib.mapAttrsToList (
            key: obj:
            # `obj.name or key` mirrors the defensive reads elsewhere
            # in this file (`parentOf`): raw fixtures that bypass the
            # type system may omit `name`, and an absent name can't
            # diverge from its key. `obj.name` in the message is only
            # forced when the guard already proved it present and
            # divergent, so this never trips the missing-attr path.
            lib.optional ((obj.name or key) != key) (
              lib.nameValuePair "nameKeyMismatch" (
                "${group}.${key}.name is '${obj.name}' but must equal its "
                + "attribute key '${key}' — the compile pipeline references "
                + "this object by '${key}'. Drop the explicit `name` (it "
                + "defaults to the key) or rename the attribute to '${obj.name}'."
              )
            )
          ) (table.${group} or { })
        );

      newErrors = lib.concatMap checkGroup keyedNameGroups;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  /*
    Reject placements the kernel will refuse, before they reach
    `nft -f`. Each rule group dispatches into a `(hook, priority)`
    pair; combined with `table.family`, the implied chain type
    (via `nftypes.chainTypeFor`) is what the kernel sees. If
    `nftypes.validChainPlacement` says the triple is rejected,
    we error out with the offending placement.

    Catches three failure modes uncovered by the audit:
      - `bridge` snat/dnat — bridge family doesn't support `nat`
        chains at all.
      - `bridge` sroute/droute — bridge has no `mangle` priority,
        so `chainTypeFor` returns null and we surface the gap
        rather than throwing in emit.
      - `route` chain at non-`output` hooks (kernel restriction
        encoded in `hooksByChainType.route = [ "output" ]`).

    Default placements are sourced from `internal.placement`,
    the same module Phase 3 dispatch reads — single source of
    truth for the per-group `(hook, priority)` constants.
  */
  checkChainPlacement =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (table.settings) localZone;
      inherit (nftypes) chainTypeFor validChainPlacement;
      inherit (internal.placement) defaultGroupChainAttrs filterChainPriority;

      /*
        For a filter/policy entry, derive every hook the dispatch
        could land on. Hook depends solely on whether `localZone`
        appears on the from / to side, so a membership check beats
        materializing the full cartesian.
      */
      filterHooks =
        dirs:
        let
          fromHasLocal = builtins.elem localZone dirs.from;
          toHasLocal = builtins.elem localZone dirs.to;
          nonLocalFrom = builtins.length dirs.from > (if fromHasLocal then 1 else 0);
          nonLocalTo = builtins.length dirs.to > (if toHasLocal then 1 else 0);
        in
        lib.optional toHasLocal "input"
        ++ lib.optional fromHasLocal "output"
        ++ lib.optional (nonLocalFrom && nonLocalTo) "forward";

      placementsForEntry =
        group: entryName: entry:
        if (entry.chain or null) != null then
          [
            {
              inherit entryName;
              inherit (entry.chain) hook priority;
            }
          ]
        else if group == "filters" || group == "policies" then
          map (hook: {
            inherit entryName hook;
            priority = filterChainPriority;
          }) (filterHooks ctx.expandedGroups.${group}.${entryName})
        else
          [
            (
              defaultGroupChainAttrs.${group}
              // {
                inherit entryName;
              }
            )
          ];

      placementsForGroup =
        group: lib.concatLists (lib.mapAttrsToList (placementsForEntry group) (table.${group} or { }));

      mkError =
        group: p: reason:
        lib.nameValuePair "invalidChainPlacement" (
          "${group}.${p.entryName} would emit a base chain at "
          + "(family=${family}, hook=${p.hook}, priority=${toString p.priority}) "
          + "— ${reason}"
        );

      classify =
        group: p:
        let
          chainType = chainTypeFor family p.hook p.priority;
        in
        if chainType == null then
          [
            (mkError group p "priority symbol '${toString p.priority}' has no value in family '${family}'")
          ]
        else if !(validChainPlacement family chainType p.hook) then
          [
            (mkError group p
              "kernel rejects chain type '${chainType}' on hook '${p.hook}' for family '${family}'"
            )
          ]
        else
          [ ];

      newErrors = lib.concatMap (
        group: lib.concatMap (classify group) (placementsForGroup group)
      ) groupNames;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  /*
    Warn (don't error) when `settings.rpfilter = true` and a user
    override at `(prerouting, raw)` already claims the slot.
    Phase 4 keeps the user's chain intact and skips synthesizing
    the rpfilter chain — without this warning, the rpfilter rule
    would silently disappear and the user would have no signal
    that their override took precedence.
  */
  checkRpfilterOverride =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (nftypes) priorityNameOf;

      claimsRawPrerouting =
        entry:
        let
          chain = entry.chain or null;
        in
        chain != null && chain.hook == "prerouting" && priorityNameOf family chain.priority == "raw";

      groupClaims = group: lib.any claimsRawPrerouting (lib.attrValues table.${group});

      newWarnings = lib.optional (table.settings.rpfilter && lib.any groupClaims chainOverrideGroups) (
        "settings.rpfilter is enabled but a user chain override "
        + "already claims (prerouting, raw); the synthesized rpfilter "
        + "chain is suppressed and the user-authored chain is used "
        + "as-is. Add `fib saddr . iif oif eq 0 drop` to the override "
        + "manually if you want rpfilter behavior in that chain."
      );
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Soft checks for kernel-valid chain overrides that are
    semantically suspect. checkChainPlacement already rejects
    placements the kernel refuses (e.g. nat at non-nat hooks);
    this validator catches the layer above — placements the
    kernel accepts but the user almost certainly didn't mean.

    Three cases the audit flagged:

      - filter at hook=postrouting: `iifname` reflects the *input*
        device, which after routing may not match user intent
        ("source zone"), especially for locally-originated
        traffic where iifname is "lo" or empty.

      - dnat at hook=output: from-side dispatches on saddr, which
        for output is the local interface address. A from-zone
        bound by a wide CIDR (0/0) would silently rewrite every
        locally-originated packet.

      - snat at priority != srcnat: stateful SNAT must run at
        srcnat (100) so conntrack records the translation. At any
        other priority the rewrite happens but conntrack misses
        it — return traffic breaks.

    All three are warnings (not errors) because each *can* be the
    user's deliberate intent in edge cases.
  */
  checkChainOverrideSemantics =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (nftypes) priorityNameOf;

      entryHasChain = entry: (entry.chain or null) != null;

      mkWarning =
        kind: entryName: msg:
        "${kind}.${entryName}.chain: ${msg}";

      # Filter at postrouting — iifname semantics differ from
      # pre-routing dispatch.
      filterPostroutingWarnings = lib.concatLists (
        lib.mapAttrsToList (
          entryName: entry:
          if entryHasChain entry && entry.chain.hook == "postrouting" then
            [
              (mkWarning "filters" entryName (
                "hook=postrouting is kernel-valid but `iifname` here reflects the "
                + "input device pre-routing, which may not match what `from` zones "
                + "mean (especially for locally-originated traffic where iifname is "
                + "'lo' or empty). Confirm this is intentional, or place the filter "
                + "at the default `(forward|input|output, filter)` instead."
              ))
            ]
          else
            [ ]
        ) (table.filters or { })
      );

      # Dnat at output — from-side at output is local, not external.
      dnatOutputWarnings = lib.concatLists (
        lib.mapAttrsToList (
          entryName: entry:
          if entryHasChain entry && entry.chain.hook == "output" then
            [
              (mkWarning "dnats" entryName (
                "hook=output rewrites locally-originated traffic. The `from` side "
                + "dispatches on saddr, which at output is the local interface "
                + "address — a from-zone with a wide CIDR (e.g. 0.0.0.0/0) would "
                + "silently rewrite every locally-originated packet. Confirm this "
                + "is what you want, or keep the default `(prerouting, dstnat)` "
                + "for external-traffic DNAT."
              ))
            ]
          else
            [ ]
        ) (table.dnats or { })
      );

      # Snat at non-srcnat priority — breaks conntrack.
      snatPriorityWarnings = lib.concatLists (
        lib.mapAttrsToList (
          entryName: entry:
          if entryHasChain entry && priorityNameOf family entry.chain.priority != "srcnat" then
            [
              (mkWarning "snats" entryName (
                "priority='${toString entry.chain.priority}' is not srcnat (100). "
                + "Stateful SNAT must run at the srcnat priority so conntrack records "
                + "the translation; at any other priority the rewrite happens but "
                + "conntrack misses it and return traffic breaks. Either use "
                + "priority='srcnat' (or 100), or accept that this NAT is one-way."
              ))
            ]
          else
            [ ]
        ) (table.snats or { })
      );

      newWarnings = filterPostroutingWarnings ++ dnatOutputWarnings ++ snatPriorityWarnings;
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Reject `snats.<x>.rule.snat = { }` and
    `dnats.<x>.rule.action.dnat = { }` where `addr` is null. nftypes'
    `natBody` lets every field default to `null` (so the user-shape
    validates), but the rendered `snat to` / `dnat to` statement with
    no target is invalid nftables syntax and `nft -f` rejects it at
    activation. Catches the empty-body case here with a clear error
    pointing to `masquerade` / `redirect` as the no-target alternative.
  */
  /*
    Warn when a `matchOverride.<side>.extra` section references
    an interface-typed `meta` field (`iif`, `iifname`, `iifgroup`,
    `iiftype` and the `oif*` counterparts). These belong in the
    `matchOverride.<side>.interfaces` section instead: that
    section is hook-gated correctly by
    `checkChainOverridePlacement` and `mkDirectionVariants` (the
    iif/oif clause is dropped at hooks where the field is
    unavailable). The `extra` section is hook-agnostic by design
    — it's inlined into every variant of every direction the
    zone appears in, regardless of hook. An iif clause in extra
    landing at the `output` hook silently becomes a no-op
    (`iifname` is unavailable there), turning a chain the user
    expected to be restrictive into a permissive one.

    Per-statement check: extract `stmt.match.left.meta.key` (the
    field name) and flag if it's an iif/oif variant. Walks
    only the `extra` section; the `interfaces` / `ipv4` / `ipv6`
    sections are hook-gated already.

    Warning-level (not error) — a user with a config that only
    ever uses the zone at hooks where the field IS valid would
    see a false positive. The warning text names the slot and
    the recommended fix (move to `matchOverride.<side>.interfaces`).
  */
  checkExtraSectionFields =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      interfaceMetaKeys = [
        "iif"
        "iifname"
        "iifgroup"
        "iiftype"
        "oif"
        "oifname"
        "oifgroup"
        "oiftype"
      ];

      sides = [
        "ingress"
        "egress"
      ];

      # nftypes match shape: `{ match = { left = { meta = {
      # key = "iif"; }; }; op; right; }; }`. Returns the meta
      # key if the statement's left side is a `meta` field;
      # null otherwise (payload matches, non-match statements,
      # etc.).
      metaKeyOf = stmt: stmt.match.left.meta.key or null;

      checkBody =
        zoneName: side: body:
        lib.concatLists (
          lib.imap0 (
            i: stmt:
            let
              key = metaKeyOf stmt;
            in
            if key != null && builtins.elem key interfaceMetaKeys then
              [
                (
                  "zones.${zoneName}.matchOverride.${side}.extra[${toString i}] matches on `meta.${key}` — "
                  + "interface fields belong in `matchOverride.${side}.interfaces` instead. The `extra` "
                  + "section is inlined hook-agnostically and would silently become a no-op at hooks "
                  + "where ${key} is unavailable (e.g. iif* at output). The `interfaces` section is "
                  + "hook-gated correctly by `checkChainOverridePlacement` and `mkDirectionVariants`."
                )
              ]
            else
              [ ]
          ) body
        );

      checkSide =
        zoneName: side:
        let
          active = getActiveMatchOverrides mergedZones.${zoneName} side;
        in
        if active ? extra then checkBody zoneName side active.extra else [ ];

      checkZone = zoneName: lib.concatMap (checkSide zoneName) sides;

      newWarnings = lib.concatMap checkZone (builtins.attrNames mergedZones);
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Warn when an entry's `from` or `to` list mixes the wildcard
    zone with explicit zone names — e.g. `from = [ "all" "wan" ]`.
    The wildcard alone already expands to every in-scope zone
    (`expandFrom` / `expandTo` substitute the wildcard sentinel),
    so explicit zones appearing alongside it are either already
    covered (no-op) or, more likely, a typo / leftover from an
    earlier config shape. The user almost certainly meant `[
    "all" ]` alone or `[ "wan" ]` alone, not both.

    Walks the raw `from` / `to` lists before wildcard expansion —
    by the time `expandWildcardZones` runs, the wildcard sentinel
    is gone. Iterates over `groupDirections` for the per-group
    direction set (filters/policies have both, dnats has `from`
    only, droutes has `to` only).

    Warning-level: the behaviour isn't wrong (expansion produces
    the right zone set either way), it's just a misleading config
    shape that suggests user confusion.
  */
  checkWildcardZoneMix =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;

      checkEntryDir =
        groupName: entryName: dir: zones:
        if builtins.elem wildcardZone zones && builtins.length zones > 1 then
          let
            others = builtins.filter (z: z != wildcardZone) zones;
          in
          [
            (
              "${groupName}.${entryName}.${dir}: list contains the wildcard zone "
              + "'${wildcardZone}' alongside explicit zone(s) ${
                lib.concatStringsSep ", " (map (z: "'${z}'") others)
              }. "
              + "The wildcard alone already expands to every in-scope zone — the explicit "
              + "names are either redundant or a leftover. Use `[ \"${wildcardZone}\" ]` "
              + "or list the explicit zones without the wildcard."
            )
          ]
        else
          [ ];

      checkEntry =
        groupName: dirs: entryName: entry:
        lib.concatMap (dir: checkEntryDir groupName entryName dir (entry.${dir} or [ ])) dirs;

      checkGroup =
        groupName: dirs:
        lib.concatLists (lib.mapAttrsToList (checkEntry groupName dirs) (table.${groupName} or { }));

      newWarnings = lib.concatLists (lib.mapAttrsToList checkGroup groupDirections);
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Reject `nodes.<name>.address` shapes with both `ipv4` and
    `ipv6` set to `null`. The type accepts the all-null shape
    (both fields are `nullOr str` defaulting to `null`), but a
    node with no address can't produce any CIDR for its lowered
    zone — `internal.node.toZone` would emit `cidrs = [ ]` and
    the zone would be unmatchable at every direction.

    Surfaced here (rather than at type `apply` time) so the error
    aggregates with the rest of Phase 1's findings instead of
    halting on the first node.
  */
  checkNodeAddresses =
    { table, ctx }:
    let
      newErrors = lib.concatLists (
        lib.mapAttrsToList (
          name: node:
          lib.optional (node.address.ipv4 == null && node.address.ipv6 == null) (
            lib.nameValuePair "nodeAddressMissing" (
              "nodes.${name}: address must set at least one of `ipv4` / `ipv6` — "
              + "a node with no address contributes no CIDR to its lowered zone."
            )
          )
        ) (table.nodes or { })
      );
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkNatBodies =
    { table, ctx }:
    let
      snatErrors = lib.concatLists (
        lib.mapAttrsToList (
          name: entry:
          lib.optional ((entry.rule ? snat) && entry.rule.snat.addr == null) (
            lib.nameValuePair "natBodyMissingAddr" (
              "snats.${name}: rule.snat.addr is null — `snat` requires a target "
              + "address. Use `rule.masquerade = { }` for auto-target via the "
              + "outgoing interface, or set `rule.snat.addr` explicitly."
            )
          )
        ) (table.snats or { })
      );

      dnatErrors = lib.concatLists (
        lib.mapAttrsToList (
          name: entry:
          lib.optional ((entry.rule.action ? dnat) && entry.rule.action.dnat.addr == null) (
            lib.nameValuePair "natBodyMissingAddr" (
              "dnats.${name}: rule.action.dnat.addr is null — `dnat` requires a "
              + "target address. Use `rule.action.redirect = { port = N; }` for "
              + "redirect-to-localhost, or set `rule.action.dnat.addr` explicitly."
            )
          )
        ) (table.dnats or { })
      );

      newErrors = snatErrors ++ dnatErrors;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkSettings =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone localZone;
      zoneNames = builtins.attrNames ctx.mergedZones;

      conflict = msg: lib.nameValuePair "settingsConflict" msg;

      pairConflict = lib.optional (wildcardZone == localZone) (
        conflict "settings.wildcardZone and settings.localZone are both '${wildcardZone}' — they must differ"
      );

      wildcardShadowed = lib.optional (builtins.elem wildcardZone zoneNames) (
        conflict "settings.wildcardZone '${wildcardZone}' collides with a declared zone or node"
      );

      localShadowed = lib.optional (builtins.elem localZone zoneNames) (
        conflict "settings.localZone '${localZone}' collides with a declared zone or node"
      );

      newErrors = pairConflict ++ wildcardShadowed ++ localShadowed;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkPolicyUniqueness =
    { table, ctx }:
    let
      /*
        Enumerate (entryName, from, to) triples from each policy
        entry's expanded directions. A policy with `from = [a b]`
        and `to = [x y]` contributes four triples — one per
        cartesian-product cell.
      */
      triples = lib.concatLists (
        lib.mapAttrsToList (
          entryName: dirs: lib.concatMap (from: map (to: { inherit entryName from to; }) dirs.to) dirs.from
        ) ctx.expandedGroups.policies
      );

      keyOf = t: "(${t.from} → ${t.to})";
      grouped = lib.groupBy keyOf triples;
      duplicates = lib.filterAttrs (_: ts: builtins.length ts > 1) grouped;

      newErrors = lib.mapAttrsToList (
        key: ts:
        lib.nameValuePair "policyConflict" "duplicate policy for ${key}: ${
          lib.concatStringsSep ", " (map (t: t.entryName) ts)
        }"
      ) duplicates;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkZoneRefs =
    { table, ctx }:
    let
      inherit (ctx) zoneRefs allZoneNames;
      invalidZoneRefs = builtins.filter (r: !(builtins.elem r.zone allZoneNames)) zoneRefs;
      allZoneNamesStr = lib.concatStringsSep ", " (lib.sort (a: b: a < b) allZoneNames);
      newErrors = map (
        r:
        lib.nameValuePair "invalidZoneRef" "${r.path} references unknown zone '${r.zone}' (known: ${allZoneNamesStr})"
      ) invalidZoneRefs;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkChainOverridePlacement =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones expandedGroups;

      iifAvailableAtHook = hook: builtins.elem hook hooksWithIifname;
      oifAvailableAtHook = hook: builtins.elem hook nftypes.compatibility.hooksWithOifname;

      ifFieldName = direction: if direction == "from" then "iifname" else "oifname";

      addrFieldName = direction: if direction == "from" then "saddr" else "daddr";

      /*
        For one (zone reference, hook, direction), is the zone
        matchable at that placement? `localZone` and unknown zones
        are skipped (handled by other validators / wildcard
        sentinel).

        With the structured matchOverride, the sections that always
        produce a hook-agnostic clause (`ipv4` / `ipv6` / `extra`)
        make the zone reachable at any hook. The `interfaces`
        section is treated as iif/oif content by convention, so it
        still depends on hook validity.
      */
      reachable =
        zoneName: hook: direction:
        if zoneName == localZone || !(mergedZones ? ${zoneName}) then
          true
        else
          let
            zone = mergedZones.${zoneName};
            side = directionToSide.${direction};
            active = getActiveMatchOverrides zone side;
            ifAvailable = if direction == "from" then iifAvailableAtHook hook else oifAvailableAtHook hook;
          in
          zone.cidrs != [ ]
          || active ? ipv4
          || active ? ipv6
          || active ? extra
          || (active ? interfaces && ifAvailable)
          || (zone.interfaces != [ ] && ifAvailable);

      /*
        Per-group iteration over the groups whose entry types
        expose a `chain` override field. Filter the file-level
        `groupDirections` by `chainOverrideGroups` so sroute /
        droute / policy (no override path) are skipped.
      */
      chainOverrideDirections = lib.filterAttrs (
        g: _: builtins.elem g chainOverrideGroups
      ) groupDirections;

      /*
        Walk one entry and emit a flat record per (direction,
        zoneName) the validator must check. Entries without a
        `chain` override are skipped.
      */
      enumerateEntry =
        groupName: directions: entryName: entry:
        if (entry.chain or null) == null then
          [ ]
        else
          let
            inherit (entry.chain) hook priority;
            expandedDirs = expandedGroups.${groupName}.${entryName};
          in
          lib.concatMap (
            direction:
            map (zoneName: {
              inherit
                groupName
                entryName
                hook
                priority
                direction
                zoneName
                ;
            }) expandedDirs.${direction}
          ) directions;

      enumerateGroup =
        groupName: directions:
        lib.concatLists (
          lib.mapAttrsToList (entryName: enumerateEntry groupName directions entryName) table.${groupName}
        );

      mkError =
        r:
        let
          side = directionToSide.${r.direction};
          addrField = addrFieldName r.direction;
          ifField = ifFieldName r.direction;
          msg =
            "${r.groupName}.${r.entryName}.${r.direction} references zone '${r.zoneName}'"
            + " which has no ${side} match expressible at chain"
            + " (hook=${r.hook}, priority=${toString r.priority})"
            + " — zone has no ${addrField} CIDRs and no hook-agnostic matchOverride.${side} sections"
            + " (ipv4 / ipv6 / extra) set, and ${ifField} is unavailable in ${r.hook}";
        in
        lib.nameValuePair "chainOverrideUnreachable" msg;

      newErrors = lib.pipe chainOverrideDirections [
        (lib.mapAttrsToList enumerateGroup)
        lib.concatLists
        (builtins.filter (r: !(reachable r.zoneName r.hook r.direction)))
        (map mkError)
      ];
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkZoneMatchable =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) zoneRefs mergedZones;

      /*
        A zone is matchable on a given side iff EITHER the user set
        any non-empty override section for that side, OR (in the
        compute path) the zone declares any interfaces or CIDRs.
      */
      isMatchable =
        zone: side: getActiveMatchOverrides zone side != { } || zone.interfaces != [ ] || zone.cidrs != [ ];

      # Skip refs without a `direction` (node parent refs), refs to
      # the localZone sentinel (no `mergedZones` entry by design),
      # and refs to unknown zones (already flagged by checkZoneRefs).
      directionBoundRefs = builtins.filter (
        r: r ? direction && r.zone != localZone && mergedZones ? ${r.zone}
      ) zoneRefs;

      unmatchableRefs = builtins.filter (
        r:
        let
          side = directionToSide.${r.direction};
        in
        !(isMatchable mergedZones.${r.zone} side)
      ) directionBoundRefs;

      newErrors = map (
        r:
        let
          side = directionToSide.${r.direction};
          msg =
            "${r.path} references zone '${r.zone}' which has no ${side} match"
            + " (no interfaces, no CIDRs, and no matchOverride sections set on the ${side} side)";
        in
        lib.nameValuePair "zoneNotMatchable" msg
      ) unmatchableRefs;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkSetNameCollisions =
    { table, ctx }:
    let
      userSetNames = builtins.attrNames table.objects.sets;
      zoneSetNames = builtins.attrNames ctx.zoneSets;

      collisions = lib.intersectLists userSetNames zoneSetNames;

      # Reverse map { setName -> sourceZone } so error messages
      # name the responsible zone. Lazy: never forced when
      # `collisions` is empty (the happy path).
      zoneSetSource = lib.foldlAttrs (
        acc: zoneName: _zone:
        acc // lib.mapAttrs (_: _: zoneName) (genSets ctx.mergedZones ctx.childrenOf zoneName)
      ) { } ctx.mergedZones;

      newErrors = map (
        n:
        let
          sourceZone = zoneSetSource.${n};
          suffix = lib.removePrefix "${sourceZone}_" n;
        in
        lib.nameValuePair "setNameCollision" (
          "objects.sets.${n} collides with the auto-generated set name "
          + "from zone '${sourceZone}' (suffix '${suffix}'); rename one"
        )
      ) collisions;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkInterfaceOverlap =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      /*
        All (zoneName, iface) pairs across every merged zone, in
        zone-then-list order. Pair-wise comparison below flags
        same-iface conflicts.
      */
      allEntries = lib.concatMap (
        zoneName: map (iface: { inherit zoneName iface; }) mergedZones.${zoneName}.interfaces
      ) (builtins.attrNames mergedZones);

      n = builtins.length allEntries;

      /*
        Compare unordered pairs (i, j) with i < j. Flag same
        interface in two cases:
          - same zone (intra-zone duplicate in `interfaces` list)
          - different zones not in ancestor/descendant relation
            (overlap with intentional parent/child sharing skipped)
      */
      pairErrors = lib.concatMap (
        i:
        lib.concatMap (
          j:
          let
            a = builtins.elemAt allEntries i;
            b = builtins.elemAt allEntries j;
            sameZone = a.zoneName == b.zoneName;
            sameIface = a.iface == b.iface;
            shouldFlag = sameIface && (sameZone || !(relatedByHierarchy mergedZones a.zoneName b.zoneName));
          in
          if shouldFlag then
            [
              (lib.nameValuePair "interfaceOverlap" (
                if sameZone then
                  "zone '${a.zoneName}' lists interface '${a.iface}' more than once"
                else
                  "interface '${a.iface}' is claimed by zones '${a.zoneName}' and '${b.zoneName}' (no ancestor/descendant relationship)"
              ))
            ]
          else
            [ ]
        ) (lib.range (i + 1) (n - 1))
      ) (lib.range 0 (n - 1));
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ pairErrors;
      };
    };

  checkCidrOverlap =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      /*
        All (zoneName, cidr-as-string, cidr-parsed) triples across
        every merged zone. Parse is lazy per entry — only forced
        on overlap check below.
      */
      allEntries = lib.concatMap (
        zoneName:
        map (cidrStr: {
          inherit zoneName cidrStr;
          parsed = libnet.cidr.parse cidrStr;
        }) mergedZones.${zoneName}.cidrs
      ) (builtins.attrNames mergedZones);

      n = builtins.length allEntries;

      /*
        Same pair-wise pattern as `checkInterfaceOverlap`. Flag
        overlap when:
          - same zone (intra-zone overlap, e.g. `[ "10.0.0.0/24"
            "10.0.0.0/28" ]`)
          - different zones not in ancestor/descendant relation
        `libnet.cidr.overlaps` is family-aware: v4 vs v6 always
        returns false.
      */
      pairErrors = lib.concatMap (
        i:
        lib.concatMap (
          j:
          let
            a = builtins.elemAt allEntries i;
            b = builtins.elemAt allEntries j;
            sameZone = a.zoneName == b.zoneName;
            shouldCheck = sameZone || !(relatedByHierarchy mergedZones a.zoneName b.zoneName);
          in
          if shouldCheck && libnet.cidr.overlaps a.parsed b.parsed then
            [
              (lib.nameValuePair "cidrOverlap" (
                if sameZone then
                  "zone '${a.zoneName}' has overlapping CIDRs '${a.cidrStr}' and '${b.cidrStr}'"
                else
                  "zone '${a.zoneName}' CIDR '${a.cidrStr}' overlaps zone '${b.zoneName}' CIDR '${b.cidrStr}' (no ancestor/descendant relationship)"
              ))
            ]
          else
            [ ]
        ) (lib.range (i + 1) (n - 1))
      ) (lib.range 0 (n - 1));
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ pairErrors;
      };
    };

  checkCrossAxisOverlap =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      zoneNames = builtins.attrNames mergedZones;
      n = builtins.length zoneNames;

      /*
        Effective axes of a zone's *from-side* dispatch path: its
        own raw fields plus every strict ancestor's. From-side
        descendant dispatch is hierarchical (Phase 4's
        `mkRootJumpRules` emits base-chain jumps for root from-zones
        only; `mkChildDispatchJumpRules` narrows into descendants
        inside ancestor sub-chains), so every ancestor's own match
        ANDs into the packet's path before the zone's own match
        applies — a CIDR-only node lowered into an interface-bound
        parent is effectively interface-AND-address there, the
        canonical `nodes` refinement rather than the
        accidentally-split-zone failure mode this audit hunts.
        To-side dispatch is flat (own sections only, straight from
        the base chain); suppression on that side rests on the
        parent declaration marking the overlap as intentional — see
        the `checkCrossAxisOverlap` module-header block for the full
        rationale and the accepted residual. Roots reduce to their
        own raw fields, keeping the original PoC pair flagged. Empty
        grouping zones remain unclassified because they contribute
        no own axis; their dispatch variants come from inherited
        descendant sections, and ancestor-axis overlap is already
        audited at the ancestor.
      */
      axesOf =
        name:
        let
          own = mergedZones.${name};
          zones = map (z: mergedZones.${z}) ([ name ] ++ walkParents mergedZones name);
        in
        {
          anchored = (own.interfaces or [ ]) != [ ] || (own.cidrs or [ ]) != [ ];
          iface = lib.any (zone: (zone.interfaces or [ ]) != [ ]) zones;
          cidr = lib.any (zone: (zone.cidrs or [ ]) != [ ]) zones;
        };

      # Forced once per zone; the O(n²) pair walk below then reads
      # each classification instead of re-walking the ancestor chain.
      zoneAxes = lib.mapAttrs (name: _: axesOf name) mergedZones;

      ifaceOnly = axes: axes.anchored && axes.iface && !axes.cidr;
      cidrOnly = axes: axes.anchored && axes.cidr && !axes.iface;

      # Pair-wise (i < j) walk. Flag the pair iff one zone is
      # interface-only and the other is CIDR-only — i.e. the user
      # split what looks like one logical zone across two
      # declarations on different axes. `checkInterfaceOverlap` and
      # `checkCidrOverlap` won't catch this by construction.
      crossAxisPair = a: b: (ifaceOnly a && cidrOnly b) || (cidrOnly a && ifaceOnly b);

      pairWarnings = lib.concatMap (
        i:
        lib.concatMap (
          j:
          let
            aName = builtins.elemAt zoneNames i;
            bName = builtins.elemAt zoneNames j;
            a = zoneAxes.${aName};
            b = zoneAxes.${bName};
          in
          if crossAxisPair a b && !(relatedByHierarchy mergedZones aName bName) then
            [
              (
                "zones '${aName}' and '${bName}' may match the same packet across different axes "
                + "(one is interface-bound, the other is CIDR-bound). If both appear in the same "
                + "chain, dispatch order is alphabetical attribute-key order — the losing zone's "
                + "rules are silently shadowed. Restructure both zones onto the same axis, or "
                + "make one a child of the other if it's a refinement."
              )
            ]
          else
            [ ]
        ) (lib.range (i + 1) (n - 1))
      ) (lib.range 0 (n - 1));
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ pairWarnings;
      };
    };

  checkObjectRefs =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;
      inherit (internal.refs) extractRefs;

      /*
        Zone-derived set names cached in `ctx.zoneSets` by
        `computeZoneSets`, also consumed by Phase 4 emit's
        `assembleOutput`.

        Collisions between `objects.sets.<name>` and zone-derived
        names are caught upstream by `checkSetNameCollisions`, so
        the union here is unambiguous when the table reaches this
        validator (or the table is rejected before it gets here).
      */
      zoneSetNames = builtins.attrNames ctx.zoneSets;

      knownNames = {
        counters = builtins.attrNames table.objects.counters;
        quotas = builtins.attrNames table.objects.quotas;
        limits = builtins.attrNames table.objects.limits;
        ctHelpers = builtins.attrNames table.objects.ctHelpers;
        ctTimeouts = builtins.attrNames table.objects.ctTimeouts;
        ctExpectations = builtins.attrNames table.objects.ctExpectations;
        secmarks = builtins.attrNames table.objects.secmarks;
        synproxies = builtins.attrNames table.objects.synproxies;
        tunnels = builtins.attrNames table.objects.tunnels;
        sets = (builtins.attrNames table.objects.sets) ++ zoneSetNames;
        maps = builtins.attrNames table.objects.maps;
        flowtables = builtins.attrNames table.objects.flowtables;
      };

      /*
        Walk every entry's `rule` body across all rule groups,
        annotating each ref with its source path for the error
        message.
      */
      refsFromGroup =
        groupName: group:
        lib.concatLists (
          lib.mapAttrsToList (
            entryName: entry:
            map (ref: ref // { path = "${groupName}.${entryName}.rule"; }) (extractRefs entry.rule)
          ) group
        );

      /*
        Walk every zone's active matchOverride sections via
        `getActiveMatchOverrides`. Inactive sections (null or
        empty) carry no refs by definition — filtering at the
        helper boundary skips them cleanly. Section name is
        included in the ref's source path so error messages point
        at the exact field (e.g.
        `zones.lan.matchOverride.ingress.ipv4`).
      */
      refsFromMatchOverrides = lib.concatLists (
        lib.mapAttrsToList (
          zoneName: zone:
          lib.concatMap
            (
              dir:
              lib.concatLists (
                lib.mapAttrsToList (
                  section: body:
                  map (
                    ref:
                    ref
                    // {
                      path = "zones.${zoneName}.matchOverride.${dir}.${section}";
                    }
                  ) (extractRefs body)
                ) (getActiveMatchOverrides zone dir)
              )
            )
            [
              "ingress"
              "egress"
            ]
        ) mergedZones
      );

      /*
        Walk every `table.objects.<kind>.<name>` body. Most object
        kinds (counters, limits, quotas, synproxies, …) are
        config-only leaves and contribute no refs. Sets and maps
        may carry refs in element-attached stateful statements
        (`dsl.expr.elem { val; stmt; }`); the recursive walker
        picks those up uniformly.
      */
      refsFromObjectKind =
        kindName: kindAttrs:
        lib.concatLists (
          lib.mapAttrsToList (
            objectName: body:
            map (ref: ref // { path = "objects.${kindName}.${objectName}"; }) (extractRefs body)
          ) kindAttrs
        );

      refsFromObjects = lib.concatLists (lib.mapAttrsToList refsFromObjectKind table.objects);

      /*
        Rule-bearing groups are listed explicitly rather than
        derived from a shared group-name list. `policies` is
        intentionally absent — the type has only a `verdict`
        field and no rule body, so it carries no named refs. If a
        future group gains a rule body, add it here too; silent
        omission would mean refs inside it never get resolved
        against `table.objects.<kind>` and would surface only at
        `nft load` time instead of compile time.
      */
      allRefs = lib.concatLists [
        (refsFromGroup "filters" table.filters)
        (refsFromGroup "snats" table.snats)
        (refsFromGroup "dnats" table.dnats)
        (refsFromGroup "sroutes" table.sroutes)
        (refsFromGroup "droutes" table.droutes)
        refsFromMatchOverrides
        refsFromObjects
      ];

      unresolvedRefs = builtins.filter (r: !(builtins.elem r.name (knownNames.${r.kind} or [ ]))) allRefs;

      newErrors = map (
        r: lib.nameValuePair "objectRefUnknown" "${r.path} references unknown ${r.kind} object '${r.name}'"
      ) unresolvedRefs;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  normalizeTable =
    table:
    let
      final = lib.pipe (mkInitialState table) [
        # Compute phases — populate ctx with derived state.
        convertNodesToZones
        computeChildrenOf
        computeZoneSets
        computeRootZoneNames
        collectAllZoneNames
        expandWildcardZones
        resolvePriorities
        collectZoneRefs
        # Validators — every phase below appends to ctx.errors
        # (or ctx.warnings); the orchestrator throws once at the
        # end if any errors fired.
        checkParentRefs
        checkParentCycles
        checkNameCollisions
        checkNameKeyMismatch
        checkSettings
        checkZoneRefs
        checkZoneMatchable
        checkChainOverridePlacement
        checkChainPlacement
        checkRpfilterOverride
        checkChainOverrideSemantics
        checkExtraSectionFields
        checkWildcardZoneMix
        checkNodeAddresses
        checkNatBodies
        checkPolicyUniqueness
        checkSetNameCollisions
        checkInterfaceOverlap
        checkCidrOverlap
        checkCrossAxisOverlap
        checkObjectRefs
      ];

      withWarnings =
        result:
        builtins.foldl' (acc: msg: lib.warn "nftzones.normalize: ${msg}" acc) result final.ctx.warnings;
    in
    if final.ctx.errors == [ ] then
      withWarnings final
    else
      throw (
        "nftzones.normalize: validation failed:\n"
        + lib.concatMapStringsSep "\n" (e: "  - [${e.name}] ${e.value}") final.ctx.errors
      );
in
{
  inherit
    convertNodesToZones
    computeZoneSets
    checkParentRefs
    checkParentCycles
    computeChildrenOf
    computeRootZoneNames
    checkNameCollisions
    checkNameKeyMismatch
    checkPolicyUniqueness
    checkSettings
    collectAllZoneNames
    expandWildcardZones
    resolvePriorities
    collectZoneRefs
    checkZoneRefs
    checkZoneMatchable
    checkChainOverridePlacement
    checkChainPlacement
    checkRpfilterOverride
    checkChainOverrideSemantics
    checkExtraSectionFields
    checkWildcardZoneMix
    checkNodeAddresses
    checkNatBodies
    checkSetNameCollisions
    checkInterfaceOverlap
    checkCidrOverlap
    checkCrossAxisOverlap
    checkObjectRefs
    normalizeTable
    ;
}
