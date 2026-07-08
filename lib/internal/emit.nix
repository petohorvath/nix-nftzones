/*
  internal/emit — Phase 4 of the compile pipeline, exposed under
  `nftzones.internal.emit`.

  Composes the rest of the pipeline state into one
  `nftypes.dsl.table` value via small focused helpers. Output is
  written to `ctx.output`.

  Pipeline pattern: each phase takes `{ table; ctx }` and returns
  the same shape, mirroring earlier phases.

  Phase pipeline (Phase 4, post-step-5 — every sub-phase below
  contributes one `ctx` artifact; `assembleOutput` rolls them
  into the final table body):

      { table; ctx (post-Phase 3) }
        ↓ computeEffectiveSubChains  ctx.effectiveSubChainsByBucket
        ↓ emitBaseChains             ctx.baseChains
        ↓ emitSubChains              ctx.subChains
        ↓ emitUserObjects            ctx.userObjects
        ↓ assembleOutput             ctx.output (nftypes.dsl.table value)
      { table; ctx }

  `ctx.zoneSets` is materialized once in Phase 1
  (`internal.normalize.computeZoneSets`) — the same artifact
  serves both Phase 1 validators (`checkSetNameCollisions`,
  `checkObjectRefs`) and Phase 4 emit (jump construction +
  `assembleOutput`'s final body), avoiding redundant evaluation.

  `ctx.effectiveSubChainsByBucket` is the same idea applied per
  base chain bucket: each bucket's full sub-chain map (direct +
  intermediate dispatchers) is computed once in
  `computeEffectiveSubChains` and consumed by both
  `mkBaseChain` (root-jump emission) and `mkSubChain` (chain
  body construction).

  ===== assembleTable =====

  Input:  `{ family; name; body; }`
  Output: an `nftypes.dsl.table` marker value.

  Thin wrapper around `nftypes.dsl.table family name body` so
  callers stay on the named-attrset shape. `body` may carry
  `sets`, `chains`, object containers, and table-level options
  (`flags`, `comment`); all are optional. As Phase 4 grows the
  body expands.

  ===== mkRuleBody =====

  Pure helper: emit one cell's rule body (list of nftypes
  statements). Dispatches on cell shape — no explicit group arg
  needed. See the `===== Output shape =====` section in
  `lib/internal/expand.nix` for the per-group cell shapes this
  consumes:
    - `cell ? verdict`         → policy (single verdict statement)
    - `cell.rule ? snat`       → snat with address translation
    - `cell.rule ? masquerade` → snat masquerade
    - `cell.rule ? action`     → dnat (match clauses + dnat /
                                 redirect action)
    - else                     → filter / sroute / droute (cell.rule
                                 is already a list of statements)

  All NAT/verdict statements are constructed via `nftypes.dsl.*`
  builders so they pass the marker-validation that prevents raw
  libnftables-json shapes from leaking through.

  ===== subChainNameOf =====

  Pure helper: build the full nftables sub-chain name from a
  `baseChainName` (`"<hook>-at-<priority>"` from Phase 3) and a
  `subChainKey` (Phase 3's local key within `bucket.subChains`,
  e.g. `"lan-to-wan"` / `"wan"`). Output is `"<base>__<sub>"` per
  design doc §4.3 — used both as the chain attribute in
  `body.chains` for sub-chains and as the `jump` target in base
  chains.

  ===== mkSubChainKey =====

  Pure helper: compose a sub-chain key from explicit
  `(fromZone, toZone)` components — the unpacked counterpart to
  `dispatch.subChainKeyOf` (which takes a cell). Used by
  `buildEffectiveSubChains` to fabricate intermediate-parent
  sub-chain keys without re-parsing strings.

  ===== isRootFrom =====

  Pure predicate: is this from-zone a root (no parent)?
  `localZone` is always a root by construction — the sentinel
  has no `mergedZones` entry. Unknown zones are also treated as
  roots defensively (consistent with the localZone case).

  ===== buildEffectiveSubChains =====

  Pure helper: for one base chain bucket, compute the full set of
  sub-chain records to emit — direct cell-bearing sub-chains
  plus transparent intermediate-parent dispatchers synthesized
  along each cell-bearing sub-chain's parent chain. Returns an
  attrset keyed by `subChainKey`.

  Why intermediates: only root from-zones jump from the base
  chain. A descendant zone with cells (e.g. `web-server`) is
  only reachable through a chain of parent dispatch jumps
  starting at its root ancestor. If any ancestor lacks its own
  cells, an empty placeholder chain still has to exist so the
  parent above can dispatch into it.

  Direct sub-chain records carry `preChildCells` and
  `postChildCells` from Phase 3. Synthesized intermediates are
  seeded with empty cell lists; emit fills them with just the
  child-dispatch jumps.

  ===== mkSubChain =====

  Pure helper: build one sub-chain body (regular non-base chain
  with a `rules` field) from one sub-chain record. Body order:

    1. preChildCells   — sorted (priority asc, name asc) by
                          Phase 3.
    2. child-dispatch jumps to children with content (one rule
                          per child × from-side variant).
    3. postChildCells  — sorted (priority asc, name asc;
                          policies appended last as tail rules)
                          by Phase 3.

  Sub-chains with no `from` (droute-style) carry no
  child-dispatch — hierarchy applies only on the from-side.

  ===== mkSubChains =====

  Walks every base chain bucket's effective sub-chains
  (see `buildEffectiveSubChains`), producing one sub-chain entry
  per `(baseChainName, subChainKey)` pair, keyed by the full
  sub-chain name (see `subChainNameOf`). Reuses Phase 3 keys
  verbatim so the name → `(hook, priority, from, to)` mapping is
  mechanical and auditable in the generated JSON.

  ===== mkDirectionVariants =====

  Pure helper: build the match-clause variants for one direction
  (`from` / `to`) of one sub-chain at a given hook. Returns a
  list of variants — each variant is a list of statements ANDed
  within a single rule. The cartesian product across both
  directions is taken in `mkRootJumpRules`.

  Why per-variant rather than ANDed clauses: in `inet` family,
  `ip <addr>` and `ip6 <addr>` clauses can't be ANDed in the
  same rule — packets of the wrong family skip the rule entirely.
  So one variant per address family with a non-empty set, plus
  the optional interface prefix when the hook allows it.

  Sections carry an *own-ness* classification (via
  `internal.zone.ownSectionsOf`; an active matchOverride section
  is own by definition): the union sets from
  `internal.zone.genSets` also hold descendant content, and only
  sections the zone anchors itself may AND together. A
  descendant-only ("inherited") section ANDed into the gate would
  narrow the ancestor's dispatch to just the descendant's
  traffic. Inherited sections widen instead:
    - inherited v4 / v6 → one extra OR variant each (behind the
      own prefix) so descendant traffic of a family the zone
      lacks still enters — unless the own gate is
      interface/extra-only, which is family-agnostic and covers
      the whole subtree already;
    - inherited interfaces → one standalone family-agnostic
      variant (never joins the prefix).

  Variant count per direction ("own" = anchored by the zone's
  raw fields or an override; "inh" = present only via
  descendants in the union set):

    zone has              | variants emitted
    ----------------------|----------------------------------
    empty                 | 0
    own iface only        | 1 (family-agnostic)
    own iface + inh v4/v6 | 1 (family-agnostic covers subtree)
    own v4 only           | 1
    own v4 + own v6       | 2
    own iface + own v4    | 1 (iface prefix + v4)
    own iface + own v4/v6 | 2 (each with iface prefix)
    own v4 + inh v6       | 2 (v4, v6 — no cross-AND)
    own v4 + inh iface    | 2 (v4; standalone iface)
    all inherited         | 1 per present section (no ANDing)

  Set references (`@<zone>_iifs`, `@<zone>_v4`, `@<zone>_v6`)
  point at the zone-derived sets emitted by Phase 1's
  `computeZoneSets`.

  Wildcard cases:
    - `zoneName == null` (single-direction sub-chain — dnat /
      sroute have no `to`, droute has no `from`).
    - `zoneName == localZone` (sentinel; matched by the chain
      dispatch already, no further constraint).
  Both return `[ [ ] ]` (one empty variant, contributing nothing
  to the cartesian product).

  ===== mkChildDispatchJumpRules =====

  Pure helper: build the child-dispatch jump rules for one
  parent sub-chain. For each child of `parentFromZone` that has
  a sub-chain in `effectiveSubChains` for the same `toZone`,
  emit one jump per from-side variant of the child's match.
  Targets `__<child>-to-<to>` (or `__<child>` for
  single-direction sub-chains).

  To-side is implicit — by the time control reaches a parent's
  sub-chain, traffic already matched the to-side at the
  chain-jump point. Child-dispatch only re-checks the from-side,
  narrowing into the more specific child match.

  ===== mkRootJumpRules =====

  Pure helper: build the dispatch jump rules for one base chain
  bucket. Walks each effective sub-chain; emits jumps only for
  sub-chains whose `from` is a root from-zone — descendants
  ride into their sub-chain via the parent's child-dispatch
  jumps, not via the base chain.

  For each emitted (root) sub-chain, computes the `from` / `to`
  direction variants and produces one jump per variant pair
  (cartesian product), dropping cross-family combinations
  (e.g. v4-from × v6-to) that nft refuses to compile in `inet`
  tables.

  Sub-chains with no `from` (droute-style) are also emitted from
  the base chain — they have no parent hierarchy to ride
  through.

  ===== mkBaseChain =====

  Pure helper: produces one base chain attrset (chainBody shape per
  `nftypes.dsl.table` docstring) for a given `{ family; settings;
  bucket; baseChainName; mergedZones; zoneSets; }`. Includes:
    - `type` derived via `nftypes.compatibility.chainTypeFor`.
    - `hook`, `prio` (priority resolved to int via
      `nftypes.resolvePriority`).
    - `policy` (filter chains only) from `settings.chainPolicy`.
    - `rules` — boilerplate for filter chains plus root-zone
      dispatch jumps:
        1. stateful   (`ct state established,related accept`,
                       `ct state invalid drop`) when filter chain
                       and `settings.stateful`.
        2. loopback   (`iif lo accept`) when filter input chain
                       and `settings.loopback`.
        3. root-zone dispatch jumps via `mkRootJumpRules` —
                       one rule per (root from-zone × from-variant
                       × to-variant) tuple.

  Per-cell rule bodies (whether for the parent's own rules or
  for descendants) live inside their respective sub-chains —
  see `mkSubChain`. The rpfilter chain is built separately by
  `mkBaseChains` and never injected into a user-authored chain.

  ===== mkBaseChains =====

  Walks `ctx.chainBuckets` producing the chain attrset for the
  table body. Threads `baseChainName`, `mergedZones`, and
  `zoneSets` to `mkBaseChain` for jump-rule construction. If
  `settings.rpfilter` is enabled and no user override has
  claimed `prerouting-at-raw`, synthesizes a dedicated chain
  carrying just `fib saddr . iif oif eq 0 drop`. A user
  override at `(prerouting, raw)` always wins; Phase 1's
  `checkRpfilterOverride` warns when both are set so the
  suppression is visible.

  ===== emitBaseChains =====

  Reads:  ctx.chainBuckets, ctx.zoneSets, table.{family, settings}
  Writes: ctx.baseChains

  Pipeline phase that wraps `mkBaseChains` and stashes the chain
  attrset on `ctx`. Reads `ctx.zoneSets` (produced in Phase 1 by
  `internal.normalize.computeZoneSets`) to construct the jump-match
  clauses.

  ===== emitSubChains =====

  Reads:  ctx.chainBuckets
  Writes: ctx.subChains

  Pipeline phase that wraps `mkSubChains` and stashes the sub-chain
  attrset on `ctx`.

  ===== emitUserObjects =====

  Reads:  table.objects
  Writes: ctx.userObjects

  Pure passthrough: `table.objects.<kind>.<name>` flows into
  `ctx.userObjects.<kind>.<name>` and then `body.<kind>.<name>` of
  the assembled table value. The type layer's `asUserBody` (in
  `lib/types/table.nix`) has already stripped `family` / `name` /
  `table` / `handle`; the nftypes renderer fills them back in
  from the parent table. Named-object reference validation lives
  upstream in Phase 1's `internal.normalize.checkObjectRefs`.

  ===== assembleOutput =====

  Reads:  ctx.zoneSets, ctx.baseChains, ctx.subChains,
          ctx.userObjects, table.{family, name}
  Writes: ctx.output

  Final pipeline phase: rolls the per-artifact ctx fields into
  one `nftypes.dsl.table` value via `assembleTable`.

  Body composition rules:
    - Base chains and sub-chains share `body.chains` — keys don't
      collide because base chains use the bare `<baseChainName>`
      and sub-chains use `<baseChainName>__<subChainKey>`.
    - User-defined sets merge with auto-generated zone sets under
      `body.sets`. Name collisions resolve user-wins; a future
      Phase 1 validator should flag these at compile time.
    - Other user-object kinds (counters / quotas / limits / …)
      pass through as their own body field. Empty kinds are
      skipped so the output JSON stays minimal.

  ===== emitTable =====

  Orchestrator: pipes `emitBaseChains`, `emitSubChains`,
  `emitUserObjects`, then `assembleOutput`. Returns `{ table; ctx }`
  with `ctx.output` set. `ctx.zoneSets` is consumed (produced in
  Phase 1 by `internal.normalize.computeZoneSets`).
*/
{ inputs, internal }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes.dsl)
    expr
    eq
    inSet
    accept
    drop
    snat
    masquerade
    dnat
    redirect
    jump
    ;
  inherit (nftypes.dsl.fields)
    meta
    ct
    ip
    ip6
    ;
  inherit (nftypes) chainTypeFor priorityNameOf;
  inherit (internal.zone) getActiveMatchOverrides ownSectionsOf;
  inherit (internal.placement) baseChainNameOf walkParents hooksWithIifname;

  # Boilerplate rule constants (each rule = list of statements).
  statefulRules = [
    [
      (inSet ct.state [
        "established"
        "related"
      ])
      accept
    ]
    [
      (eq ct.state "invalid")
      drop
    ]
  ];

  loopbackRules = [
    [
      (eq meta.iif "lo")
      accept
    ]
  ];

  rpfilterRules = [
    [
      (eq (expr.fib {
        result = "oif";
        flags = [
          "saddr"
          "iif"
        ];
      }) 0)
      drop
    ]
  ];

  /*
    Map a policy verdict string to its DSL verdict statement.
    Policies are limited to "accept" / "drop" by `policyVerdict`
    (see `lib/types/policy.nix`); attribute access fails fast
    for any other value.
  */
  policyVerdictStmts = { inherit accept drop; };

  /*
    Emit one cell's rule entry. A non-null `cell.comment` wraps the
    statement list as `{ expr; comment; }` — the alternate rule-list
    element shape per nftypes' `dsl/structure/table.nix`.

    Cell shape dispatch:
      - `cell ? verdict`            → policy
      - `cell.rule ? snat`          → snat with address translation
      - `cell.rule ? masquerade`    → snat masquerade
      - `cell.rule ? action`        → dnat (action.dnat | action.redirect)
      - else (`cell.rule` is list)  → filter / sroute / droute
  */
  mkRuleBody =
    cell:
    let
      stmts =
        if cell ? verdict then
          [ policyVerdictStmts.${cell.verdict} ]
        else if cell.rule ? snat then
          [ (snat cell.rule.snat) ]
        else if cell.rule ? masquerade then
          [ (masquerade cell.rule.masquerade) ]
        else if cell.rule ? action then
          cell.rule.match
          ++ [
            (if cell.rule.action ? dnat then dnat cell.rule.action.dnat else redirect cell.rule.action.redirect)
          ]
        else
          cell.rule;
    in
    if cell.comment != null then
      {
        expr = stmts;
        inherit (cell) comment;
      }
    else
      stmts;

  /*
    Build the full nftables sub-chain name from a base chain name
    and a sub-chain key (Phase 3's local key within
    `bucket.subChains`). Output is the `<base>__<sub>` form per
    design doc §4.3 — used as the chain attribute in
    `body.chains` for sub-chains and as the `jump` target in base
    chains.
  */
  subChainNameOf = baseChainName: subChainKey: "${baseChainName}__${subChainKey}";

  /*
    Compose a sub-chain key from explicit `(fromZone, toZone)`
    components — mirrors `dispatch.subChainKeyOf` but operates on
    the unpacked pair instead of a cell. Used by
    `buildEffectiveSubChains` to generate intermediate-parent
    keys without re-parsing strings.
  */
  mkSubChainKey =
    fromZone: toZone:
    if fromZone != null && toZone != null then
      "${fromZone}-to-${toZone}"
    else if fromZone != null then
      fromZone
    else
      toZone;

  /*
    Predicate: is this from-zone a root (no parent)?
    `localZone` is always a root by construction — it's a
    sentinel that has no `mergedZones` entry. Defensive default
    for unknown zones (also missing from `mergedZones`) is
    "root", matching the localZone case. Reads
    `zone.parent or null` to accommodate raw test fixtures.
  */
  isRootFrom =
    mergedZones: localZone: fromZone:
    fromZone == localZone
    || !(mergedZones ? ${fromZone})
    || (mergedZones.${fromZone}.parent or null) == null;

  /*
    For one base chain bucket, compute the full set of sub-chain
    records to emit — direct cell-bearing sub-chains plus
    transparent intermediate-parent dispatchers synthesized along
    each cell-bearing sub-chain's parent chain. Returns an
    attrset keyed by `subChainKey`.

    Why intermediates: only root from-zones jump from the base
    chain. A descendant zone with cells (e.g., `web-server`) is
    only reachable through a chain of parent dispatch jumps
    starting at its root ancestor. If any ancestor lacks its own
    cells, an empty placeholder chain still has to exist so the
    parent can dispatch into it.

    Direct sub-chain records carry `preChildCells` and
    `postChildCells` from Phase 3. Synthesized intermediates are
    seeded with empty cell lists; Phase 4 emit fills them with
    just the child-dispatch jumps.

    `bucket.subChains` overrides any intermediate placeholder
    that turned out to share its key with a cell-bearing
    sub-chain.
  */
  buildEffectiveSubChains =
    bucket: mergedZones:
    let
      # Strict ancestor walk lives in `internal.placement.walkParents`.
      # Phase 1's `checkParentCycles` rejects any cycle before we get
      # here; the helper's own `visited` guard is defensive so unit-
      # test fixtures that bypass Phase 1 don't infinite-loop.
      ancestorsOf = name: walkParents mergedZones name;

      mkEmptyRecord =
        fromZone: toZone:
        lib.optionalAttrs (fromZone != null) { from = fromZone; }
        // lib.optionalAttrs (toZone != null) { to = toZone; }
        // {
          preChildCells = [ ];
          postChildCells = [ ];
        };

      intermediatesOf =
        record:
        let
          fromZone = record.from or null;
          toZone = record.to or null;
        in
        lib.foldl' (
          acc: ancestor:
          let
            key = mkSubChainKey ancestor toZone;
          in
          if acc ? ${key} then acc else acc // { ${key} = mkEmptyRecord ancestor toZone; }
        ) { } (ancestorsOf fromZone);

      allIntermediates = lib.foldlAttrs (
        acc: _subChainKey: record:
        acc // intermediatesOf record
      ) { } bucket.subChains;
    in
    allIntermediates // bucket.subChains;

  /*
    Build child-dispatch jumps for one parent sub-chain. For each
    child of `parentFromZone` whose subtree has content for this
    `(baseChainName, toZone)`, emit one jump per from-side
    variant of the child's match.

    To-side is implicit: by the time we're inside a
    `__<parent>-to-<to>` sub-chain, traffic already matched the
    to-side at the chain-jump point. Child-dispatch only re-checks
    the from-side, narrowing into the more specific child match.
  */
  mkChildDispatchJumpRules =
    {
      hook,
      parentFromZone,
      toZone,
      baseChainName,
      childrenOf,
      effectiveSubChains,
      mergedZones,
      zoneSets,
      localZone,
    }:
    let
      children = if parentFromZone == null then [ ] else childrenOf.${parentFromZone} or [ ];

      activeFor =
        zoneName:
        if zoneName == localZone || !(mergedZones ? ${zoneName}) then
          { }
        else
          getActiveMatchOverrides mergedZones.${zoneName} "ingress";

      mkJumpsForChild =
        childName:
        let
          childKey = mkSubChainKey childName toZone;
        in
        if !(effectiveSubChains ? ${childKey}) then
          [ ]
        else
          let
            fromVariants = mkDirectionVariants {
              inherit
                hook
                mergedZones
                zoneSets
                localZone
                ;
              direction = "from";
              zoneName = childName;
              active = activeFor childName;
            };
            jumpStmt = jump (subChainNameOf baseChainName childKey);
          in
          map (variant: variant ++ [ jumpStmt ]) fromVariants;
    in
    lib.concatMap mkJumpsForChild children;

  /*
    Build one sub-chain body. Body shape: a regular (non-base)
    chain with just a `rules` field. Rule order:

      1. preChildCells   — sorted (priority asc, name asc).
      2. child-dispatch jumps to children with content (one rule
         per child × from-side variant).
      3. postChildCells  — sorted (priority asc, name asc;
                            policies appended last as tail rules).

    Sub-chains with no `from` field (droute-style) carry no
    child-dispatch (hierarchy is from-side only); their body
    reduces to `preChildCells ++ postChildCells`.
  */
  mkSubChain =
    {
      hook,
      subChain,
      baseChainName,
      childrenOf,
      effectiveSubChains,
      mergedZones,
      zoneSets,
      localZone,
    }:
    let
      parentFromZone = subChain.from or null;
      toZone = subChain.to or null;

      childJumps = mkChildDispatchJumpRules {
        inherit
          hook
          parentFromZone
          toZone
          baseChainName
          childrenOf
          effectiveSubChains
          mergedZones
          zoneSets
          localZone
          ;
      };

      rules =
        (map mkRuleBody subChain.preChildCells) ++ childJumps ++ (map mkRuleBody subChain.postChildCells);
    in
    {
      inherit rules;
    };

  /*
    Walk every base chain bucket's effective sub-chains,
    producing one sub-chain entry per `(baseChainName,
    subChainKey)` pair, keyed by the full sub-chain name (see
    `subChainNameOf`).
  */
  mkSubChains =
    {
      chainBuckets,
      effectiveSubChainsByBucket,
      childrenOf,
      mergedZones,
      zoneSets,
      localZone,
    }:
    lib.foldlAttrs (
      acc: baseChainName: bucket:
      let
        effectiveSubChains = effectiveSubChainsByBucket.${baseChainName};
      in
      acc
      // lib.mapAttrs' (
        subChainKey: subChain:
        lib.nameValuePair (subChainNameOf baseChainName subChainKey) (mkSubChain {
          inherit (bucket) hook;
          inherit
            subChain
            baseChainName
            childrenOf
            effectiveSubChains
            mergedZones
            zoneSets
            localZone
            ;
        })
      ) effectiveSubChains
    ) { } chainBuckets;

  /*
    Build the match-clause variants for one direction of one
    sub-chain at a given hook. Returns a list of variants — each
    variant is a list of statements ANDed within a single rule.
    Multiple variants → multiple rules (the cartesian product is
    taken in `mkRootJumpRules` / `mkChildDispatchJumpRules`).

    Why per-variant rather than ANDed clauses: in `inet` family,
    `ip <addr>` and `ip6 <addr>` cannot be ANDed in the same
    rule — packets of the wrong family skip the rule entirely.
    So one variant per address family that has a non-empty set,
    plus the optional interface prefix when the hook allows it.

    Section resolution (`active` is the user's active override
    sections from `internal.zone.getActiveMatchOverrides`):
      - `interfaces` section: `active.interfaces` if the user
        provided it, else auto `inSet <ifField> @<zone>_iifs`.
        Hook-gated — only included when `iifname` / `oifname`
        is valid at the hook.
      - `ipv4` / `ipv6` sections: user override if present, else
        auto `inSet <addrField> @<zone>_<v4|v6>`. Always valid
        at any hook.
      - `extra` section: family-agnostic user clauses (mark,
        vlan, cgroup, …); no auto path. Joined into the prefix
        when present.

    Own-ness: the union sets behind the auto path also carry
    descendant content (`internal.zone.genSets`), so each section
    is classified own (anchored by the zone's raw fields —
    `internal.zone.ownSectionsOf` — or by an active override) vs
    inherited (descendant-contributed only). Only own sections
    AND together; an inherited section ANDed into the gate would
    narrow the ancestor's dispatch to just the descendant's
    traffic — adding a descendant must never shrink what an
    ancestor matches.

    Variant construction:
      - prefix           = own ifsAtHook ++ extraSection
      - one variant per non-empty own family section:
          [ prefix ++ v4Section ], [ prefix ++ v6Section ]
      - own family variants present → widen with the inherited
        leftovers: one OR variant per inherited family
        ([ prefix ++ famSection ], patching the own anchors'
        family-blindness) plus a standalone [ ifsAtHook ] when
        interfaces are inherited (family-agnostic, so it must
        not be constrained by the zone's own sections).
      - no own family sections but prefix non-empty → single
        prefix-only variant. Family-agnostic: descendant traffic
        of every family already enters through it (an
        address-only child lives behind the parent's own
        interfaces), so inherited families add no variant.
      - nothing own (grouping zone) → every present section
        stands alone as one variant. Different descendants may
        contribute different sections; ANDing them would match
        only their intersection.

    Special cases:
      - `zoneName == null` (single-direction sub-chain — dnat /
        sroute have no `to`, droute has no `from`)         → `[ [ ] ]`.
      - `zoneName == localZone` (sentinel; never matchable as a
        zone — the chain dispatch already used it)         → `[ [ ] ]`.

    Phase 1's `checkChainOverridePlacement` and `checkZoneMatchable`
    guarantee a referenced zone has at least one matchable section at
    its hook, so the `[ ]` empty-result branch shouldn't fire for
    non-localZone refs. If it does (defense), the cartesian product
    in `mkRootJumpRules` / `mkChildDispatchJumpRules` drops the entire
    jump for that sub-chain.
  */
  mkDirectionVariants =
    {
      hook,
      direction,
      zoneName,
      active,
      mergedZones,
      zoneSets,
      localZone,
    }:
    if zoneName == null || zoneName == localZone then
      [ [ ] ]
    else
      let
        isFromDirection = direction == "from";
        iifAvailable = builtins.elem hook hooksWithIifname;
        oifAvailable = builtins.elem hook nftypes.compatibility.hooksWithOifname;
        ifAvailable = if isFromDirection then iifAvailable else oifAvailable;

        ifField = if isFromDirection then meta.iifname else meta.oifname;
        addrFieldV4 = if isFromDirection then ip.saddr else ip.daddr;
        addrFieldV6 = if isFromDirection then ip6.saddr else ip6.daddr;

        iifsName = "${zoneName}_iifs";
        v4Name = "${zoneName}_v4";
        v6Name = "${zoneName}_v6";

        autoIfs = lib.optional (zoneSets ? ${iifsName}) (inSet ifField (expr.setRef iifsName));
        autoV4 = lib.optional (zoneSets ? ${v4Name}) (inSet addrFieldV4 (expr.setRef v4Name));
        autoV6 = lib.optional (zoneSets ? ${v6Name}) (inSet addrFieldV6 (expr.setRef v6Name));

        # Active section wins if present; else fall back to auto.
        ifsSection = active.interfaces or autoIfs;
        v4Section = active.ipv4 or autoV4;
        v6Section = active.ipv6 or autoV6;
        extraSection = active.extra or [ ];

        # Interfaces section is hook-gated: drop it when the relevant
        # iif/oif field isn't valid at the hook. checkChainOverride‑
        # Placement should have flagged this case, so this is defensive.
        ifsAtHook = if ifAvailable then ifsSection else [ ];

        /*
          Own-ness per section: an active override is own by
          definition; the auto path is own iff the zone's raw
          fields anchor it (`internal.zone.ownSectionsOf`).
          A zone missing from `mergedZones` (raw fixtures;
          unreachable through the validated pipeline) classifies
          everything as own, reproducing the all-AND composition
          a flat zone gets.
        */
        own =
          if mergedZones ? ${zoneName} then
            ownSectionsOf mergedZones.${zoneName}
          else
            {
              interfaces = true;
              v4 = true;
              v6 = true;
            };
        ifsOwn = active ? interfaces || own.interfaces;
        v4Own = active ? ipv4 || own.v4;
        v6Own = active ? ipv6 || own.v6;

        # Own-anchored prefix, ANDed into every family variant.
        # `extra` is override-only and therefore always own;
        # inherited interfaces never join (see inheritedIfsVariant).
        prefix = (if ifsOwn then ifsAtHook else [ ]) ++ extraSection;

        ownFamilyVariants =
          lib.optional (v4Own && v4Section != [ ]) (prefix ++ v4Section)
          ++ lib.optional (v6Own && v6Section != [ ]) (prefix ++ v6Section);

        # Descendant-contributed families widen the gate with one
        # OR variant each: the own family anchors are family-blind,
        # so without these a descendant of another family could
        # never enter the ancestor's sub-chain.
        inheritedFamilyVariants =
          lib.optional (!v4Own && v4Section != [ ]) (prefix ++ v4Section)
          ++ lib.optional (!v6Own && v6Section != [ ]) (prefix ++ v6Section);

        # Descendant-contributed interfaces stand alone as one
        # family-agnostic variant — ANDing them into the prefix
        # would narrow the zone's own variants to descendant
        # traffic.
        inheritedIfsVariant = lib.optional (!ifsOwn && ifsAtHook != [ ]) ifsAtHook;
      in
      if ownFamilyVariants != [ ] then
        # Family-anchored own gate, widened by whatever the
        # descendants contribute on top.
        ownFamilyVariants ++ inheritedFamilyVariants ++ inheritedIfsVariant
      else if prefix != [ ] then
        # Interface/extra-only own gate — family-agnostic, so the
        # whole subtree (including inherited families) already
        # rides it; nothing to widen.
        [ prefix ]
      else
        # Nothing own (grouping zone): every present section is
        # descendant-contributed and stands alone.
        inheritedFamilyVariants ++ inheritedIfsVariant;

  /*
    Classify a variant (list of match statements) by network-layer
    family in a single fold: `"ip"` / `"ip6"` if any statement
    carries that payload protocol, `null` (family-agnostic) for
    interface-only, extra-only, or empty variants. Used by
    `mkRootJumpRules` to drop cross-family cartesian-product pairs
    that nft rejects with "conflicting network layer protocols
    specified".
  */
  variantFamily =
    variant:
    builtins.foldl' (
      acc: stmt: if acc != null then acc else stmt.match.left.payload.protocol or null
    ) null variant;

  /*
    Build the root-zone dispatch jumps for one base chain bucket.
    Walks each effective sub-chain; emits jumps only for
    sub-chains whose `from` is a root from-zone (or whose
    sub-chain has no `from` at all, like droute-style entries
    which still flat-dispatch from the base chain).

    Non-root (descendant) sub-chains are reachable only via their
    parent's child-dispatch; they don't get base-chain jumps.

    For each emitted sub-chain, computes the from/to direction
    variants and produces one jump per variant pair, dropping
    cross-family combinations (e.g. v4-from × v6-to) that nft
    refuses to compile in `inet` tables.
  */
  mkRootJumpRules =
    {
      hook,
      baseChainName,
      effectiveSubChains,
      mergedZones,
      zoneSets,
      localZone,
    }:
    let
      activeFor =
        zoneName: side:
        if zoneName == null || zoneName == localZone then
          { }
        else
          getActiveMatchOverrides mergedZones.${zoneName} side;

      tagFamily = variant: {
        inherit variant;
        family = variantFamily variant;
      };

      mkJumpsForSubChain =
        subChainKey: subChain:
        let
          fromZone = subChain.from or null;
          toZone = subChain.to or null;
          isRoot = fromZone == null || isRootFrom mergedZones localZone fromZone;
        in
        if !isRoot then
          [ ]
        else
          let
            fromVariants = map tagFamily (mkDirectionVariants {
              inherit
                hook
                mergedZones
                zoneSets
                localZone
                ;
              direction = "from";
              zoneName = fromZone;
              active = activeFor fromZone "ingress";
            });
            toVariants = map tagFamily (mkDirectionVariants {
              inherit
                hook
                mergedZones
                zoneSets
                localZone
                ;
              direction = "to";
              zoneName = toZone;
              active = activeFor toZone "egress";
            });
            jumpStmt = jump (subChainNameOf baseChainName subChainKey);
          in
          map ({ from, to }: from.variant ++ to.variant ++ [ jumpStmt ]) (
            builtins.filter ({ from, to }: from.family == null || to.family == null || from.family == to.family)
              (
                lib.cartesianProduct {
                  from = fromVariants;
                  to = toVariants;
                }
              )
          );
    in
    lib.concatLists (lib.mapAttrsToList mkJumpsForSubChain effectiveSubChains);

  mkBaseChain =
    {
      family,
      settings,
      bucket,
      baseChainName,
      effectiveSubChains,
      mergedZones,
      zoneSets,
    }:
    let
      inherit (settings) localZone;

      chainType = chainTypeFor family bucket.hook bucket.priority;
      priorityName = priorityNameOf family bucket.priority;

      # `isFilterBaseChain` is the narrower predicate that gates
      # stateful + loopback boilerplate: chain at the canonical
      # `filter` priority specifically, not other filter-type
      # placements (`raw` for rpfilter, `security`, …). Compares
      # canonical names so bridge filter (-200) and ip filter (0)
      # both qualify.
      isFilterBaseChain = chainType == "filter" && priorityName == "filter";
      isInput = bucket.hook == "input";

      statefulPrelude = lib.optionals (isFilterBaseChain && settings.stateful) statefulRules;
      loopbackPrelude = lib.optionals (isFilterBaseChain && isInput && settings.loopback) loopbackRules;

      jumpRules = mkRootJumpRules {
        inherit (bucket) hook;
        inherit
          baseChainName
          effectiveSubChains
          mergedZones
          zoneSets
          localZone
          ;
      };

      rules = statefulPrelude ++ loopbackPrelude ++ jumpRules;
    in
    {
      type = chainType;
      inherit (bucket) hook;
      # `prio` is the JSON / nftypes-schema field name; internally
      # we use `priority` everywhere else.
      prio = nftypes.resolvePriority family bucket.priority;
      inherit rules;
    }
    // lib.optionalAttrs isFilterBaseChain {
      policy = settings.chainPolicy;
    };

  mkBaseChains =
    {
      family,
      settings,
      chainBuckets,
      effectiveSubChainsByBucket,
      mergedZones,
      zoneSets,
    }:
    let
      fromBuckets = lib.mapAttrs (
        baseChainName: bucket:
        mkBaseChain {
          inherit
            family
            settings
            bucket
            baseChainName
            mergedZones
            zoneSets
            ;
          effectiveSubChains = effectiveSubChainsByBucket.${baseChainName};
        }
      ) chainBuckets;

      # rpfilter chain lives entirely here so user overrides at
      # `(prerouting, raw)` aren't silently mutated. Synthesized
      # only when the user hasn't already claimed the slot —
      # Phase 1's `checkRpfilterOverride` warns when both are
      # set so the user knows their override took precedence.
      # Bucket key is built via `baseChainNameOf` (same helper Phase
      # 3 uses) so int and symbol priority forms collapse to the
      # same key regardless of which form the user wrote.
      rpfilterBucketKey = baseChainNameOf family {
        hook = "prerouting";
        priority = "raw";
      };
      needsRpfilter = settings.rpfilter && !(fromBuckets ? ${rpfilterBucketKey});
      synthesizedRpfilterChain = {
        type = "filter";
        hook = "prerouting";
        prio = nftypes.resolvePriority family "raw";
        rules = rpfilterRules;
      };
      rpfilterAddition = lib.optionalAttrs needsRpfilter {
        ${rpfilterBucketKey} = synthesizedRpfilterChain;
      };
    in
    fromBuckets // rpfilterAddition;

  assembleTable =
    {
      family,
      name,
      body,
    }:
    nftypes.dsl.table family name body;

  /*
    Materialize each base chain bucket's effective sub-chains
    (direct + intermediate dispatchers) once at the start of
    Phase 4, before anything reads them. Both `mkBaseChain` (for
    root-jump emission) and `mkSubChain` (for child-dispatch
    emission and chain body construction) consume the same
    artifact — caching avoids the parent-chain walks happening
    twice per bucket.

    Mirrors the `ctx.zoneSets` precedent: one fold in Phase 1
    feeds two Phase 1 validators and Phase 4 emit.
  */
  computeEffectiveSubChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        effectiveSubChainsByBucket = lib.mapAttrs (
          _baseChainName: bucket: buildEffectiveSubChains bucket ctx.mergedZones
        ) ctx.chainBuckets;
      };
    };

  emitBaseChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        baseChains = mkBaseChains {
          inherit (table) family settings;
          inherit (ctx)
            chainBuckets
            effectiveSubChainsByBucket
            mergedZones
            zoneSets
            ;
        };
      };
    };

  emitSubChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        subChains = mkSubChains {
          inherit (ctx)
            chainBuckets
            effectiveSubChainsByBucket
            childrenOf
            mergedZones
            zoneSets
            ;
          inherit (table.settings) localZone;
        };
      };
    };

  /*
    Pure passthrough: `table.objects.<kind>.<name>` maps directly to
    `body.<kind>.<name>` in the assembled `nftypes.dsl.table` value.
    Pure passthrough — the type layer's `asUserBody` (in
    `lib/types/table.nix`) has already stripped `family` / `name`
    / `table` / `handle`; the nftypes renderer fills them back in
    from the parent table.
  */
  emitUserObjects =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        userObjects = table.objects;
      };
    };

  assembleOutput =
    { table, ctx }:
    let
      # Base chains and sub-chains share the body's `chains` field;
      # keys won't collide because base chains use the bare
      # `<chain-key>` and sub-chains use `<chain-key>__<sub-key>`.
      allChains = ctx.baseChains // ctx.subChains;

      # User-defined sets merge with the auto-generated zone sets
      # under one `body.sets` field. Collisions are rejected
      # upstream by `internal.normalize.checkSetNameCollisions`,
      # so this merge is always safe — `//` semantics don't matter.
      allSets = ctx.zoneSets // (ctx.userObjects.sets or { });

      # Other user-object kinds pass through as their own body
      # field. Empty kinds are skipped so the output stays clean.
      otherUserObjectKinds = lib.filterAttrs (_: v: v != { }) (
        builtins.removeAttrs ctx.userObjects [ "sets" ]
      );

      body =
        lib.optionalAttrs (table.flags != [ ]) { inherit (table) flags; }
        // lib.optionalAttrs (table.comment != null) { inherit (table) comment; }
        // lib.optionalAttrs (allSets != { }) { sets = allSets; }
        // lib.optionalAttrs (allChains != { }) { chains = allChains; }
        // otherUserObjectKinds;
    in
    {
      inherit table;
      ctx = ctx // {
        output = assembleTable {
          inherit (table) family name;
          inherit body;
        };
      };
    };

  emitTable =
    state:
    lib.pipe state [
      computeEffectiveSubChains
      emitBaseChains
      emitSubChains
      emitUserObjects
      assembleOutput
    ];
in
{
  inherit
    mkRuleBody
    subChainNameOf
    mkSubChainKey
    isRootFrom
    buildEffectiveSubChains
    mkSubChain
    mkSubChains
    mkDirectionVariants
    mkChildDispatchJumpRules
    mkRootJumpRules
    mkBaseChain
    mkBaseChains
    assembleTable
    computeEffectiveSubChains
    emitBaseChains
    emitSubChains
    emitUserObjects
    assembleOutput
    emitTable
    ;
}
