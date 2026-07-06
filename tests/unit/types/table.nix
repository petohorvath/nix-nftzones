/*
  Unit tests for `lib/types/table.nix` (exposed as
  `nftzones.types.{table,tableName,tableFamily,tableFlags,
  tableComment,tableSettings,tableChainPolicy,tableZones,
  tableNodes,tableFilters,tablePolicies,tableSnats,tableDnats,
  tableSroutes,tableDroutes,tableObjects}`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable evalFails;

  empty = evalTable { };
in
{
  # ===== top-level metadata defaults =====

  testTableNameDerivedFromOptionKey = {
    # The `fw` option in evalTable's harness drives the key-derived
    # `name` field (`default = name`); tests using a different option
    # key would see that key here.
    expr = empty.name;
    expected = "fw";
  };

  testTableFamilyDefaultInet = {
    expr = empty.family;
    expected = "inet";
  };

  testTableFlagsDefaultEmpty = {
    expr = empty.flags;
    expected = [ ];
  };

  testTableCommentDefaultNull = {
    expr = empty.comment;
    expected = null;
  };

  testTableFamilyAcceptsBridge = {
    expr = (evalTable { family = "bridge"; }).family;
    expected = "bridge";
  };

  testTableFamilyAcceptsIp = {
    expr = (evalTable { family = "ip"; }).family;
    expected = "ip";
  };

  testTableFamilyAcceptsIp6 = {
    expr = (evalTable { family = "ip6"; }).family;
    expected = "ip6";
  };

  # `arp` and `netdev` are admitted by nftypes' family enum but
  # not by ours — see the type comment on `tableFamily` and the
  # README "Known limitations" section for rationale.
  testTableFamilyRejectsArp = {
    expr = evalFails (evalTable { family = "arp"; }).family;
    expected = true;
  };

  testTableFamilyRejectsNetdev = {
    expr = evalFails (evalTable { family = "netdev"; }).family;
    expected = true;
  };

  testTableFamilyRejectsBogus = {
    expr = evalFails (evalTable { family = "wat"; }).family;
    expected = true;
  };

  # ===== content groups all default to {} =====

  testTableEmptyDefaults = {
    expr = {
      inherit (empty)
        zones
        nodes
        filters
        policies
        snats
        dnats
        sroutes
        droutes
        ;
    };
    expected = {
      zones = { };
      nodes = { };
      filters = { };
      policies = { };
      snats = { };
      dnats = { };
      sroutes = { };
      droutes = { };
    };
  };

  # ===== settings — best-practice defaults =====

  testTableSettingsDefaults = {
    expr = {
      inherit (empty.settings)
        stateful
        loopback
        rpfilter
        chainPolicy
        localZone
        wildcardZone
        ;
    };
    expected = {
      stateful = true;
      loopback = true;
      rpfilter = false;
      chainPolicy = "drop";
      localZone = "local";
      wildcardZone = "all";
    };
  };

  testTableSettingsChainPolicyAcceptsAccept = {
    expr = (evalTable { settings.chainPolicy = "accept"; }).settings.chainPolicy;
    expected = "accept";
  };

  testTableSettingsChainPolicyRejectsReject = {
    expr = evalFails (evalTable { settings.chainPolicy = "reject"; }).settings.chainPolicy;
    expected = true;
  };

  testTableSettingsLocalZoneCustom = {
    expr = (evalTable { settings.localZone = "host"; }).settings.localZone;
    expected = "host";
  };

  testTableSettingsLocalZoneRejectsBadShape = {
    expr = evalFails (evalTable { settings.localZone = "Bad"; }).settings.localZone;
    expected = true;
  };

  # ===== objects — every kind defaults to {} =====

  testTableObjectsDefaults = {
    expr = {
      inherit (empty.objects)
        counters
        quotas
        limits
        ctHelpers
        ctTimeouts
        ctExpectations
        secmarks
        synproxies
        tunnels
        sets
        maps
        flowtables
        ;
    };
    expected = {
      counters = { };
      quotas = { };
      limits = { };
      ctHelpers = { };
      ctTimeouts = { };
      ctExpectations = { };
      secmarks = { };
      synproxies = { };
      tunnels = { };
      sets = { };
      maps = { };
      flowtables = { };
    };
  };

  # ===== objects — container fields are stripped from user surface =====

  testTableObjectsCounterUserBody = {
    # The user-facing body has no family/name/table/handle —
    # those come from the table context at compile time. Setting
    # any of them at user level should be rejected.
    expr =
      evalFails
        (evalTable {
          objects.counters.ssh-attempts = {
            packets = 0;
            bytes = 0;
            family = "inet";
          };
        }).objects.counters.ssh-attempts;
    expected = true;
  };

  testTableObjectsCounterAccepted = {
    # counterObjectBody includes a nullable `comment` field
    # alongside the user-supplied counters.
    expr =
      (evalTable {
        objects.counters.ssh-attempts = {
          packets = 0;
          bytes = 0;
        };
      }).objects.counters.ssh-attempts;
    expected = {
      packets = 0;
      bytes = 0;
      comment = null;
    };
  };
}
