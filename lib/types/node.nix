/*
  types/node — exposes node-related types under `nftzones.types`.

  Exported types:
    - `node`        — submodule for one node definition
    - `nodeName`    — string identifier for a node
    - `nodeAddress` — submodule with `ipv4` and/or `ipv6` (at least
                      one required, type-level enforced via
                      `addCheck`)

  A node is a single-host shortcut: a machine with a name, a
  parent zone, and one or two bare IP addresses. Nodes share the
  zone namespace — rules in filter / snat / dnat / sroute / droute
  / policy can reference a node by name in `from` / `to`, the same
  way they reference a zone.

  Compile lowering: `internal.node.toZone` produces a fully-shaped
  zone value mirroring the `nftzones.types.zone` submodule's
  evaluated form:
    name          = node.name;
    parent        = node.zone;
    interfaces    = [ ];
    cidrs         = optional ipv4 "${ipv4}/32"
                 ++ optional ipv6 "${ipv6}/128";
    matchOverride = { ingress = { }; egress = { }; };
  The lowered values merge directly with declared zones (also
  submodule-evaluated) under one uniform shape — no re-evaluation
  needed downstream. Phase 1 of the compile pipeline performs the
  merge in `convertNodesToZones`.

  At the type layer:
    - `zone` (parent reference) is required.
    - `address` is a submodule with two nullable fields. The
      "at least one of `ipv4` / `ipv6` must be set" constraint
      is NOT enforced at the type layer — `addCheck` operates
      on raw user input (not the merged-with-defaults value),
      so the empty-defaults case slips through. Phase 1's
      `checkNodeAddresses` validator catches it instead, which
      also lets the error aggregate with other Phase 1 errors
      under one message.

  Cross-cutting concerns (Phase 1 validators):
    - Node names must not collide with zone names (shared
      namespace at compile time) — `checkNameCollisions`.
    - `node.zone` must reference an existing zone — handled by
      `convertNodesToZones` / `checkZoneRefs`.
    - At least one of `address.ipv4` / `address.ipv6` is set —
      `checkNodeAddresses`.

  Example:
    options.nodes = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.node;
      default = { };
    };

    config.zones.dmz = { interfaces = [ "eth1" ]; };
    config.zones.lan = { interfaces = [ "eth2" ]; };
    config.nodes = {
      web-server = {
        zone = "dmz";
        address.ipv4 = "10.0.0.5";
      };
      admin-laptop = {
        zone = "lan";
        address = {
          ipv4 = "10.0.0.50";
          ipv6 = "fe80::1";
        };
      };
    };

    config.filters.allow-ssh-admin = {
      from = [ "admin-laptop" ];   # node — same namespace as zones
      to = [ "web-server" ];
      rule = [ (eq tcp.dport 22) accept ];
    };
*/
{
  inputs,
  primitives,
  zone,
}:
let
  inherit (inputs) lib libnet;
  inherit (zone) zoneName;

  nodeName = primitives.identifier;

  /*
    Submodule with optional `ipv4` / `ipv6` fields. The
    constraint "at least one must be set" is enforced by Phase
    1's `checkNodeAddresses` validator, NOT at the type layer.
    `addCheck` would not work here: it operates on raw user
    input (not the merged-with-defaults value), so the empty-
    defaults case `{ ipv4 = null; ipv6 = null; }` slips through.
    Deferring to Phase 1 also lets the error aggregate with
    other validation errors under one message.
  */
  nodeAddress = lib.types.submodule {
    options = {
      ipv4 = lib.mkOption {
        type = lib.types.nullOr libnet.types.ipv4;
        default = null;
        example = "10.0.0.5";
        description = ''
          IPv4 address (bare IP, no CIDR — node is one host).
        '';
      };
      ipv6 = lib.mkOption {
        type = lib.types.nullOr libnet.types.ipv6;
        default = null;
        example = "fe80::1";
        description = ''
          IPv6 address (bare IP, no CIDR).
        '';
      };
    };
  };

  node = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = nodeName;
          default = name;
          example = "web-server";
          description = ''
            The node's name. Defaults to the attribute name in
            the enclosing `nodes` attrset, e.g.
            `nodes.web-server.name == "web-server"`.
          '';
        };

        zone = lib.mkOption {
          type = zoneName;
          example = "dmz";
          description = ''
            Parent zone name. Must reference an existing zone in
            the same firewall config; the check is enforced at
            module level, not by the type.
          '';
        };

        address = lib.mkOption {
          type = nodeAddress;
          example = {
            ipv4 = "10.0.0.5";
          };
          description = ''
            IP address(es) of the node. At least one of `ipv4` /
            `ipv6` must be set — enforced by Phase 1's
            `checkNodeAddresses` validator so the error aggregates
            with other validation errors instead of throwing
            immediately at type-apply time.
          '';
        };
      };
    }
  );
in
{
  inherit
    nodeName
    nodeAddress
    node
    ;
}
