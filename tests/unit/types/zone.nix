/*
  Unit tests for `lib/types/zone.nix` (exposed as
  `nftzones.types.{zone,zoneName,zoneParent,zoneInterfaces,
  zoneCidrs,zoneMatchOverride}`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable evalType evalFails;

  zoneIn =
    body:
    (evalTable {
      zones.lan = body;
    }).zones.lan;
in
{
  # ===== zoneName — kebab-case identifier shape =====

  testZoneNameAcceptsLower = {
    expr = evalType nftzones.types.zoneName "lan";
    expected = "lan";
  };

  testZoneNameAcceptsKebab = {
    expr = evalType nftzones.types.zoneName "web-server";
    expected = "web-server";
  };

  testZoneNameAcceptsDigits = {
    expr = evalType nftzones.types.zoneName "lan2";
    expected = "lan2";
  };

  testZoneNameRejectsUppercase = {
    expr = evalFails (evalType nftzones.types.zoneName "Lan");
    expected = true;
  };

  testZoneNameRejectsLeadingDigit = {
    expr = evalFails (evalType nftzones.types.zoneName "1lan");
    expected = true;
  };

  testZoneNameRejectsEmpty = {
    expr = evalFails (evalType nftzones.types.zoneName "");
    expected = true;
  };

  # ===== zone.name — derives from attrset key =====

  testZoneNameDerivedFromKey = {
    expr = (zoneIn { }).name;
    expected = "lan";
  };

  # `name` is no longer `readOnly`, so the type accepts an explicit
  # value (this is what keeps evaluated zones copy-safe). The
  # `name == key` invariant is enforced at compile time by
  # `internal.normalize.checkNameKeyMismatch`, exercised in
  # `tests/unit/types/name-key.nix`.
  testZoneNameAcceptsExplicitKey = {
    expr =
      (evalTable {
        zones.lan.name = "lan";
      }).zones.lan.name;
    expected = "lan";
  };

  # ===== defaults — every zone field has a sensible empty default =====

  testZoneParentDefault = {
    expr = (zoneIn { }).parent;
    expected = null;
  };

  testZoneInterfacesDefault = {
    expr = (zoneIn { }).interfaces;
    expected = [ ];
  };

  testZoneCidrsDefault = {
    expr = (zoneIn { }).cidrs;
    expected = [ ];
  };

  testZoneMatchOverrideDefaultsAllNull = {
    expr =
      let
        z = zoneIn { };
      in
      {
        ingress = {
          inherit (z.matchOverride.ingress)
            interfaces
            ipv4
            ipv6
            extra
            ;
        };
        egress = {
          inherit (z.matchOverride.egress)
            interfaces
            ipv4
            ipv6
            extra
            ;
        };
      };
    expected = {
      ingress = {
        interfaces = null;
        ipv4 = null;
        ipv6 = null;
        extra = null;
      };
      egress = {
        interfaces = null;
        ipv4 = null;
        ipv6 = null;
        extra = null;
      };
    };
  };

  # ===== zoneInterfaces — libnet's strict interfaceName check =====

  testZoneInterfacesAcceptsValidName = {
    expr = (zoneIn { interfaces = [ "eth0" ]; }).interfaces;
    expected = [ "eth0" ];
  };

  testZoneInterfacesRejectsBadShape = {
    # libnet's interfaceName enforces kernel `dev_valid_name`
    # parity — slashes (and other reserved chars) are rejected.
    expr = evalFails (zoneIn { interfaces = [ "eth/0" ]; }).interfaces;
    expected = true;
  };

  # ===== zoneCidrs — mixed v4/v6, family-aware via libnet =====

  testZoneCidrsAcceptsV4 = {
    expr = (zoneIn { cidrs = [ "10.0.0.0/24" ]; }).cidrs;
    expected = [ "10.0.0.0/24" ];
  };

  testZoneCidrsAcceptsV6 = {
    expr = (zoneIn { cidrs = [ "2001:db8::/32" ]; }).cidrs;
    expected = [ "2001:db8::/32" ];
  };

  testZoneCidrsAcceptsMixed = {
    expr =
      (zoneIn {
        cidrs = [
          "10.0.0.0/24"
          "2001:db8::/32"
        ];
      }).cidrs;
    expected = [
      "10.0.0.0/24"
      "2001:db8::/32"
    ];
  };

  testZoneCidrsRejectsBogus = {
    expr = evalFails (zoneIn { cidrs = [ "not-a-cidr" ]; }).cidrs;
    expected = true;
  };

  # ===== zone.parent — string-or-null shape =====

  testZoneParentAcceptsString = {
    expr = (zoneIn { parent = "wan"; }).parent;
    expected = "wan";
  };

  testZoneParentRejectsBadShape = {
    expr = evalFails (zoneIn { parent = "Bad-Name"; }).parent;
    expected = true;
  };

  # ===== zone.matchOverride.<side>.<section> — list of statements =====

  testZoneMatchOverrideExtraAccepted =
    let
      stmt = nftypes.dsl.eq nftypes.dsl.fields.meta.mark 100;
      z = zoneIn { matchOverride.ingress.extra = [ stmt ]; };
    in
    {
      expr = z.matchOverride.ingress.extra;
      expected = [ stmt ];
    };
}
