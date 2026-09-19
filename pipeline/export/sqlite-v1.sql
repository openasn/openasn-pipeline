-- Normative SQLite schema: export v1 / core-v1 / lookup policy 1.
-- EXPORT_FORMATS.md is the authority for semantic and cross-row validation.
-- No JSON1 or STRICT-table dependency. core_sources is canonical JSON text.
PRAGMA page_size = 4096;
PRAGMA journal_mode = DELETE;
PRAGMA user_version = 1;

CREATE TABLE v4 (
  start INTEGER PRIMARY KEY CHECK(typeof(start) = 'integer' AND start BETWEEN 0 AND 4294967295),
  end INTEGER NOT NULL CHECK(typeof(end) = 'integer' AND end BETWEEN start AND 4294967295),
  asn INTEGER CHECK(asn IS NULL OR (typeof(asn) = 'integer' AND asn BETWEEN 0 AND 4294967295)),
  as_org TEXT CHECK(as_org IS NULL OR (typeof(as_org) = 'text' AND length(CAST(as_org AS BLOB)) BETWEEN 1 AND 96)),
  category TEXT CHECK(category IS NULL OR category IN ('isp','hosting','business','education_research','government_admin')),
  network_role TEXT CHECK(network_role IS NULL OR network_role IN ('tier1_transit','major_transit','midsize_transit','access_provider','content_network','stub')),
  bad_asn INTEGER NOT NULL CHECK(typeof(bad_asn) = 'integer' AND bad_asn IN (0,1)),
  vpn_provider INTEGER NOT NULL CHECK(typeof(vpn_provider) = 'integer' AND vpn_provider IN (0,1)),
  mobile_carrier INTEGER NOT NULL CHECK(typeof(mobile_carrier) = 'integer' AND mobile_carrier IN (0,1)),
  enterprise_gw INTEGER NOT NULL CHECK(typeof(enterprise_gw) = 'integer' AND enterprise_gw IN (0,1)),
  cdn INTEGER NOT NULL CHECK(typeof(cdn) = 'integer' AND cdn IN (0,1)),
  hosting_extra INTEGER NOT NULL CHECK(typeof(hosting_extra) = 'integer' AND hosting_extra IN (0,1)),
  vpn_range INTEGER NOT NULL CHECK(typeof(vpn_range) = 'integer' AND vpn_range IN (0,1)),
  datacenter_range INTEGER NOT NULL CHECK(typeof(datacenter_range) = 'integer' AND datacenter_range IN (0,1)),
  core_verdict TEXT NOT NULL CHECK(core_verdict IN ('residential_isp','mobile','business','hosting','vpn','enterprise_gateway','education','government','unknown')),
  core_sources TEXT NOT NULL CHECK(typeof(core_sources) = 'text'),
  CHECK(asn IS NOT NULL OR (
    as_org IS NULL AND category IS NULL AND network_role IS NULL AND
    bad_asn = 0 AND vpn_provider = 0 AND mobile_carrier = 0 AND
    enterprise_gw = 0 AND cdn = 0 AND hosting_extra = 0
  ))
);

CREATE TABLE v6 (
  start BLOB PRIMARY KEY NOT NULL CHECK(typeof(start) = 'blob' AND length(start) = 16),
  end BLOB NOT NULL CHECK(typeof(end) = 'blob' AND length(end) = 16 AND end >= start),
  asn INTEGER CHECK(asn IS NULL OR (typeof(asn) = 'integer' AND asn BETWEEN 0 AND 4294967295)),
  as_org TEXT CHECK(as_org IS NULL OR (typeof(as_org) = 'text' AND length(CAST(as_org AS BLOB)) BETWEEN 1 AND 96)),
  category TEXT CHECK(category IS NULL OR category IN ('isp','hosting','business','education_research','government_admin')),
  network_role TEXT CHECK(network_role IS NULL OR network_role IN ('tier1_transit','major_transit','midsize_transit','access_provider','content_network','stub')),
  bad_asn INTEGER NOT NULL CHECK(typeof(bad_asn) = 'integer' AND bad_asn IN (0,1)),
  vpn_provider INTEGER NOT NULL CHECK(typeof(vpn_provider) = 'integer' AND vpn_provider IN (0,1)),
  mobile_carrier INTEGER NOT NULL CHECK(typeof(mobile_carrier) = 'integer' AND mobile_carrier IN (0,1)),
  enterprise_gw INTEGER NOT NULL CHECK(typeof(enterprise_gw) = 'integer' AND enterprise_gw IN (0,1)),
  cdn INTEGER NOT NULL CHECK(typeof(cdn) = 'integer' AND cdn IN (0,1)),
  hosting_extra INTEGER NOT NULL CHECK(typeof(hosting_extra) = 'integer' AND hosting_extra IN (0,1)),
  vpn_range INTEGER NOT NULL CHECK(typeof(vpn_range) = 'integer' AND vpn_range IN (0,1)),
  datacenter_range INTEGER NOT NULL CHECK(typeof(datacenter_range) = 'integer' AND datacenter_range IN (0,1)),
  core_verdict TEXT NOT NULL CHECK(core_verdict IN ('residential_isp','mobile','business','hosting','vpn','enterprise_gateway','education','government','unknown')),
  core_sources TEXT NOT NULL CHECK(typeof(core_sources) = 'text'),
  CHECK(asn IS NOT NULL OR (
    as_org IS NULL AND category IS NULL AND network_role IS NULL AND
    bad_asn = 0 AND vpn_provider = 0 AND mobile_carrier = 0 AND
    enterprise_gw = 0 AND cdn = 0 AND hosting_extra = 0
  ))
) WITHOUT ROWID;

CREATE TABLE meta (
  k TEXT PRIMARY KEY NOT NULL CHECK(typeof(k) = 'text' AND length(k) > 0),
  v TEXT NOT NULL CHECK(typeof(v) = 'text')
) WITHOUT ROWID;

