"""Stdlib-only tests for pipeline/export/sqlite.py (PRD 17.1).

The Ruby suite drives sqlite.py as a subprocess and checks what came back.
Nothing exercised the writer's own units: the spool binding rules, the
schema application, the refusals, or the lookup query that PRD 10.4 makes
normative. Those are what this file covers, in-process, with no third-party
packages and no network - the same constraint the writer itself lives under.

The module is imported BY PATH rather than by package name. sqlite.py is a
build tool that ships inside the pipeline tree, not an installed package,
and importing it the way the release producer runs it is the point: a test
that imported some other copy would pass while the shipped one was broken.

Run it through `rake exports:python_test`, which resolves the interpreter
explicitly (sqlite.rb's CANDIDATES) and prints sys.version and
sqlite3.sqlite_version first. WHICH interpreter matters: sqlite3.sqlite_version
decides the physical database file, so a green suite under an engine that
never writes a release is a green suite about nothing.
"""

import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WRITER_PATH = os.path.join(ROOT, "pipeline", "export", "sqlite.py")


def load_writer():
    spec = importlib.util.spec_from_file_location("openasn_sqlite_writer", WRITER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


writer = load_writer()


# --------------------------------------------------------------------------
# fixtures


def record(version, start_hex, end_hex, **overrides):
    """One spool line, with every column present, as Spool.line_for emits it."""
    base = {
        "ip_version": version,
        "start_hex": start_hex,
        "end_hex": end_hex,
        "asn": 64496,
        "as_org": 'Example ISP, S.L. "Fibra"',
        "category": "isp",
        "network_role": "access_provider",
        "bad_asn": False,
        "vpn_provider": False,
        "mobile_carrier": False,
        "enterprise_gw": False,
        "cdn": False,
        "hosting_extra": False,
        "vpn_range": False,
        "datacenter_range": False,
        "core_verdict": "residential_isp",
        "core_sources": ["asn_category"],
    }
    base.update(overrides)
    return base


V4_ONE = record(4, "c0000200", "c000027f")
V4_TWO = record(4, "c6336400", "c63364ff", asn=64498, as_org="Example Hosting & CDN",
                category="hosting", network_role="content_network", cdn=True,
                core_verdict="hosting", core_sources=["asn_cdn", "asn_category"])
V6_ONE = record(6, "20010db8" + "0" * 24, "20010db8" + "0" * 20 + "ffff",
                asn=64502, as_org=u"Örebro Stadsnät AB", mobile_carrier=True,
                core_verdict="mobile", core_sources=["asn_mobile_carrier"])


def metadata_for(v4, v6):
    """Only strings: meta.v is TEXT for every key (PRD 10.2)."""
    return {
        "schema_version": "1",
        "schema_revision": "0",
        "classification_profile": "core-v1",
        "build_id": "2026-09-09T07:06:40Z",
        "records_ipv4": str(v4),
        "records_ipv6": str(v6),
        "records_total": str(v4 + v6),
    }


class WriterCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def write_spool(self, records, name="records.jsonl"):
        path = self.path(name)
        with open(path, "w", encoding="utf-8") as handle:
            for item in records:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        return path

    def write_metadata(self, data, name="metadata.json"):
        path = self.path(name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return path

    def build(self, records, metadata=None, output="openasn.sqlite"):
        v4 = len([r for r in records if r["ip_version"] == 4])
        v6 = len([r for r in records if r["ip_version"] == 6])
        spool = self.write_spool(records)
        meta = self.write_metadata(metadata or metadata_for(v4, v6))
        database = self.path(output)
        return database, spool, meta, writer.build(spool, meta, database)


# --------------------------------------------------------------------------
# metadata and spool parsing


class MetadataTest(WriterCase):
    def test_every_value_must_be_text(self):
        path = self.write_metadata({"schema_version": 1})
        with self.assertRaises(writer.Failure) as caught:
            writer.read_metadata(path)
        self.assertIn("not a string", str(caught.exception))

    def test_an_empty_object_is_not_metadata(self):
        path = self.write_metadata({})
        with self.assertRaises(writer.Failure):
            writer.read_metadata(path)

    def test_a_good_document_round_trips(self):
        data = metadata_for(1, 0)
        self.assertEqual(writer.read_metadata(self.write_metadata(data)), data)


class SpoolTest(WriterCase):
    def test_blank_lines_are_skipped_and_line_numbers_stay_true(self):
        path = self.path("records.jsonl")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n")
            handle.write(json.dumps(V4_ONE) + "\n")
        parsed = list(writer.iter_spool(path))
        self.assertEqual(len(parsed), 1)
        # Line 2, not line 1: a failure message has to point at the file.
        self.assertEqual(parsed[0][0], 2)
        self.assertEqual(parsed[0][1], "v4")

    def test_an_unparseable_line_names_its_number(self):
        path = self.path("records.jsonl")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(V4_ONE) + "\n")
            handle.write("{not json\n")
        with self.assertRaises(writer.Failure) as caught:
            list(writer.iter_spool(path))
        self.assertIn("line 2", str(caught.exception))

    def test_an_unknown_ip_version_is_refused(self):
        path = self.write_spool([record(5, "00000000", "000000ff")])
        with self.assertRaises(writer.Failure) as caught:
            list(writer.iter_spool(path))
        self.assertIn("ip_version", str(caught.exception))


class EndpointTest(unittest.TestCase):
    def test_ipv4_decodes_to_an_integer_and_ipv6_to_sixteen_bytes(self):
        self.assertEqual(writer.endpoint("v4", V4_ONE, "start", 1), 0xC0000200)
        value = writer.endpoint("v6", V6_ONE, "start", 1)
        self.assertIsInstance(value, bytes)
        self.assertEqual(len(value), 16)
        self.assertEqual(value[:4], b"\x20\x01\x0d\xb8")

    def test_the_width_is_fixed_per_family(self):
        with self.assertRaises(writer.Failure) as caught:
            writer.endpoint("v6", record(6, "20010db8", "20010db8"), "start", 7)
        self.assertIn("32 hex characters", str(caught.exception))

    def test_uppercase_hex_is_refused_rather_than_normalized(self):
        # A lexical sort of the spool is also a numeric sort only while the
        # hex is lowercase; accepting mixed case would silently break that.
        with self.assertRaises(writer.Failure) as caught:
            writer.endpoint("v4", record(4, "C0000200", "c000027f"), "start", 3)
        self.assertIn("lowercase", str(caught.exception))

    def test_non_hex_of_the_right_width_is_refused(self):
        with self.assertRaises(writer.Failure):
            writer.endpoint("v4", record(4, "zzzzzzzz", "c000027f"), "start", 3)


class BindValueTest(unittest.TestCase):
    def test_booleans_bind_as_explicit_integers(self):
        # Python's bool IS an int, so this would "work" by accident here and
        # nowhere else. The explicit branch is what the test is about.
        self.assertEqual(writer.bind_value("cdn", True, 1), 1)
        self.assertEqual(writer.bind_value("cdn", False, 1), 0)
        self.assertNotIsInstance(writer.bind_value("cdn", True, 1), bool)

    def test_null_stays_null(self):
        self.assertIsNone(writer.bind_value("as_org", None, 1))

    def test_a_source_list_becomes_compact_json_text(self):
        self.assertEqual(writer.bind_value("core_sources", ["a", "b"], 1), '["a","b"]')

    def test_a_non_string_source_is_refused(self):
        with self.assertRaises(writer.Failure):
            writer.bind_value("core_sources", ["a", 2], 1)

    def test_a_value_with_no_binding_is_refused_rather_than_stringified(self):
        with self.assertRaises(writer.Failure) as caught:
            writer.bind_value("as_org", {"name": "x"}, 1)
        self.assertIn("no SQLite binding", str(caught.exception))


class RowForTest(unittest.TestCase):
    COLUMNS = ["start", "end", "asn", "as_org", "category", "network_role", "bad_asn",
               "vpn_provider", "mobile_carrier", "enterprise_gw", "cdn", "hosting_extra",
               "vpn_range", "datacenter_range", "core_verdict", "core_sources"]

    def test_a_missing_column_names_itself(self):
        broken = dict(V4_ONE)
        del broken["cdn"]
        with self.assertRaises(writer.Failure) as caught:
            writer.row_for("v4", self.COLUMNS, broken, 4)
        self.assertIn("cdn", str(caught.exception))

    def test_an_unknown_field_is_refused_rather_than_dropped(self):
        extra = dict(V4_ONE)
        extra["tor_exit"] = True
        with self.assertRaises(writer.Failure) as caught:
            writer.row_for("v4", self.COLUMNS, extra, 4)
        self.assertIn("tor_exit", str(caught.exception))


# --------------------------------------------------------------------------
# schema


class SchemaTest(WriterCase):
    def test_the_column_list_comes_from_the_tracked_sql_file(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        columns = writer.apply_schema(conn)
        self.assertEqual(columns[:2], ["start", "end"])
        self.assertEqual(columns, writer.schema_columns(conn, "v6"))
        self.assertIn("core_sources", columns)
        # One logical record, two tables: a difference here is a schema bug
        # that would make the two families disagree about their own shape.
        self.assertEqual(writer.schema_columns(conn, "v4"), writer.schema_columns(conn, "v6"))


# --------------------------------------------------------------------------
# build and verify


class BuildTest(WriterCase):
    def test_a_good_spool_builds_and_verifies(self):
        database, _, _, report = self.build([V4_ONE, V4_TWO, V6_ONE])
        self.assertEqual(report["rows"], {"v4": 2, "v6": 1, "total": 3})
        self.assertEqual(report["integrity_check"], "ok")
        self.assertEqual(report["user_version"], 1)
        self.assertEqual(report["page_size"], 4096)
        # The engine that wrote the file, reported by the file's own writer.
        self.assertEqual(report["sqlite_version"], sqlite3.sqlite_version)
        self.assertTrue(os.path.isfile(database))

    def test_the_database_is_a_single_self_contained_file(self):
        database, _, _, _ = self.build([V4_ONE, V6_ONE])
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.exists(database + suffix), suffix)

    def test_values_store_with_the_types_the_schema_promises(self):
        database, _, _, _ = self.build([V4_ONE, V6_ONE])
        conn = writer.open_readonly(database)
        self.addCleanup(conn.close)
        row = conn.execute("SELECT start, end, as_org, cdn, core_sources FROM v4").fetchone()
        self.assertIsInstance(row[0], int)
        self.assertEqual(row[2], 'Example ISP, S.L. "Fibra"')
        self.assertEqual(row[3], 0)
        self.assertEqual(row[4], '["asn_category"]')
        start = conn.execute("SELECT start FROM v6").fetchone()[0]
        self.assertIsInstance(start, bytes)
        self.assertEqual(len(start), 16)

    def test_a_null_org_stays_null_rather_than_an_empty_string(self):
        database, _, _, _ = self.build([record(4, "c0000200", "c000027f", as_org=None)])
        conn = writer.open_readonly(database)
        self.addCleanup(conn.close)
        self.assertIsNone(conn.execute("SELECT as_org FROM v4").fetchone()[0])

    def test_it_refuses_to_overwrite_an_existing_output(self):
        database, spool, meta, _ = self.build([V4_ONE])
        with self.assertRaises(writer.Failure) as caught:
            writer.build(spool, meta, database)
        self.assertIn("already exists", str(caught.exception))

    def test_a_failed_build_leaves_no_half_written_candidate(self):
        spool = self.write_spool([V4_ONE, record(4, "c0000200", "c000027f")])
        meta = self.write_metadata(metadata_for(2, 0))
        database = self.path("openasn.sqlite")
        with self.assertRaises(writer.Failure):
            writer.build(spool, meta, database)
        self.assertFalse(os.path.exists(database))

    def test_an_unsorted_family_is_refused(self):
        with self.assertRaises(writer.Failure) as caught:
            self.build([V4_TWO, V4_ONE])
        self.assertIn("ascending", str(caught.exception))

    def test_overlapping_intervals_are_refused(self):
        with self.assertRaises(writer.Failure) as caught:
            self.build([record(4, "c0000200", "c00002ff"),
                        record(4, "c0000280", "c00003ff")])
        self.assertIn("overlaps", str(caught.exception))

    def test_an_inverted_interval_is_refused(self):
        with self.assertRaises(writer.Failure) as caught:
            self.build([record(4, "c00002ff", "c0000200")])
        self.assertIn("end precedes start", str(caught.exception))

    def test_the_spool_must_be_all_ipv4_then_all_ipv6(self):
        with self.assertRaises(writer.Failure) as caught:
            self.build([V4_ONE, V6_ONE, V4_TWO])
        self.assertIn("spool order", str(caught.exception))

    def test_metadata_that_disagrees_with_the_rows_is_refused(self):
        with self.assertRaises(writer.Failure) as caught:
            self.build([V4_ONE, V4_TWO, V6_ONE], metadata=metadata_for(99, 1))
        self.assertIn("records_ipv4", str(caught.exception))


class VerifyTest(WriterCase):
    def test_verify_rejects_a_row_that_no_longer_matches_the_spool(self):
        database, spool, meta, _ = self.build([V4_ONE, V4_TWO, V6_ONE])
        conn = sqlite3.connect(database)
        conn.execute("UPDATE v4 SET core_verdict = 'hosting' WHERE start = ?", (0xC0000200,))
        conn.commit()
        conn.close()
        with self.assertRaises(writer.Failure) as caught:
            writer.verify(database, spool, meta)
        self.assertIn("core_verdict", str(caught.exception))

    def test_verify_rejects_a_database_with_fewer_rows_than_the_spool(self):
        database, spool, meta, _ = self.build([V4_ONE, V4_TWO, V6_ONE])
        conn = sqlite3.connect(database)
        conn.execute("DELETE FROM v6")
        conn.commit()
        conn.close()
        with self.assertRaises(writer.Failure) as caught:
            writer.verify(database, spool, meta)
        self.assertIn("more rows than the database", str(caught.exception))

    def test_verify_rejects_a_database_with_more_rows_than_the_spool(self):
        database, spool, meta, _ = self.build([V4_ONE, V4_TWO, V6_ONE])
        conn = sqlite3.connect(database)
        # Appended to v6, the LAST table read, so the extra row is surplus to
        # an exhausted spool rather than a family mismatch mid-stream.
        conn.execute("INSERT INTO v6 SELECT X'fd000000000000000000000000000000', "
                     "X'fd0000000000000000000000000000ff', asn, as_org, category, "
                     "network_role, bad_asn, vpn_provider, mobile_carrier, enterprise_gw, cdn, "
                     "hosting_extra, vpn_range, datacenter_range, core_verdict, core_sources "
                     "FROM v6 LIMIT 1")
        conn.commit()
        conn.close()
        with self.assertRaises(writer.Failure) as caught:
            writer.verify(database, spool, meta)
        self.assertIn("more rows than the spool", str(caught.exception))

    def test_verify_rejects_a_missing_database(self):
        with self.assertRaises(writer.Failure):
            writer.verify(self.path("nope.sqlite"), self.path("nope.jsonl"),
                          self.write_metadata(metadata_for(0, 0)))

    def test_a_secondary_index_is_refused(self):
        # An index nobody declared changes the bytes and the query plan; the
        # lookup is a primary-key search by contract (PRD 10.4).
        database, spool, meta, _ = self.build([V4_ONE, V4_TWO])
        conn = sqlite3.connect(database)
        conn.execute("CREATE INDEX v4_end ON v4(end)")
        conn.commit()
        conn.close()
        with self.assertRaises(writer.Failure) as caught:
            writer.verify(database, spool, meta)
        self.assertIn("index", str(caught.exception))


class ReadOnlyTest(WriterCase):
    def test_open_readonly_cannot_write(self):
        database, _, _, _ = self.build([V4_ONE])
        conn = writer.open_readonly(database)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("DELETE FROM v4")


# --------------------------------------------------------------------------
# the normative lookup (PRD 10.4)


class LookupTest(WriterCase):
    def setUp(self):
        super().setUp()
        # A deliberate gap between the two IPv4 rows: the interesting case
        # is an address whose PREDECESSOR exists but does not contain it.
        self.database, _, _, _ = self.build([V4_ONE, V4_TWO, V6_ONE])
        self.conn = writer.open_readonly(self.database)
        self.addCleanup(self.conn.close)

    def test_the_first_and_last_address_of_an_interval_hit(self):
        for probe in (0xC0000200, 0xC000027F):
            row = writer.lookup(self.conn, "v4", probe)
            self.assertIsNotNone(row, hex(probe))
            self.assertEqual(row[0], 0xC0000200)

    def test_an_interior_address_hits(self):
        row = writer.lookup(self.conn, "v4", 0xC0000240)
        self.assertEqual(row[0], 0xC0000200)

    def test_the_address_after_an_interval_misses(self):
        self.assertIsNone(writer.lookup(self.conn, "v4", 0xC0000280))

    def test_an_address_below_every_interval_misses(self):
        self.assertIsNone(writer.lookup(self.conn, "v4", 0x01010101))

    def test_ipv6_matches_through_a_sixteen_byte_blob_key(self):
        base = int("20010db8" + "0" * 24, 16)
        row = writer.lookup(self.conn, "v6", base + 0x1000)
        self.assertIsNotNone(row)
        self.assertEqual(row[0], bytes.fromhex("20010db8" + "0" * 24))
        self.assertIsNone(writer.lookup(self.conn, "v6", base + 0x1_0000))

    def test_the_plan_searches_the_primary_key_in_both_families(self):
        plans = writer.verify_query_plans(self.conn)
        for table in ("v4", "v6"):
            detail = " | ".join(plans[table])
            self.assertIn("PRIMARY KEY", detail)
            self.assertNotIn("SCAN %s" % table, detail)
            self.assertNotIn("TEMP B-TREE", detail)

    def test_the_seeded_probe_sweep_reports_hits_and_misses(self):
        checked = writer.verify_queries(self.conn)
        self.assertEqual(checked["seed"], writer.QUERY_SEED)
        self.assertGreater(checked["hits"], 0)
        self.assertGreater(checked["misses"], 0)


# --------------------------------------------------------------------------
# the CLI the Ruby side drives


class CliTest(WriterCase):
    def test_build_then_verify_print_one_json_object_each(self):
        import io

        spool = self.write_spool([V4_ONE, V4_TWO, V6_ONE])
        meta = self.write_metadata(metadata_for(2, 1))
        database = self.path("openasn.sqlite")

        captured = io.StringIO()
        original = sys.stdout
        sys.stdout = captured
        try:
            code = writer.main(["build", "--records", spool, "--metadata", meta,
                                "--output", database])
        finally:
            sys.stdout = original
        self.assertEqual(code, 0)
        report = json.loads(captured.getvalue())
        self.assertEqual(report["mode"], "build")
        self.assertEqual(report["interpreter"], sys.executable)
        self.assertEqual(report["rows"]["total"], 3)

    def test_a_failure_exits_nonzero_without_printing_a_report(self):
        import io

        spool = self.write_spool([record(4, "C0000200", "c000027f")])
        meta = self.write_metadata(metadata_for(1, 0))
        captured = io.StringIO()
        errors = io.StringIO()
        original_out, original_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = captured, errors
        try:
            code = writer.main(["build", "--records", spool, "--metadata", meta,
                                "--output", self.path("openasn.sqlite")])
        finally:
            sys.stdout, sys.stderr = original_out, original_err
        self.assertEqual(code, 1)
        self.assertEqual(captured.getvalue(), "")
        self.assertIn("FAILED", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
