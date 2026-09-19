#!/usr/bin/env python3
"""Build-only SQLite writer and verifier for the OpenASN portable exports.

PRD sections 10 and 14. Two modes, both offline, both stdlib only:

    sqlite.py build  --records PATH --metadata PATH --output PATH
    sqlite.py verify --database PATH --records PATH --metadata PATH

Exit 0 means the output (or the database under test) is completely valid;
any nonzero exit means the stage failed, with the reason on stderr. There is
no partial success: a half-written candidate is deleted, never promoted.

WHY PYTHON AT ALL, in an otherwise stdlib-Ruby pipeline: the SQLite engine
has to come from somewhere, and Python ships one. That makes WHICH Python
runs this file part of the release contract - sqlite3.sqlite_version decides
the physical bytes - so the interpreter is resolved explicitly by the Ruby
side (see sqlite.rb) and recorded in metadata's `producer` block. This file
defends the same rule from the inside: it refuses to run on anything below
3.9 and names the interpreter that ran it, because the failure it is
guarding against is a bare `python3` resolving to some other install.

That guard is also why this file contains no f-strings and no modern syntax:
a SyntaxError on an old interpreter would hide the very message the reader
needs. It has to PARSE on the wrong Python in order to complain about it.

The column list is never typed out here. It is read from the tracked schema
via PRAGMA table_info, so this writer cannot drift from sqlite-v1.sql, and
sqlite-v1.sql cannot drift from the copy published in the data repo's
conformance directory. One source of schema truth, as PRD 10.1 requires.
"""

import sys

MIN_PYTHON = (3, 9)
if sys.version_info < MIN_PYTHON:
    sys.stderr.write(
        "openasn sqlite writer: needs Python >= %d.%d, but ran under %s (%s).\n"
        "Set OPENASN_PYTHON to a suitable interpreter; do not rely on PATH order.\n"
        % (MIN_PYTHON[0], MIN_PYTHON[1],
           ".".join(str(p) for p in sys.version_info[:3]), sys.executable)
    )
    raise SystemExit(2)

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import random  # noqa: E402

try:
    import sqlite3
except ImportError as exc:  # pragma: no cover - a Python built without sqlite3
    sys.stderr.write(
        "openasn sqlite writer: %s has no sqlite3 module (%s).\n" % (sys.executable, exc)
    )
    raise SystemExit(2)

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sqlite-v1.sql")

TABLES = ("v4", "v6")
IP_VERSION = {"v4": 4, "v6": 6}
HEX_WIDTH = {"v4": 8, "v6": 32}
# Columns the spool supplies under a different name: the spool carries
# fixed-width hex endpoints, the database stores an integer or a 16-byte key.
ENDPOINTS = ("start", "end")

# PRD 10.4. The predecessor is isolated first, then containment is checked;
# the outer `end >= :ip` is what turns "the row before this address" into
# "the row containing this address" and must never be dropped.
LOOKUP_SQL = (
    "SELECT * FROM ("
    "SELECT * FROM {table} WHERE start <= :ip ORDER BY start DESC LIMIT 1"
    ") AS candidate WHERE end >= :ip"
)

# Seeded so a failing probe is reproducible from the log line alone.
QUERY_SEED = 20260918
QUERY_SAMPLES = 400


class Failure(Exception):
    """A validation failure with an actionable, stage-named message."""


# --------------------------------------------------------------------------
# spool and metadata


def read_metadata(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not data:
        raise Failure("metadata %s is not a nonempty JSON object" % path)
    for key, value in data.items():
        if not isinstance(key, str) or key == "":
            raise Failure("metadata key %r is not a nonempty string" % (key,))
        if not isinstance(value, str):
            # meta.v is TEXT for every key; an integer here would store as an
            # integer and break every consumer that compares strings.
            raise Failure("metadata[%s] is %s, not a string" % (key, type(value).__name__))
    return data


def iter_spool(path):
    """Yields (table, record) for every spool line, in file order."""
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                raise Failure("spool line %d is not JSON: %s" % (number, exc))
            version = record.get("ip_version")
            if version == 4:
                table = "v4"
            elif version == 6:
                table = "v6"
            else:
                raise Failure("spool line %d has ip_version %r" % (number, version))
            yield number, table, record


def endpoint(table, record, name, number):
    hex_text = record.get(name + "_hex")
    width = HEX_WIDTH[table]
    if not isinstance(hex_text, str) or len(hex_text) != width:
        raise Failure(
            "spool line %d: %s_hex %r is not %d hex characters" % (number, name, hex_text, width)
        )
    if hex_text != hex_text.lower():
        raise Failure("spool line %d: %s_hex %r is not lowercase" % (number, name, hex_text))
    try:
        value = int(hex_text, 16)
    except ValueError:
        raise Failure("spool line %d: %s_hex %r is not hex" % (number, name, hex_text))
    if table == "v4":
        return value
    return bytes.fromhex(hex_text)


def bind_value(column, value, number):
    """JSON payload value -> SQLite binding, with no implicit coercion.

    Booleans become explicit 0/1 ints (Python's bool is an int subclass, so
    leaving them alone would store True and read back as 1 anyway - but only
    by accident, and only in Python). Nulls stay null. A source list becomes
    the compact JSON text the schema documents.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str) or item == "":
                raise Failure("spool line %d: %s has a non-string source %r" % (number, column, item))
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    raise Failure("spool line %d: %s is %s, which has no SQLite binding"
                  % (number, column, type(value).__name__))


def row_for(table, columns, record, number):
    values = []
    for column in columns:
        if column in ENDPOINTS:
            values.append(endpoint(table, record, column, number))
            continue
        if column not in record:
            raise Failure("spool line %d is missing %s" % (number, column))
        values.append(bind_value(column, record[column], number))

    extra = set(record) - set(columns) - set(["ip_version", "start_hex", "end_hex"])
    if extra:
        raise Failure("spool line %d has unknown field(s) %s" % (number, ", ".join(sorted(extra))))
    return tuple(values)


# --------------------------------------------------------------------------
# schema


def schema_columns(conn, table):
    columns = [row[1] for row in conn.execute("PRAGMA table_info(%s)" % table)]
    if not columns:
        raise Failure("schema has no table %s" % table)
    if columns[0:2] != list(ENDPOINTS):
        raise Failure("%s starts with %s, not %s" % (table, columns[0:2], list(ENDPOINTS)))
    return columns


def apply_schema(conn):
    with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
        conn.executescript(handle.read())
    columns = dict((table, schema_columns(conn, table)) for table in TABLES)
    if columns["v4"] != columns["v6"]:
        raise Failure("v4 and v6 have different columns; one logical record, two tables")
    return columns["v4"]


# --------------------------------------------------------------------------
# build


def build(records_path, metadata_path, output_path):
    metadata = read_metadata(metadata_path)
    for path in (records_path, metadata_path):
        if not os.path.isfile(path):
            raise Failure("input missing: %s" % path)
    if os.path.exists(output_path):
        # A writer that overwrites is a writer that can destroy the artifact
        # it was asked to describe. The caller stages a fresh candidate.
        raise Failure("output %s already exists; write a fresh candidate path" % output_path)
    directory = os.path.dirname(os.path.abspath(output_path))
    if not os.path.isdir(directory):
        raise Failure("output directory missing: %s" % directory)

    counts = {"v4": 0, "v6": 0}
    conn = sqlite3.connect(output_path, isolation_level=None)
    try:
        columns = apply_schema(conn)
        insert = "INSERT INTO {table} VALUES ({marks})"
        marks = ",".join(["?"] * len(columns))

        conn.execute("BEGIN")
        # One pass over the spool, in its own order: IPv4 rows then IPv6
        # rows, each family ascending. Rows go in in primary-key order, so
        # the b-tree is filled left to right and never needs a VACUUM.
        table = None
        batch = []
        previous_start = None
        previous_end = None
        for number, row_table, record in iter_spool(records_path):
            if row_table != table:
                if table is not None:
                    if batch:
                        conn.executemany(insert.format(table=table, marks=marks), batch)
                        batch = []
                    if (table, row_table) != ("v4", "v6"):
                        raise Failure("spool line %d returns to %s after %s; spool order is all IPv4 "
                                      "then all IPv6" % (number, row_table, table))
                table = row_table
                previous_start = None
                previous_end = None

            values = row_for(table, columns, record, number)
            start, end = values[0], values[1]
            if end < start:
                raise Failure("spool line %d: end precedes start" % number)
            if previous_start is not None:
                if start <= previous_start:
                    raise Failure("spool line %d: %s start is not ascending (duplicate or unsorted row)"
                                  % (number, table))
                if start <= previous_end:
                    raise Failure("spool line %d: %s overlaps the previous row" % (number, table))
            previous_start, previous_end = start, end
            batch.append(values)
            counts[table] += 1
            if len(batch) >= 20000:
                conn.executemany(insert.format(table=table, marks=marks), batch)
                batch = []
        if batch:
            conn.executemany(insert.format(table=table, marks=marks), batch)

        conn.executemany(
            "INSERT INTO meta (k, v) VALUES (?, ?)",
            [(key, metadata[key]) for key in sorted(metadata)],
        )
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        if os.path.exists(output_path):
            os.remove(output_path)
        raise
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass

    report = verify(output_path, records_path, metadata_path)
    report["inserted"] = counts
    if counts != dict((table, report["rows"][table]) for table in TABLES):
        raise Failure("inserted %r rows, read back %r" % (counts, report["rows"]))
    return report


# --------------------------------------------------------------------------
# verify


def open_readonly(path):
    uri = "file:" + path.replace("?", "%3f").replace("#", "%23") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def verify(database_path, records_path, metadata_path):
    if not os.path.isfile(database_path):
        raise Failure("database missing: %s" % database_path)
    metadata = read_metadata(metadata_path)

    conn = open_readonly(database_path)
    try:
        report = verify_structure(conn, database_path)
        columns = dict((table, schema_columns(conn, table)) for table in TABLES)
        if columns["v4"] != columns["v6"]:
            raise Failure("v4 and v6 have different columns; one logical record, two tables")
        report["rows"] = verify_rows(conn, columns["v4"], records_path)
        verify_meta(conn, metadata, report["rows"])
        report["plans"] = verify_query_plans(conn)
        report["queries"] = verify_queries(conn)
    finally:
        conn.close()

    # DELETE journal mode plus a clean close means the database is one file.
    # A leftover sidecar would make the published .gz incomplete.
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = database_path + suffix
        if os.path.exists(sidecar):
            raise Failure("database needs sidecar %s; it must be a single self-contained file" % sidecar)
    report["bytes"] = os.path.getsize(database_path)
    return report


def verify_structure(conn, database_path):
    integrity = [row[0] for row in conn.execute("PRAGMA integrity_check")]
    if integrity != ["ok"]:
        raise Failure("integrity_check: %s" % "; ".join(integrity))

    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if user_version != 1:
        raise Failure("user_version is %r, expected 1" % (user_version,))
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    if page_size != 4096:
        raise Failure("page_size is %r, expected 4096" % (page_size,))
    journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
    if str(journal).lower() != "delete":
        raise Failure("journal_mode is %r, expected delete" % (journal,))

    names = sorted(
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    )
    if names != ["meta", "v4", "v6"]:
        raise Failure("tables are %s, expected meta, v4, v6" % ", ".join(names))
    indexes = sorted(
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL"
        )
    )
    if indexes:
        raise Failure("unexpected secondary index(es): %s" % ", ".join(indexes))

    return {
        "database": os.path.basename(database_path),
        "sqlite_version": sqlite3.sqlite_version,
        "python": sys.version.split()[0],
        "integrity_check": "ok",
        "user_version": user_version,
        "page_size": page_size,
        "journal_mode": journal,
    }


def verify_rows(conn, columns, records_path):
    """Every stored row against the spool, streamed and ordered.

    Also re-derives the two cross-row invariants from the DATA rather than
    trusting the DDL: intervals must not overlap, and two adjacent intervals
    must never carry an identical payload (they would have been coalesced).
    """
    counts = {"v4": 0, "v6": 0}
    spool = iter_spool(records_path)
    for table in TABLES:
        cursor = conn.execute(
            "SELECT %s FROM %s ORDER BY start" % (",".join('"%s"' % c for c in columns), table)
        )
        previous_end = None
        previous_payload = None
        for stored in cursor:
            try:
                number, row_table, record = next(spool)
            except StopIteration:
                raise Failure("%s has more rows than the spool" % table)
            if row_table != table:
                raise Failure(
                    "spool line %d is %s while reading %s; spool order is all IPv4 then all IPv6"
                    % (number, row_table, table)
                )
            expected = row_for(table, columns, record, number)
            if tuple(stored) != expected:
                for index, column in enumerate(columns):
                    if stored[index] != expected[index]:
                        raise Failure(
                            "spool line %d: %s.%s is %r in the database, %r in the spool"
                            % (number, table, column, stored[index], expected[index])
                        )
                raise Failure("spool line %d: %s row differs from the spool" % (number, table))

            start, end = stored[0], stored[1]
            payload = tuple(stored[2:])
            if previous_end is not None:
                if start <= previous_end:
                    raise Failure("%s: interval starting %r overlaps the previous one" % (table, start))
                adjacent = (
                    start == previous_end + 1 if table == "v4"
                    else int.from_bytes(start, "big") == int.from_bytes(previous_end, "big") + 1
                )
                if adjacent and payload == previous_payload:
                    raise Failure(
                        "%s: adjacent intervals ending %r carry an identical payload; the projection "
                        "must coalesce them" % (table, previous_end)
                    )
            previous_end, previous_payload = end, payload
            counts[table] += 1

    remaining = next(spool, None)
    if remaining is not None:
        raise Failure("the spool has more rows than the database (from line %d)" % remaining[0])
    counts["total"] = counts["v4"] + counts["v6"]
    return counts


def verify_meta(conn, metadata, counts):
    stored = dict(conn.execute("SELECT k, v FROM meta"))
    missing = sorted(set(metadata) - set(stored))
    if missing:
        raise Failure("meta is missing %s" % ", ".join(missing))
    extra = sorted(set(stored) - set(metadata))
    if extra:
        raise Failure("meta has unexpected key(s) %s" % ", ".join(extra))
    for key in sorted(metadata):
        if stored[key] != metadata[key]:
            raise Failure("meta[%s] is %r, expected %r" % (key, stored[key], metadata[key]))
        if not isinstance(stored[key], str):
            raise Failure("meta[%s] did not store as TEXT" % key)

    for key, actual in (("records_ipv4", counts["v4"]),
                        ("records_ipv6", counts["v6"]),
                        ("records_total", counts["total"])):
        if key not in stored:
            raise Failure("meta is missing %s" % key)
        if stored[key] != str(actual):
            raise Failure("meta[%s] says %s, the database holds %d" % (key, stored[key], actual))


def verify_query_plans(conn):
    """PRD 10.4: the lookup must reach the table through its primary key.

    The plan legitimately contains a CO-ROUTINE for the inner predecessor
    and a SCAN of that co-routine's single output row; what must never
    appear is a scan of v4/v6 themselves or a temporary sort.
    """
    plans = {}
    for table in TABLES:
        probe = 0 if table == "v4" else bytes(16)
        rows = list(conn.execute("EXPLAIN QUERY PLAN " + LOOKUP_SQL.format(table=table), {"ip": probe}))
        detail = [row[3] for row in rows]
        plans[table] = detail
        searched = [d for d in detail if d.startswith("SEARCH %s " % table) and "PRIMARY KEY" in d]
        if not searched:
            raise Failure("%s lookup does not search the primary key: %s" % (table, " | ".join(detail)))
        for line in detail:
            if line.startswith("SCAN %s" % table):
                raise Failure("%s lookup scans the table: %s" % (table, " | ".join(detail)))
            if "TEMP B-TREE" in line:
                raise Failure("%s lookup sorts into a temp b-tree: %s" % (table, " | ".join(detail)))
    return plans


def verify_queries(conn):
    """Randomized start/end/interior/gap probes, both families, fixed seed."""
    rng = random.Random(QUERY_SEED)
    checked = {"hits": 0, "misses": 0, "seed": QUERY_SEED}

    for table in TABLES:
        # Only the keys are materialized: sampling by OFFSET would walk the
        # b-tree from the left edge for every probe, which on a 450k-row
        # table turns a validation into a benchmark.
        starts = [row[0] for row in conn.execute("SELECT start FROM %s ORDER BY start" % table)]
        if not starts:
            continue
        for key in rng.sample(starts, min(QUERY_SAMPLES, len(starts))):
            row = conn.execute("SELECT * FROM %s WHERE start = ?" % table, (key,)).fetchone()
            start, end = row[0], row[1]
            start_i = start if table == "v4" else int.from_bytes(start, "big")
            end_i = end if table == "v4" else int.from_bytes(end, "big")

            probes = [start_i, end_i]
            if end_i > start_i:
                probes.append(rng.randint(start_i, end_i))
            for probe in probes:
                got = lookup(conn, table, probe)
                if got is None:
                    raise Failure("%s: address %d is inside %d..%d but did not match"
                                  % (table, probe, start_i, end_i))
                if tuple(got) != tuple(row):
                    raise Failure("%s: address %d matched a different row than %d..%d"
                                  % (table, probe, start_i, end_i))
                checked["hits"] += 1

            # The address after this interval is a miss unless the next
            # interval starts there - which is exactly the "predecessor
            # exists but does not contain the address" case (PRD S04).
            after = end_i + 1
            if after <= max_address(table):
                got = lookup(conn, table, after)
                if got is None:
                    checked["misses"] += 1
                else:
                    got_start = got[0] if table == "v4" else int.from_bytes(got[0], "big")
                    if got_start != after:
                        raise Failure("%s: address %d fell into %d.., which does not contain it"
                                      % (table, after, got_start))
                    checked["hits"] += 1
    return checked


def max_address(table):
    return (1 << 32) - 1 if table == "v4" else (1 << 128) - 1


# The parameter type is the whole game for v6: a 16-byte BLOB compares
# unsigned and byte-wise, the same text would compare as TEXT and never
# match a BLOB key at all (PRD S02/S03).
def lookup(conn, table, address):
    parameter = address if table == "v4" else address.to_bytes(16, "big")
    return conn.execute(LOOKUP_SQL.format(table=table), {"ip": parameter}).fetchone()


# --------------------------------------------------------------------------
# CLI


def main(argv):
    parser = argparse.ArgumentParser(description="OpenASN SQLite export writer (build-only)")
    sub = parser.add_subparsers(dest="mode")

    builder = sub.add_parser("build", help="write a new SQLite export from a spool and metadata")
    builder.add_argument("--records", required=True)
    builder.add_argument("--metadata", required=True)
    builder.add_argument("--output", required=True)

    verifier = sub.add_parser("verify", help="validate an existing SQLite export against its inputs")
    verifier.add_argument("--database", required=True)
    verifier.add_argument("--records", required=True)
    verifier.add_argument("--metadata", required=True)

    args = parser.parse_args(argv)
    if args.mode is None:
        parser.print_usage(sys.stderr)
        return 2

    try:
        if args.mode == "build":
            report = build(args.records, args.metadata, args.output)
        else:
            report = verify(args.database, args.records, args.metadata)
    except Failure as exc:
        sys.stderr.write("openasn sqlite %s FAILED: %s\n" % (args.mode, exc))
        return 1
    except (OSError, sqlite3.Error, ValueError) as exc:
        sys.stderr.write("openasn sqlite %s FAILED: %s: %s\n" % (args.mode, type(exc).__name__, exc))
        return 1

    # stdout carries the structured result and nothing else; the Ruby side
    # parses it into the build log and the validation report.
    report["mode"] = args.mode
    report["interpreter"] = sys.executable
    json.dump(report, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
