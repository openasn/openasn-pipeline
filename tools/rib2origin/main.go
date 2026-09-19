// Command rib2origin derives an IP-range -> origin-ASN table from RouteViews
// MRT RIB dumps, in the same CSV shape the pipeline consumes from sapics.
//
//	rib2origin build -out DIR [-min-peers N] RIB.bz2 [RIB.bz2 ...]
//	rib2origin compare -a sapics.csv -b ours.csv [-prefixes ours-prefixes.tsv] [-links links.bin]
//
// build writes, into DIR:
//
//	origin-asn-ipv4-num.csv, origin-asn-ipv6-num.csv  (start,end,asn,)
//	prefixes-ipv4.tsv, prefixes-ipv6.tsv              (per-prefix decision + all candidates)
//	links.bin                                          (observed upstream->origin adjacencies, for compare)
//	stats.json                                         (every filter's effect, timings, inputs)
//
// Data provenance: RouteViews (www.routeviews.org), University of Oregon.
// See the data repo's ATTRIBUTION.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rib2origin build|compare [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "build":
		err = runBuild(os.Args[2:])
	case "compare":
		err = runCompare(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rib2origin:", err)
		os.Exit(1)
	}
}
