// Command openasn-mmdb turns the export spool into openasn.mmdb, and verifies
// the result against that same spool with a reader that shares no code with
// the writer (PRD §12, EXPORT_FORMATS.md §6).
//
// Two modes, no third:
//
//	openasn-mmdb build  --records PATH --metadata PATH --output PATH
//	openasn-mmdb verify --database PATH --records PATH --metadata PATH
//
// It has no HTTP client, no data fetching and no file discovery. Every input
// arrives as an explicit path, because a build tool that can find its own
// inputs is a build tool that can quietly export yesterday's snapshot. Exit 0
// means the whole stage succeeded; anything else prints the stage and the
// reason on stderr and exits nonzero. There is no partial success.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const programName = "openasn-mmdb"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: " + programName + " build|verify [flags] (see --help on either mode)")
	}

	switch args[0] {
	case "build":
		fs := flag.NewFlagSet(programName+" build", flag.ContinueOnError)
		records := fs.String("records", "", "path to the JSONL export spool")
		metadata := fs.String("metadata", "", "path to the export metadata JSON")
		output := fs.String("output", "", "path to write the MMDB to")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := requirePaths(fs, map[string]string{
			"records": *records, "metadata": *metadata, "output": *output,
		}); err != nil {
			return err
		}
		return buildCommand(*records, *metadata, *output)

	case "verify":
		fs := flag.NewFlagSet(programName+" verify", flag.ContinueOnError)
		database := fs.String("database", "", "path to the MMDB to verify")
		records := fs.String("records", "", "path to the JSONL export spool it was built from")
		metadata := fs.String("metadata", "", "path to the export metadata JSON it was built from")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := requirePaths(fs, map[string]string{
			"database": *database, "records": *records, "metadata": *metadata,
		}); err != nil {
			return err
		}
		return verifyCommand(*database, *records, *metadata)

	default:
		return fmt.Errorf("unknown mode %q: expected build or verify", args[0])
	}
}

// Flags are mandatory rather than defaulted: a defaulted path is how a tool
// ends up exporting whatever happened to be lying in the working directory.
func requirePaths(fs *flag.FlagSet, paths map[string]string) error {
	missing := []string{}
	// fs.VisitAll keeps the message in declaration order instead of Go's
	// randomized map order, so the same mistake prints the same message.
	fs.VisitAll(func(f *flag.Flag) {
		if value, ok := paths[f.Name]; ok && value == "" {
			missing = append(missing, "--"+f.Name)
		}
	})
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %v", missing)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument(s): %v", fs.Args())
	}
	return nil
}
