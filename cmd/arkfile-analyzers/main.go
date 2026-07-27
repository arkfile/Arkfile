package main

import (
	"github.com/arkfile/Arkfile/internal/analysis/arkfilechecks"
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	multichecker.Main(
		arkfilechecks.RawIPAnalyzer,
		arkfilechecks.SecurityEventAnalyzer,
		arkfilechecks.OPAQUEFileKeyAnalyzer,
	)
}
