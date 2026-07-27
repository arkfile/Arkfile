package arkfilechecks

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestRawIPAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), RawIPAnalyzer, "rawipfixture")
}

func TestSecurityEventAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), SecurityEventAnalyzer, "securityeventfixture")
}

func TestOPAQUEFileKeyAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), OPAQUEFileKeyAnalyzer, "opaquefilekeyfixture")
}
