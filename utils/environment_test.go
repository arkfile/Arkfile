package utils

import "testing"

func TestArkfileEnvironmentSelectsProduction(t *testing.T) {
	t.Setenv("ARKFILE_ENV", "production")
	if !IsProductionEnvironment() {
		t.Fatal("ARKFILE_ENV=production must enable production safeguards")
	}
	if got := GetEnvironmentName(); got != "production" {
		t.Fatalf("GetEnvironmentName() = %q, want production", got)
	}
}
