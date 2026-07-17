package flags

import "testing"

func TestPopBool(t *testing.T) {
	args, found := PopBool([]string{"19.99", "--json"}, "--json")
	if !found {
		t.Fatal("expected --json to be found")
	}
	if len(args) != 1 || args[0] != "19.99" {
		t.Fatalf("unexpected args: %#v", args)
	}

	args, found = PopBool([]string{"--json", "19.99"}, "--json")
	if !found {
		t.Fatal("expected leading --json to be found")
	}
	if len(args) != 1 || args[0] != "19.99" {
		t.Fatalf("unexpected args: %#v", args)
	}
}
