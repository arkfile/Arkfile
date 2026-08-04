package main

import "testing"

func TestBatchOutcomesToPendingSkipsCancelled(t *testing.T) {
	outcomes := []batchFileOutcome{
		{FileID: "1", Filename: "a.bin", PasswordType: "account", Reason: "network"},
		{FileID: "2", Filename: "b.bin", PasswordType: "custom", Reason: "cancelled"},
		{FileID: "3", Filename: "c.bin", PasswordType: "custom", Reason: "wrong_custom_password"},
		{FileID: "4", Filename: "d.bin", PasswordType: "account", Reason: "skipped"},
	}
	got := batchOutcomesToPending(outcomes)
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	if got[0].FileID != "1" || got[1].FileID != "3" {
		t.Fatalf("unexpected pending: %+v", got)
	}
}
