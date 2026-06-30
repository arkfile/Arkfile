package models

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestListAllSubscriptionPlans_ScansBooleanColumns(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE subscription_plans (
			plan_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			price_usd_cents INTEGER NOT NULL,
			storage_limit_bytes BIGINT NOT NULL,
			sort_order INTEGER NOT NULL DEFAULT 0,
			is_active BOOLEAN NOT NULL DEFAULT 1,
			is_public BOOLEAN NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		);
		INSERT INTO subscription_plans
		  (plan_id, name, price_usd_cents, storage_limit_bytes, is_active, is_public, updated_by)
		VALUES ('plan_dev_250gb', '250 GB', 500, 268435456000, 1, 1, 'system');
	`); err != nil {
		t.Fatal(err)
	}

	plans, err := ListAllSubscriptionPlans(db)
	if err != nil {
		t.Fatalf("ListAllSubscriptionPlans: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if plans[0].PlanID != DevSubscriptionPlanID {
		t.Fatalf("plan_id = %q", plans[0].PlanID)
	}
	if !plans[0].IsActive || !plans[0].IsPublic {
		t.Fatalf("expected active public plan, got active=%v public=%v", plans[0].IsActive, plans[0].IsPublic)
	}

	got, err := GetSubscriptionPlan(db, DevSubscriptionPlanID)
	if err != nil {
		t.Fatalf("GetSubscriptionPlan: %v", err)
	}
	if !got.IsActive || !got.IsPublic {
		t.Fatalf("GetSubscriptionPlan booleans: active=%v public=%v", got.IsActive, got.IsPublic)
	}
	if got.StorageLimitBytes != DevPlanStorageBytes {
		t.Fatalf("storage_limit_bytes = %d, want %d", got.StorageLimitBytes, DevPlanStorageBytes)
	}
}

func TestScanInt64_RqliteFloatStorageLimit(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want int64
	}{
		{"int64", int64(DevPlanStorageBytes), DevPlanStorageBytes},
		{"float64 exact", float64(DevPlanStorageBytes), DevPlanStorageBytes},
		{"float64 scientific", float64(2.68435456e11), DevPlanStorageBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScanInt64(tc.in); got != tc.want {
				t.Fatalf("ScanInt64(%#v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
