package billing

import (
	"sync"
	"testing"
	"time"
)

// TestComputeRate verifies the floor-rounded conversion from customer price
// (USD per TiB per month, 30-day month) to the internal rate
// (microcents per GiB per hour, binary GiB = 2^30).
//
// Spec §3.3: the derived rate must NEVER exceed the operator's stated price.
// All values therefore floor-round.
func TestComputeRate(t *testing.T) {
	cases := []struct {
		priceUSDPerTBPerMonth       string
		wantMicrocentsPerGiBPerHour int64
	}{
		{"10.00", 1356},
		{"19.99", 2711},
		{"20.00", 2712},
		{"24.99", 3389},
		// Rounding boundaries: $1 should not become 0 microcents/GiB/hour.
		{"1.00", 135},
	}
	for _, tc := range cases {
		rate, err := computeRate(tc.priceUSDPerTBPerMonth)
		if err != nil {
			t.Errorf("computeRate(%q) error: %v", tc.priceUSDPerTBPerMonth, err)
			continue
		}
		if rate.MicrocentsPerGiBPerHour != tc.wantMicrocentsPerGiBPerHour {
			t.Errorf("computeRate(%q) = %d microcents/GiB/hour, want %d",
				tc.priceUSDPerTBPerMonth,
				rate.MicrocentsPerGiBPerHour,
				tc.wantMicrocentsPerGiBPerHour)
		}
		if rate.CustomerPriceUSDPerTBPerMonth != tc.priceUSDPerTBPerMonth {
			t.Errorf("computeRate(%q): CustomerPriceUSDPerTBPerMonth = %q, want %q",
				tc.priceUSDPerTBPerMonth, rate.CustomerPriceUSDPerTBPerMonth, tc.priceUSDPerTBPerMonth)
		}
	}
}

func TestComputeRate_Invalid(t *testing.T) {
	invalids := []string{
		"",
		"abc",
		"-1.00",
		"0.00",   // must be positive
		"10.001", // wait, this is allowed by ParseCreditsFromUSD (3 dp)... actually, 4dp max, so this is fine
	}
	// Override: only enforce a few invalids that should definitely fail.
	failures := []string{
		"",
		"abc",
		"-1.00",
		"0.00",
	}
	_ = invalids
	for _, in := range failures {
		if _, err := computeRate(in); err == nil {
			t.Errorf("computeRate(%q) expected error, got nil", in)
		}
	}
}

func TestRateFormatHumanReadable(t *testing.T) {
	r := &Rate{
		MicrocentsPerGiBPerHour:       1356,
		CustomerPriceUSDPerTBPerMonth: "10.00",
		ResolvedAt:                    time.Now(),
	}
	if got := r.FormatHumanReadable(); got != "$10.00/TiB/month" {
		t.Errorf("FormatHumanReadable() = %q, want %q", got, "$10.00/TiB/month")
	}

	var nilRate *Rate
	if got := nilRate.FormatHumanReadable(); got != "" {
		t.Errorf("nil.FormatHumanReadable() = %q, want empty string", got)
	}
}

// TestCachedRate_AtomicSwap verifies that concurrent reads during a write
// never observe a torn Rate value. (atomic.Pointer guarantees this; the test
// is a smoke check that the API contract holds.)
func TestCachedRate_AtomicSwap(t *testing.T) {
	defer ResetCachedRateForTest()
	ResetCachedRateForTest()

	r1 := &Rate{MicrocentsPerGiBPerHour: 1356, CustomerPriceUSDPerTBPerMonth: "10.00"}
	r2 := &Rate{MicrocentsPerGiBPerHour: 2711, CustomerPriceUSDPerTBPerMonth: "19.99"}
	SetCachedRate(r1)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := CachedRate()
				if r != nil && r.MicrocentsPerGiBPerHour != 1356 && r.MicrocentsPerGiBPerHour != 2711 {
					t.Errorf("torn read: rate = %+v", r)
					return
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			SetCachedRate(r1)
		} else {
			SetCachedRate(r2)
		}
	}
	close(stop)
	wg.Wait()
}
