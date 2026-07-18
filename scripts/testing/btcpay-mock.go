//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/api/v1/stores/test_store_id/invoices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Amount   string            `json:"amount"`
			Currency string            `json:"currency"`
			Metadata map[string]string `json:"metadata"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		invoiceID := payload.Metadata["invoice_id"]
		if invoiceID == "" {
			invoiceID = "mock_prov_abc123"
		}

		providerID := "btcpay_mock_" + invoiceID

		response := map[string]interface{}{
			"id":           providerID,
			"checkoutLink": fmt.Sprintf("http://localhost:3000/checkout/%s", invoiceID),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	})

	log.Println("Starting mock BTCPay server on :3000...")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}
