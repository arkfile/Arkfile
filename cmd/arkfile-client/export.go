// export.go - Export command for arkfile-client
// Downloads a .arkbackup bundle from the server for offline decryption.

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func handleExportCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to export")
	outputPath := fs.String("output", "", "Output file path (default: <file-id>.arkbackup)")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client export --file-id FILE_ID [--output PATH]\n\nExport an encrypted file as a .arkbackup bundle for offline decryption.\n")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("--file-id is required")
	}

	if *outputPath == "" {
		*outputPath = *fileID + ".arkbackup"
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	logVerbose("Exporting file %s as .arkbackup bundle...", *fileID)

	// GET /api/files/<fileId>/export with auth token
	url := fmt.Sprintf("%s/api/files/%s/export", client.baseURL, *fileID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create export request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("export failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Stream response to output file
	outFile, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	written, err := io.Copy(outFile, resp.Body)
	outFile.Close()
	if err != nil {
		os.Remove(*outputPath)
		return fmt.Errorf("failed to write export bundle: %w", err)
	}

	fmt.Printf("Exported %s to %s (%d bytes)\n", *fileID, *outputPath, written)
	return nil
}
