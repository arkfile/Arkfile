package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/crypto"
)

func TestValidateOwnerSelectionFlags(t *testing.T) {
	reject := []ownerSelectionFlags{
		{All: true, FileIDs: []string{"a"}, OutputDir: "d"},
		{All: true, Tags: "x", OutputDir: "d"},
		{All: true},
		{FileIDs: []string{"a"}, Output: "o", OutputDir: "d"},
		{FileIDs: []string{"a", "b"}, Output: "o"},
		{Tags: "x", Output: "o"},
		{FileIDs: []string{"a", "b"}},
		{Tags: "x"},
		{All: true, OutputDir: "d", PasswordStdin: true},
		{FileIDs: []string{"a", "b"}, OutputDir: "d", PasswordStdin: true},
		{Tags: "x", OutputDir: "d", PasswordStdin: true},
		{},
	}
	for _, f := range reject {
		if err := validateOwnerSelectionFlags(f); err == nil {
			t.Errorf("expected rejection for %+v", f)
		}
	}
	accept := []ownerSelectionFlags{
		{FileIDs: []string{"a"}},
		{FileIDs: []string{"a"}, Output: "o", PasswordStdin: true},
		{FileIDs: []string{"a"}, OutputDir: "d", PasswordStdin: true},
		{FileIDs: []string{"a", "b"}, OutputDir: "d"},
		{Tags: "x", OutputDir: "d"},
		{All: true, OutputDir: "d"},
	}
	for _, f := range accept {
		if err := validateOwnerSelectionFlags(f); err != nil {
			t.Errorf("unexpected rejection for %+v: %v", f, err)
		}
	}
	if !(ownerSelectionFlags{FileIDs: []string{"a"}, OutputDir: "d"}).singleExplicit() {
		t.Fatal("one listed --file-id with --output-dir must stay single-target")
	}
	if (ownerSelectionFlags{Tags: "x", OutputDir: "d"}).singleExplicit() {
		t.Fatal("a scanned selection must never be single-target, even if it matches one file")
	}
}

func TestResolveOwnerSelectionAll(t *testing.T) {
	pages := [][]ServerFileInfo{
		{{FileID: "1"}, {FileID: "2"}},
		{{FileID: "2"}, {FileID: "3"}},
	}
	calls := 0
	list := func() ([]ServerFileInfo, error) {
		calls++
		var all []ServerFileInfo
		for _, p := range pages {
			all = append(all, p...)
		}
		return all, nil
	}
	got, err := resolveOwnerSelection(ownerSelectionFlags{All: true, OutputDir: "d"}, testOwner, list, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "1,2,3" || calls != 1 {
		t.Fatalf("got %v after %d listing calls", got, calls)
	}

	_, err = resolveOwnerSelection(ownerSelectionFlags{All: true, OutputDir: "d"}, testOwner, func() ([]ServerFileInfo, error) { return nil, nil }, nil)
	if !errors.Is(err, errEmptyVault) {
		t.Fatalf("empty vault should be reported as empty selection, got %v", err)
	}

	explicit, err := resolveOwnerSelection(ownerSelectionFlags{FileIDs: []string{"b", "a", "b"}}, testOwner, func() ([]ServerFileInfo, error) {
		t.Fatal("explicit selection must not list the vault")
		return nil, nil
	}, nil)
	if err != nil || strings.Join(explicit, ",") != "b,a" {
		t.Fatalf("explicit selection = %v, %v", explicit, err)
	}
}

func TestResolveOwnerSelectionTags(t *testing.T) {
	key := randomBytes(t, 32)
	tagged := func(id, tags string) ServerFileInfo {
		f := ServerFileInfo{FileID: id, OwnerUsername: testOwner}
		if tags != "" {
			f.EncryptedTags, f.TagsNonce = encryptTestField(t, tags, key, id, crypto.AADFieldTags, testOwner)
		}
		return f
	}
	files := []ServerFileInfo{tagged("1", "food,fun"), tagged("2", "food"), tagged("3", "")}
	list := func() ([]ServerFileInfo, error) { return files, nil }

	got, err := resolveOwnerSelection(ownerSelectionFlags{Tags: "food,fun", OutputDir: "d"}, testOwner, list, key)
	if err != nil || strings.Join(got, ",") != "1" {
		t.Fatalf("tag AND filter = %v, %v", got, err)
	}
	if _, err := resolveOwnerSelection(ownerSelectionFlags{Tags: "missing", OutputDir: "d"}, testOwner, list, key); err == nil || errors.Is(err, errEmptyVault) {
		t.Fatalf("a --tags selection that matches nothing must keep the error, got %v", err)
	}
	if _, err := resolveOwnerSelection(ownerSelectionFlags{Tags: "food", OutputDir: "d"}, testOwner, list, nil); err == nil {
		t.Fatal("--tags without an Account Key must fail")
	}
}

type fakeExportServer struct {
	mu       sync.Mutex
	bundles  map[string][]byte
	fail     map[string]int
	requests []string
}

func (s *fakeExportServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer test-token" || r.URL.Query().Get("token") != "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[3] != "export" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id := parts[2]
	if s.fail[id] > 0 {
		s.fail[id]--
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ARKB short"))
		return
	}
	data, ok := s.bundles[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Write(data)
}

func newExportTestEnv(t *testing.T, server *fakeExportServer) (*HTTPClient, *AuthSession) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(server.handler))
	t.Cleanup(srv.Close)
	client := &HTTPClient{client: srv.Client(), baseURL: srv.URL}
	session := &AuthSession{AccessToken: "test-token", RefreshToken: "", ExpiresAt: time.Now().Add(time.Hour)}
	return client, session
}

func TestExportBatchReservesNamesAndNeverReplaces(t *testing.T) {
	key := randomBytes(t, 32)
	_, photoA := buildTestBundleBytes(t, testBundleSpec{FileID: batchFileA, AccountKey: key, Filename: "photo.png", Plaintext: []byte("a")})
	_, photoB := buildTestBundleBytes(t, testBundleSpec{FileID: batchFileB, AccountKey: key, Filename: "photo.png", Plaintext: []byte("b")})
	server := &fakeExportServer{bundles: map[string][]byte{batchFileA: photoA, batchFileB: photoB}, fail: map[string]int{batchFileB: 1}}
	client, session := newExportTestEnv(t, server)

	dir := t.TempDir()
	existing := filepath.Join(dir, "photo.png.arkbackup")
	os.WriteFile(existing, []byte("old bundle bytes"), 0o600)
	reserver, err := newOutputNameReserver(dir, arkbackupSuffix)
	if err != nil {
		t.Fatal(err)
	}
	targets := []exportTarget{
		{FileID: batchFileA, Filename: "photo.png", Output: reservedOutputTarget(reserver, "photo.png")},
		{FileID: batchFileB, Filename: "photo.png", Output: reservedOutputTarget(reserver, "photo.png")},
	}
	var runErr error
	out := captureStdout(t, func() { runErr = runExportBatch(context.Background(), client, session, targets) })
	if runErr != nil {
		t.Fatalf("export with one retried failure should succeed: %v\n%s", runErr, out)
	}
	if got, _ := os.ReadFile(existing); string(got) != "old bundle bytes" {
		t.Fatal("re-export replaced an existing bundle")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "photo-1.png.arkbackup")); string(got) != string(photoA) {
		t.Fatalf("first new bundle missing: %v", listDirNames(t, dir))
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "photo-2.png.arkbackup")); string(got) != string(photoB) {
		t.Fatalf("retried bundle did not reuse its reservation: %v", listDirNames(t, dir))
	}
	if !strings.Contains(out, "Retrying 1 failed export(s) once") || !strings.Contains(out, "Succeeded: 2. Failed: 0. Skipped: 0.") {
		t.Fatalf("unexpected summary:\n%s", out)
	}
	if hasTempLeftovers(listDirNames(t, dir)) {
		t.Fatal("temporary export file left behind")
	}
	for _, p := range server.requests {
		if strings.Contains(p, "export-token") {
			t.Fatal("export minted a token")
		}
	}
}

func TestExportSingleExactPathKeepsEarlierBundleOnFailure(t *testing.T) {
	key := randomBytes(t, 32)
	_, good := buildTestBundleBytes(t, testBundleSpec{FileID: batchFileA, AccountKey: key, Filename: "x.bin", Plaintext: []byte("x")})
	server := &fakeExportServer{bundles: map[string][]byte{batchFileA: good}, fail: map[string]int{batchFileA: 1}}
	client, session := newExportTestEnv(t, server)
	path := filepath.Join(t.TempDir(), batchFileA+arkbackupSuffix)
	os.WriteFile(path, []byte("earlier bundle"), 0o600)

	if _, err := exportOneBundle(context.Background(), client, session, batchFileA, exactOutputTarget(path)); err == nil {
		t.Fatal("truncated response must fail")
	}
	if got, _ := os.ReadFile(path); string(got) != "earlier bundle" {
		t.Fatal("failed re-export destroyed the earlier bundle")
	}
	if _, err := exportOneBundle(context.Background(), client, session, batchFileA, exactOutputTarget(path)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(good) {
		t.Fatal("successful exact-path export did not replace atomically")
	}
}

func TestExportRejectsInvalidBundleResponse(t *testing.T) {
	server := &fakeExportServer{bundles: map[string][]byte{batchFileA: []byte("not a bundle at all")}}
	client, session := newExportTestEnv(t, server)
	dir := t.TempDir()
	reserver, _ := newOutputNameReserver(dir, arkbackupSuffix)
	if _, err := exportOneBundle(context.Background(), client, session, batchFileA, reservedOutputTarget(reserver, batchFileA)); err == nil {
		t.Fatal("non-bundle response was published")
	}
	if len(listDirNames(t, dir)) != 0 {
		t.Fatalf("failed export left entries: %v", listDirNames(t, dir))
	}
}

func TestOwnerDownloadDefaultNameReservedInsideOutputDir(t *testing.T) {
	key := randomBytes(t, 32)
	salt := testOwnerSalt()
	fek, _ := generateFEK()
	wrapped, err := wrapFEK(fek, key, salt, "account", batchFileA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("owner download bytes")
	chunk, _ := encryptChunk(plaintext, fek, batchFileA, 0, 1)
	encName, nameNonce := encryptTestField(t, "../.Report.pdf", key, batchFileA, crypto.AADFieldFilename, testOwner)
	encSHA, shaNonce := encryptTestField(t, fileSHA256HexBytes(plaintext), key, batchFileA, crypto.AADFieldSha256, testOwner)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/files/"+batchFileA+"/meta", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"file_id":%q,"owner_username":%q,"password_type":"account","encrypted_fek":%q,"encrypted_filename":%q,"filename_nonce":%q,"encrypted_sha256sum":%q,"sha256sum_nonce":%q,"size_bytes":%d,"chunk_count":1}`,
			batchFileA, testOwner, wrapped, encName, nameNonce, encSHA, shaNonce, len(chunk))
	})
	mux.HandleFunc("/api/auth/crypto-metadata", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"success":true,"data":{"account_kdf_salt":%q,"account_kdf_profile":%d}}`, crypto.EncodeBase64(salt), crypto.OwnerEnvelopeKDFProfile())
	})
	mux.HandleFunc("/api/files/"+batchFileA+"/chunks/0", func(w http.ResponseWriter, r *http.Request) {
		w.Write(chunk)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := &HTTPClient{client: srv.Client(), baseURL: srv.URL}
	session := &AuthSession{Username: testOwner, AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".report.PDF"), []byte("existing"), 0o600)
	captureStdout(t, func() {
		err = downloadOneOwnerFile(context.Background(), client, session, key, batchFileA, nil, dir, nil)
	})
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, ".Report-1.pdf"))
	if readErr != nil || string(got) != string(plaintext) {
		t.Fatalf("expected reserved dotfile name .Report-1.pdf in the output dir: %v", listDirNames(t, dir))
	}
	if existing, _ := os.ReadFile(filepath.Join(dir, ".report.PDF")); string(existing) != "existing" {
		t.Fatal("default download replaced an existing entry")
	}
}

func fileSHA256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestExportBatchSessionLossSkipsRemainder(t *testing.T) {
	key := randomBytes(t, 32)
	_, a := buildTestBundleBytes(t, testBundleSpec{FileID: batchFileA, AccountKey: key, Filename: "a", Plaintext: []byte("a")})
	server := &fakeExportServer{bundles: map[string][]byte{batchFileA: a}}
	client, session := newExportTestEnv(t, server)
	session.AccessToken = "revoked"
	dir := t.TempDir()
	reserver, _ := newOutputNameReserver(dir, arkbackupSuffix)
	targets := []exportTarget{
		{FileID: batchFileA, Output: reservedOutputTarget(reserver, batchFileA)},
		{FileID: batchFileB, Output: reservedOutputTarget(reserver, batchFileB)},
	}
	var runErr error
	out := captureStdout(t, func() { runErr = runExportBatch(context.Background(), client, session, targets) })
	if runErr == nil || !strings.Contains(out, "Skipped: 2.") {
		t.Fatalf("session loss should skip the rest: %v\n%s", runErr, out)
	}
}
