package crypto

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed file-tags-params.json
var embeddedFileTagsParams []byte

// FileTagsParams holds shared tag limits for Go and TypeScript clients.
type FileTagsParams struct {
	MaxTagsPerFile        int `json:"maxTagsPerFile"`
	MaxTagLength          int `json:"maxTagLength"`
	MaxTagsPerFilterQuery int `json:"maxTagsPerFilterQuery"`
}

// MaxEncryptedTagsBase64Len is the server-side cap on non-empty encrypted_tags
// base64 strings (abuse guard; plaintext limits are enforced only by clients).
const MaxEncryptedTagsBase64Len = 1024

// AES-GCM nonce size for metadata fields (12 bytes -> 16 base64 characters).
const TagsNonceRawBytes = 12

var (
	fileTagsParamsOnce  sync.Once
	fileTagsParamsCache *FileTagsParams
	fileTagsParamsErr   error

	tagSyntaxRE = regexp.MustCompile(`^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$`)
)

// LoadFileTagsParams loads tag limits from the embedded JSON.
func LoadFileTagsParams() (*FileTagsParams, error) {
	fileTagsParamsOnce.Do(func() {
		params := &FileTagsParams{}
		if err := json.Unmarshal(embeddedFileTagsParams, params); err != nil {
			fileTagsParamsErr = fmt.Errorf("failed to parse embedded file-tags-params.json: %w", err)
			return
		}
		if params.MaxTagsPerFile <= 0 || params.MaxTagLength <= 0 || params.MaxTagsPerFilterQuery <= 0 {
			fileTagsParamsErr = fmt.Errorf("file-tags-params.json has invalid non-positive limits")
			return
		}
		fileTagsParamsCache = params
	})
	return fileTagsParamsCache, fileTagsParamsErr
}

// GetFileTagsParams returns loaded tag limits or panics.
func GetFileTagsParams() *FileTagsParams {
	params, err := LoadFileTagsParams()
	if err != nil {
		panic(fmt.Sprintf("Failed to load file tags params: %v", err))
	}
	return params
}

// GetEmbeddedFileTagsParamsJSON returns the raw embedded JSON for API serving.
func GetEmbeddedFileTagsParamsJSON() []byte {
	return embeddedFileTagsParams
}

// ParseTagList splits a comma-separated tag string, trims surrounding whitespace
// per segment, and rejects empty segments. It does not validate syntax or limits.
func ParseTagList(input string) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return []string{}, nil
	}
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			return nil, fmt.Errorf("empty tag segment")
		}
		out = append(out, tag)
	}
	return out, nil
}

// ValidateTagSyntax checks a single tag against the locked character rules and length.
// Failures name the specific rule that was violated.
func ValidateTagSyntax(tag string, maxLen int) error {
	if tag == "" {
		return fmt.Errorf("tag is empty")
	}
	if maxLen <= 0 {
		maxLen = GetFileTagsParams().MaxTagLength
	}
	if len(tag) > maxLen {
		return fmt.Errorf("tag exceeds max length %d", maxLen)
	}
	if strings.ContainsAny(tag, " \t\n\r") {
		return fmt.Errorf("tag contains whitespace")
	}
	if strings.HasPrefix(tag, "-") {
		return fmt.Errorf("tag cannot start with a dash")
	}
	if strings.HasSuffix(tag, "-") {
		return fmt.Errorf("tag cannot end with a dash")
	}
	if strings.Contains(tag, "--") {
		return fmt.Errorf("tag cannot contain consecutive dashes")
	}
	for _, r := range tag {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return fmt.Errorf("tag contains invalid characters (use A-Z, a-z, 0-9, and single dashes between segments)")
	}
	if !tagSyntaxRE.MatchString(tag) {
		return fmt.Errorf("tag has invalid syntax (use alphanumeric segments separated by single dashes)")
	}
	return nil
}

// ErrMaxTagsPerFile returns the canonical user-facing limit error.
func ErrMaxTagsPerFile(max int) error {
	return fmt.Errorf("%d tags maximum", max)
}

// CanonicalizeTags validates, deduplicates case-insensitively (first-seen casing),
// enforces max tags per file, and returns the canonical ordered list.
func CanonicalizeTags(tags []string) ([]string, error) {
	params := GetFileTagsParams()
	if len(tags) > params.MaxTagsPerFile {
		return nil, ErrMaxTagsPerFile(params.MaxTagsPerFile)
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if err := ValidateTagSyntax(tag, params.MaxTagLength); err != nil {
			return nil, err
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tag)
	}
	if len(out) > params.MaxTagsPerFile {
		return nil, ErrMaxTagsPerFile(params.MaxTagsPerFile)
	}
	return out, nil
}

// ParseAndCanonicalizeTags parses input then canonicalizes.
func ParseAndCanonicalizeTags(input string) ([]string, error) {
	parsed, err := ParseTagList(input)
	if err != nil {
		return nil, err
	}
	return CanonicalizeTags(parsed)
}

// SerializeTags joins tags with commas and no surrounding spaces.
func SerializeTags(tags []string) string {
	return strings.Join(tags, ",")
}

// ParseFilterTags parses a filter query, collapses case-insensitive duplicates
// (first-seen casing), and enforces the filter-query max against the unique set.
func ParseFilterTags(input string) ([]string, error) {
	params := GetFileTagsParams()
	parsed, err := ParseTagList(input)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(parsed))
	out := make([]string, 0, len(parsed))
	for _, tag := range parsed {
		if err := ValidateTagSyntax(tag, params.MaxTagLength); err != nil {
			return nil, err
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tag)
	}
	if len(out) > params.MaxTagsPerFilterQuery {
		return nil, fmt.Errorf("too many filter tags: max %d", params.MaxTagsPerFilterQuery)
	}
	return out, nil
}

// FileHasAllTags reports whether fileTags contains every query tag (AND),
// using ASCII case-folded comparison.
func FileHasAllTags(fileTags, queryTags []string) bool {
	if len(queryTags) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(fileTags))
	for _, t := range fileTags {
		set[strings.ToLower(t)] = struct{}{}
	}
	for _, q := range queryTags {
		if _, ok := set[strings.ToLower(q)]; !ok {
			return false
		}
	}
	return true
}

// AddTag appends tag if not already present (case-insensitive). Preserves order.
func AddTag(tags []string, tag string) ([]string, error) {
	return AddTags(tags, []string{tag})
}

// AddTags appends each tag in toAdd if not already present (case-insensitive).
// Preserves existing order and appends new tags in toAdd order. Whitespace inside
// a tag remains invalid; callers should ParseTagList first so spaces around commas
// are trimmed. Returns ErrMaxTagsPerFile if the resulting list would exceed the limit.
func AddTags(tags []string, toAdd []string) ([]string, error) {
	params := GetFileTagsParams()
	out := append([]string(nil), tags...)
	for _, tag := range toAdd {
		if err := ValidateTagSyntax(tag, params.MaxTagLength); err != nil {
			return nil, err
		}
		key := strings.ToLower(tag)
		present := false
		for _, t := range out {
			if strings.ToLower(t) == key {
				present = true
				break
			}
		}
		if present {
			continue
		}
		if len(out) >= params.MaxTagsPerFile {
			return nil, ErrMaxTagsPerFile(params.MaxTagsPerFile)
		}
		out = append(out, tag)
	}
	return out, nil
}

// ParseAndAddTags parses a comma-separated input (trimming spaces around commas)
// and merges the tags into existing via AddTags.
func ParseAndAddTags(existing []string, input string) ([]string, error) {
	parsed, err := ParseTagList(input)
	if err != nil {
		return nil, err
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("tag is empty")
	}
	return AddTags(existing, parsed)
}

// RemoveTag removes the first case-insensitive match. Missing tag is a no-op.
func RemoveTag(tags []string, tag string) []string {
	key := strings.ToLower(tag)
	out := make([]string, 0, len(tags))
	removed := false
	for _, t := range tags {
		if !removed && strings.ToLower(t) == key {
			removed = true
			continue
		}
		out = append(out, t)
	}
	return out
}

// ReplaceTag replaces the first case-insensitive match for oldTag with newTag,
// keeping position. Casing-only replacement is allowed. Collision with another
// existing tag (different from oldTag) is rejected.
func ReplaceTag(tags []string, oldTag, newTag string) ([]string, error) {
	params := GetFileTagsParams()
	if err := ValidateTagSyntax(newTag, params.MaxTagLength); err != nil {
		return nil, err
	}
	oldKey := strings.ToLower(oldTag)
	newKey := strings.ToLower(newTag)
	idx := -1
	for i, t := range tags {
		if strings.ToLower(t) == oldKey {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("tag not found")
	}
	if oldKey != newKey {
		for i, t := range tags {
			if i != idx && strings.ToLower(t) == newKey {
				return nil, fmt.Errorf("replacement collides with existing tag")
			}
		}
	}
	out := make([]string, len(tags))
	copy(out, tags)
	out[idx] = newTag
	return out, nil
}

// TagPresent reports case-insensitive membership.
func TagPresent(tags []string, tag string) bool {
	key := strings.ToLower(tag)
	for _, t := range tags {
		if strings.ToLower(t) == key {
			return true
		}
	}
	return false
}
