package crypto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFileTagsParamsEmbedded(t *testing.T) {
	params, err := LoadFileTagsParams()
	if err != nil {
		t.Fatalf("LoadFileTagsParams: %v", err)
	}
	if params.MaxTagsPerFile != 5 || params.MaxTagLength != 32 || params.MaxTagsPerFilterQuery != 10 {
		t.Fatalf("unexpected defaults: %+v", params)
	}
	var raw map[string]int
	if err := json.Unmarshal(GetEmbeddedFileTagsParamsJSON(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["maxTagsPerFile"] != 5 {
		t.Fatalf("embedded JSON drift: %v", raw)
	}
}

func TestParseAndCanonicalizeTags(t *testing.T) {
	tags, err := ParseAndCanonicalizeTags(" Food ,activity,FUN,food ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tags, ",") != "Food,activity,FUN" {
		t.Fatalf("got %q", strings.Join(tags, ","))
	}
}

func TestParseAndCanonicalizeTags_TrimsSpacesRejectsMax(t *testing.T) {
	// Spaces around commas must not produce "tag contains whitespace".
	_, err := ParseAndCanonicalizeTags("apple, banana, cherry, DOG, 123, noun")
	if err == nil {
		t.Fatal("expected max-tags error for six tags")
	}
	if err.Error() != "5 tags maximum" {
		t.Fatalf("got %q, want %q", err.Error(), "5 tags maximum")
	}

	tags, err := ParseAndCanonicalizeTags("apple, banana, cherry, DOG, 123")
	if err != nil {
		t.Fatalf("five spaced tags should succeed: %v", err)
	}
	if strings.Join(tags, ",") != "apple,banana,cherry,DOG,123" {
		t.Fatalf("got %q", strings.Join(tags, ","))
	}
}

func TestParseAndAddTags_MultiWithSpaces(t *testing.T) {
	out, err := ParseAndAddTags([]string{"Food"}, " activity , FUN ,food ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out, ",") != "Food,activity,FUN" {
		t.Fatalf("got %q", strings.Join(out, ","))
	}

	_, err = ParseAndAddTags([]string{"a", "b", "c", "d", "e"}, "f, g")
	if err == nil || err.Error() != "5 tags maximum" {
		t.Fatalf("expected 5 tags maximum, got %v", err)
	}

	// In-tag space still invalid after trim of comma segments.
	if _, err := ParseAndAddTags(nil, "apple banana"); err == nil {
		t.Fatal("expected whitespace/syntax error for in-tag space")
	}
}

func TestValidateTagSyntax(t *testing.T) {
	params := GetFileTagsParams()
	valid := []string{"ab-cd", "PC-1", "topicC", "A", "a-b-c-d"}
	for _, tag := range valid {
		if err := ValidateTagSyntax(tag, params.MaxTagLength); err != nil {
			t.Fatalf("%q should be valid: %v", tag, err)
		}
	}
	cases := []struct {
		tag string
		msg string
	}{
		{"", "tag is empty"},
		{"ab cd", "tag contains whitespace"},
		{"-abc", "tag cannot start with a dash"},
		{"a-b-c-d-", "tag cannot end with a dash"},
		{"-abcd-", "tag cannot start with a dash"},
		{"ab--cd", "tag cannot contain consecutive dashes"},
		{"---", "tag cannot start with a dash"},
		{"a_b", "tag contains invalid characters (use A-Z, a-z, 0-9, and single dashes between segments)"},
		{strings.Repeat("a", 33), "tag exceeds max length 32"},
	}
	for _, tc := range cases {
		err := ValidateTagSyntax(tc.tag, params.MaxTagLength)
		if err == nil {
			t.Fatalf("%q should be invalid", tc.tag)
		}
		if err.Error() != tc.msg {
			t.Fatalf("%q: got %q, want %q", tc.tag, err.Error(), tc.msg)
		}
	}
}

func TestAddRemoveReplaceTag(t *testing.T) {
	tags := []string{"Food", "activity"}
	out, err := AddTag(tags, "FUN")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out, ",") != "Food,activity,FUN" {
		t.Fatalf("add: %q", strings.Join(out, ","))
	}
	out = RemoveTag(out, "activity")
	if strings.Join(out, ",") != "Food,FUN" {
		t.Fatalf("remove: %q", strings.Join(out, ","))
	}
	out, err = ReplaceTag(out, "Food", "FOOD")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out, ",") != "FOOD,FUN" {
		t.Fatalf("casing replace: %q", strings.Join(out, ","))
	}
	if _, err := ReplaceTag(out, "FOOD", "FUN"); err == nil {
		t.Fatal("expected collision")
	}
}

func TestParseFilterTagsAndMatch(t *testing.T) {
	query, err := ParseFilterTags("Food, food,FUN")
	if err != nil {
		t.Fatal(err)
	}
	if len(query) != 2 {
		t.Fatalf("expected collapsed query, got %v", query)
	}
	if !FileHasAllTags([]string{"Food", "activity", "FUN"}, query) {
		t.Fatal("expected AND match")
	}
	if FileHasAllTags([]string{"Food"}, query) {
		t.Fatal("expected AND miss")
	}
}

func TestParseFilterTagsLimit(t *testing.T) {
	parts := make([]string, 11)
	for i := range parts {
		parts[i] = string(rune('a' + i))
	}
	if _, err := ParseFilterTags(strings.Join(parts, ",")); err == nil {
		t.Fatal("expected filter max error")
	}
}
