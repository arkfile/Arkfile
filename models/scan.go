package models

// ScanBool normalizes SQL BOOLEAN column values from database/sql Scan.
// rqlite and SQLite drivers may return bool, integer, float, or string forms
// depending on storage and the HTTP/JSON decode path.
func ScanBool(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case int64:
		return val != 0
	case float64:
		return val != 0
	case string:
		return val == "1" || val == "true" || val == "TRUE"
	default:
		return false
	}
}

// ScanInt64 normalizes SQL INTEGER/BIGINT column values from database/sql Scan.
// rqlite returns large BIGINT values as JSON float64 (sometimes scientific notation).
func ScanInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	default:
		return 0
	}
}

// ScanInt normalizes SQL INTEGER column values from database/sql Scan.
func ScanInt(v interface{}) int {
	return int(ScanInt64(v))
}
