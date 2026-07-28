package logging

type SecurityEvent struct {
	Details map[string]interface{}
}

func LogSecurityEvent(eventType string, clientIP, username, entityID interface{}, details map[string]interface{}) error {
	return nil
}

func GetOrCreateEntityID(context interface{}) string {
	return ""
}
