package rawipfixture

import (
	"log"
	"net/http"

	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
)

type context interface {
	RealIP() string
}

func rejected(context context, request *http.Request) {
	log.Printf("client=%s", context.RealIP())        // want "raw request IP must be converted"
	log.Print(request.RemoteAddr)                    // want "raw request IP must be converted"
	log.Print(request.Header.Get("X-Forwarded-For")) // want "raw request IP must be converted"
	rawIP := context.RealIP()
	log.Print(rawIP) // want "raw request IP must be converted"

	logging.LogSecurityEvent("event", nil, nil, nil, map[string]interface{}{ // want "raw request IP must be converted"
		"message": context.RealIP(),
	})
	database.LogUserAction("user", "action", request.RemoteAddr) // want "raw request IP must be converted"
}

func accepted(context context, request *http.Request) {
	entityID := logging.GetOrCreateEntityID(context)
	log.Printf("entity=%s path=%s", entityID, request.URL.Path)
	logging.LogSecurityEvent("event", context.RealIP(), nil, nil, map[string]interface{}{
		"endpoint": request.URL.Path,
	})
}
