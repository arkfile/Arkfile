package handlers

import (
	"github.com/84adam/arkfile/auth"
)

// RegisterRoutes initializes all routes for the application
func RegisterRoutes() {
	// Static files
	Echo.Static("/", "client/static")
	
	// Authentication
	Echo.POST("/api/register", Register)
	Echo.POST("/api/login", Login)
	
	// Files - require authentication
	auth.Echo.GET("/api/files", ListFiles)
	auth.Echo.POST("/api/upload", UploadFile)
	auth.Echo.GET("/api/download/:filename", DownloadFile)
	auth.Echo.DELETE("/api/files/:filename", DeleteFile)
	
	// Chunked uploads
	auth.Echo.POST("/api/uploads/init", InitiateChunkedUpload)
	auth.Echo.POST("/api/uploads/:sessionId/chunks/:chunkNumber", UploadChunk)
	auth.Echo.POST("/api/uploads/:sessionId/complete", CompleteChunkedUpload)
	auth.Echo.GET("/api/uploads/:sessionId/status", GetUploadStatus)
	auth.Echo.DELETE("/api/uploads/:sessionId", CancelChunkedUpload)
	
	// Share file
	auth.Echo.POST("/api/share", ShareFile)
	auth.Echo.GET("/api/user/shares", ListShares)
	auth.Echo.DELETE("/api/share/:id", DeleteShare)
	
	// Access shared file
	Echo.GET("/shared/:id", GetSharedFile)
	Echo.POST("/shared/:id/auth", AuthenticateShare)
	Echo.GET("/shared/:id/download", DownloadSharedFile)
	
	// File encryption key management
	auth.Echo.POST("/api/files/:filename/update-encryption", UpdateEncryption)
	auth.Echo.GET("/api/files/:filename/keys", ListKeys)
	auth.Echo.DELETE("/api/files/:filename/keys/:keyId", DeleteKey)
	auth.Echo.PATCH("/api/files/:filename/keys/:keyId", UpdateKey)
	auth.Echo.POST("/api/files/:filename/keys/:keyId/set-primary", SetPrimaryKey)
	
	// User management (admin only)
	auth.Echo.GET("/api/admin/users", ListUsers)
	auth.Echo.PATCH("/api/admin/users/:email", UpdateUser)
	auth.Echo.DELETE("/api/admin/users/:email", DeleteUser)
	
	// System statistics (admin only)
	auth.Echo.GET("/api/admin/stats", GetSystemStats)
	auth.Echo.GET("/api/admin/activity", GetActivityLogs)
}
