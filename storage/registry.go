package storage

import (
	"context"
	"fmt"
	"io"
	"log"
)

// ProviderRegistry holds references to the primary and optional secondary/tertiary
// ObjectStorageProvider instances. It replaces the single global Provider as the
// primary interface for handler code.
type ProviderRegistry struct {
	primary     ObjectStorageProvider
	secondary   ObjectStorageProvider // nil in single-provider mode
	tertiary    ObjectStorageProvider // nil if not configured
	primaryID   string                // e.g. "seaweedfs-local"
	secondaryID string                // e.g. "wasabi-us-central-1"
	tertiaryID  string                // e.g. "backblaze-us-west"
}

// Registry is the global provider registry instance.
var Registry *ProviderRegistry

// NewProviderRegistry creates a new ProviderRegistry with the given primary provider.
// Secondary and tertiary providers are optional and can be nil.
func NewProviderRegistry(primary ObjectStorageProvider, primaryID string) *ProviderRegistry {
	return &ProviderRegistry{
		primary:   primary,
		primaryID: primaryID,
	}
}

// SetSecondary configures the secondary provider.
func (r *ProviderRegistry) SetSecondary(provider ObjectStorageProvider, id string) {
	r.secondary = provider
	r.secondaryID = id
}

// SetTertiary configures the tertiary provider.
func (r *ProviderRegistry) SetTertiary(provider ObjectStorageProvider, id string) {
	r.tertiary = provider
	r.tertiaryID = id
}

// Primary returns the primary provider. Used by upload handlers.
func (r *ProviderRegistry) Primary() ObjectStorageProvider {
	return r.primary
}

// Secondary returns the secondary provider, or nil if not configured.
func (r *ProviderRegistry) Secondary() ObjectStorageProvider {
	return r.secondary
}

// Tertiary returns the tertiary provider, or nil if not configured.
func (r *ProviderRegistry) Tertiary() ObjectStorageProvider {
	return r.tertiary
}

// HasSecondary returns true if a secondary provider is configured and active.
func (r *ProviderRegistry) HasSecondary() bool {
	return r.secondary != nil
}

// HasTertiary returns true if a tertiary provider is configured and active.
func (r *ProviderRegistry) HasTertiary() bool {
	return r.tertiary != nil
}

// PrimaryID returns the human-readable primary provider ID.
func (r *ProviderRegistry) PrimaryID() string {
	return r.primaryID
}

// SecondaryID returns the human-readable secondary provider ID.
func (r *ProviderRegistry) SecondaryID() string {
	return r.secondaryID
}

// TertiaryID returns the human-readable tertiary provider ID.
func (r *ProviderRegistry) TertiaryID() string {
	return r.tertiaryID
}

// GetProvider returns the provider instance matching the given ID, or nil if not found.
func (r *ProviderRegistry) GetProvider(providerID string) ObjectStorageProvider {
	switch providerID {
	case r.primaryID:
		return r.primary
	case r.secondaryID:
		return r.secondary
	case r.tertiaryID:
		return r.tertiary
	default:
		return nil
	}
}

// GetObjectWithFallback attempts to GET from primary. On failure, tries secondary,
// then tertiary. Returns the object, the provider ID that served it, and any error.
func (r *ProviderRegistry) GetObjectWithFallback(ctx context.Context, objectName string, opts GetObjectOptions) (ReadableStoredObject, string, error) {
	// Try primary
	obj, err := r.primary.GetObject(ctx, objectName, opts)
	if err == nil {
		return obj, r.primaryID, nil
	}
	primaryErr := err

	// Try secondary if available
	if r.secondary != nil {
		log.Printf("Primary provider %s failed for GetObject(%s), trying secondary %s: %v", r.primaryID, objectName, r.secondaryID, primaryErr)
		obj, err = r.secondary.GetObject(ctx, objectName, opts)
		if err == nil {
			return obj, r.secondaryID, nil
		}
		log.Printf("Secondary provider %s also failed for GetObject(%s): %v", r.secondaryID, objectName, err)

		// Try tertiary if available
		if r.tertiary != nil {
			log.Printf("Trying tertiary provider %s for GetObject(%s)", r.tertiaryID, objectName)
			obj, err = r.tertiary.GetObject(ctx, objectName, opts)
			if err == nil {
				return obj, r.tertiaryID, nil
			}
			log.Printf("Tertiary provider %s also failed for GetObject(%s): %v", r.tertiaryID, objectName, err)
			return nil, "", fmt.Errorf("all providers failed for GetObject(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
		}

		return nil, "", fmt.Errorf("all providers failed for GetObject(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
	}

	// Single provider mode, just return the primary error
	return nil, "", primaryErr
}

// GetObjectChunkWithFallback attempts chunked GET from primary, then secondary,
// then tertiary. Returns the chunk reader, the provider ID that served it, and any error.
func (r *ProviderRegistry) GetObjectChunkWithFallback(ctx context.Context, objectName string, offset, length int64) (io.ReadCloser, string, error) {
	// Try primary
	reader, err := r.primary.GetObjectChunk(ctx, objectName, offset, length)
	if err == nil {
		return reader, r.primaryID, nil
	}
	primaryErr := err

	// Try secondary if available
	if r.secondary != nil {
		log.Printf("Primary provider %s failed for GetObjectChunk(%s), trying secondary %s: %v", r.primaryID, objectName, r.secondaryID, primaryErr)
		reader, err = r.secondary.GetObjectChunk(ctx, objectName, offset, length)
		if err == nil {
			return reader, r.secondaryID, nil
		}
		log.Printf("Secondary provider %s also failed for GetObjectChunk(%s): %v", r.secondaryID, objectName, err)

		// Try tertiary if available
		if r.tertiary != nil {
			log.Printf("Trying tertiary provider %s for GetObjectChunk(%s)", r.tertiaryID, objectName)
			reader, err = r.tertiary.GetObjectChunk(ctx, objectName, offset, length)
			if err == nil {
				return reader, r.tertiaryID, nil
			}
			log.Printf("Tertiary provider %s also failed for GetObjectChunk(%s): %v", r.tertiaryID, objectName, err)
			return nil, "", fmt.Errorf("all providers failed for GetObjectChunk(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
		}

		return nil, "", fmt.Errorf("all providers failed for GetObjectChunk(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
	}

	// Single provider mode
	return nil, "", primaryErr
}
