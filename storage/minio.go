package storage

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	MinioClient *minio.Client
	BucketName  string
)

type StorageProvider string

const (
	ProviderBackblaze StorageProvider = "backblaze"
	ProviderWasabi    StorageProvider = "wasabi"
	ProviderVultr     StorageProvider = "vultr"
	ProviderLocal     StorageProvider = "local"
	ProviderCluster   StorageProvider = "cluster"
)

type StorageConfig struct {
	Provider        StorageProvider
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	UseSSL          bool
	// Local storage specific
	LocalPath string
	// Cluster specific
	ClusterNodes []string
}

func getProviderEndpoint(provider StorageProvider, region string) string {
	switch provider {
	case ProviderWasabi:
		return fmt.Sprintf("s3.%s.wasabi.com", region)
	case ProviderVultr:
		return fmt.Sprintf("%s.vultrobjects.com", region)
	case ProviderLocal:
		return "localhost:9000" // MinIO server in filesystem mode
	case ProviderCluster:
		if nodeEndpoint := os.Getenv("MINIO_CLUSTER_NODES"); nodeEndpoint != "" {
			return nodeEndpoint // Use first node as primary endpoint
		}
		return "localhost:9000"
	default: // Backblaze
		return os.Getenv("S3_ENDPOINT")
	}
}

func InitMinio() error {
	provider := StorageProvider(os.Getenv("STORAGE_PROVIDER"))
	config := StorageConfig{
		Provider: provider,
		UseSSL:   true,
	}

	switch provider {
	case ProviderLocal:
		localPath := os.Getenv("LOCAL_STORAGE_PATH")
		if localPath == "" {
			return fmt.Errorf("LOCAL_STORAGE_PATH must be set for local storage provider")
		}
		// Ensure directory exists
		if err := os.MkdirAll(localPath, 0750); err != nil {
			return fmt.Errorf("failed to create local storage directory: %w", err)
		}
		config.LocalPath = localPath
		config.AccessKeyID = os.Getenv("MINIO_ROOT_USER")
		if config.AccessKeyID == "" {
			config.AccessKeyID = "minioadmin" // Default MinIO credentials
		}
		config.SecretAccessKey = os.Getenv("MINIO_ROOT_PASSWORD")
		if config.SecretAccessKey == "" {
			config.SecretAccessKey = "minioadmin"
		}
		config.BucketName = "arkfile"
		config.UseSSL = false // Local filesystem mode doesn't use SSL

	case ProviderCluster:
		nodeEndpoint := os.Getenv("MINIO_CLUSTER_NODES")
		if nodeEndpoint == "" {
			return fmt.Errorf("MINIO_CLUSTER_NODES must be set for cluster provider")
		}
		config.ClusterNodes = []string{nodeEndpoint} // For now, just use first node
		config.AccessKeyID = os.Getenv("MINIO_CLUSTER_ACCESS_KEY")
		config.SecretAccessKey = os.Getenv("MINIO_CLUSTER_SECRET_KEY")
		if config.AccessKeyID == "" || config.SecretAccessKey == "" {
			return fmt.Errorf("MINIO_CLUSTER_ACCESS_KEY and MINIO_CLUSTER_SECRET_KEY must be set")
		}
		config.BucketName = os.Getenv("MINIO_CLUSTER_BUCKET")
		if config.BucketName == "" {
			config.BucketName = "arkfile"
		}

	default: // External providers (Backblaze, Wasabi, Vultr)
		config.Region = os.Getenv("S3_REGION")
		config.AccessKeyID = os.Getenv("S3_ACCESS_KEY_ID")
		config.SecretAccessKey = os.Getenv("S3_SECRET_KEY")
		config.BucketName = os.Getenv("S3_BUCKET_NAME")
		// Validate region for providers that require it
		if (provider == ProviderWasabi || provider == ProviderVultr) && config.Region == "" {
			return fmt.Errorf("region is required for %s provider", provider)
		}
		// Validate required fields
		if config.AccessKeyID == "" || config.SecretAccessKey == "" || config.BucketName == "" {
			return fmt.Errorf("missing required storage configuration for provider %s", provider)
		}
	}

	// Set endpoint based on provider
	config.Endpoint = getProviderEndpoint(provider, config.Region)
	if config.Endpoint == "" {
		return fmt.Errorf("failed to determine endpoint for provider %s", provider)
	}

	BucketName = config.BucketName

	var err error
	MinioClient, err = minio.New(config.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
	})
	if err != nil {
		return fmt.Errorf("failed to create MinIO client: %w", err)
	}

	// Ensure bucket exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exists, err := MinioClient.BucketExists(ctx, config.BucketName)
	if err != nil {
		return fmt.Errorf("failed to check bucket existence: %w", err)
	}

	if !exists {
		err = createBucket(ctx, config.BucketName)
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
	}

	// Set bucket policy for private access
	err = setBucketPolicy(ctx, config.BucketName)
	if err != nil {
		return fmt.Errorf("failed to set bucket policy: %w", err)
	}

	return nil
}

func createBucket(ctx context.Context, bucketName string) error {
	err := MinioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}
	log.Printf("Created new bucket: %s", bucketName)
	return nil
}

func setBucketPolicy(ctx context.Context, bucketName string) error {
	// Set a private policy
	policy := `{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::%s/*",
                    "arn:aws:s3:::%s"
                ]
            }
        ]
    }`
	policy = fmt.Sprintf(policy, bucketName, bucketName)

	err := MinioClient.SetBucketPolicy(ctx, bucketName, policy)
	if err != nil {
		return fmt.Errorf("failed to set bucket policy: %w", err)
	}
	return nil
}

// GetPresignedURL generates a temporary URL for file download
func GetPresignedURL(filename string, expiry time.Duration) (string, error) {
	ctx := context.Background()
	url, err := MinioClient.PresignedGetObject(ctx, BucketName, filename, expiry, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}
	return url.String(), nil
}

// RemoveFile deletes a file from storage
func RemoveFile(filename string) error {
	ctx := context.Background()
	err := MinioClient.RemoveObject(ctx, BucketName, filename, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to remove file: %w", err)
	}
	return nil
}
