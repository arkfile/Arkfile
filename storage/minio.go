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

type StorageConfig struct {
    Endpoint        string
    AccessKeyID     string
    SecretAccessKey string
    BucketName      string
    UseSSL         bool
}

func InitMinio() error {
    config := StorageConfig{
        Endpoint:        os.Getenv("BACKBLAZE_ENDPOINT"),
        AccessKeyID:     os.Getenv("BACKBLAZE_KEY_ID"),
        SecretAccessKey: os.Getenv("BACKBLAZE_APPLICATION_KEY"),
        BucketName:      os.Getenv("BACKBLAZE_BUCKET_NAME"),
        UseSSL:         true,
    }

    // Validate configuration
    if config.Endpoint == "" || config.AccessKeyID == "" || config.SecretAccessKey == "" || config.BucketName == "" {
        return fmt.Errorf("missing required Backblaze configuration")
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
