package storage

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3AWSStorage implements the ObjectStorageProvider interface using AWS SDK v2.
type S3AWSStorage struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	bucketName    string
}

// Ensure S3AWSStorage implements ObjectStorageProvider
var _ ObjectStorageProvider = (*S3AWSStorage)(nil)

// awsObjectWrapper wraps s3.GetObjectOutput to implement ReadableStoredObject
type awsObjectWrapper struct {
	*s3.GetObjectOutput
}

func (w *awsObjectWrapper) Read(p []byte) (n int, err error) {
	return w.Body.Read(p)
}

func (w *awsObjectWrapper) Close() error {
	return w.Body.Close()
}

func (w *awsObjectWrapper) Stat() (ObjectInfo, error) {
	return ObjectInfo{
		// Key is not included in GetObjectOutput; the caller knows the key.
		Size:         *w.ContentLength,
		ETag:         aws.ToString(w.ETag),
		LastModified: *w.LastModified,
		ContentType:  aws.ToString(w.ContentType),
		UserMetadata: w.Metadata,
	}, nil
}

// InitS3 initializes the S3 storage provider
func InitS3() error {
	provider := StorageProvider(os.Getenv("STORAGE_PROVIDER"))
	if provider == "" {
		provider = ProviderGenericS3
	}

	// Basic configuration
	region := os.Getenv("S3_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1" // Default
	}

	accessKey := os.Getenv("S3_ACCESS_KEY")
	if accessKey == "" {
		accessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	}

	secretKey := os.Getenv("S3_SECRET_KEY")
	if secretKey == "" {
		secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}

	bucketName := os.Getenv("S3_BUCKET")
	if bucketName == "" {
		bucketName = os.Getenv("AWS_S3_BUCKET_NAME")
	}

	// Resolve endpoint URL and credentials per provider
	var endpointURL string
	usePathStyle := false

	switch provider {
	case ProviderWasabi:
		endpointURL = fmt.Sprintf("https://s3.%s.wasabi.com", region)
	case ProviderVultr:
		endpointURL = fmt.Sprintf("https://%s.vultrobjects.com", region)
	case ProviderCloudflareR2:
		endpointURL = os.Getenv("CLOUDFLARE_ENDPOINT")
		accessKey = os.Getenv("CLOUDFLARE_ACCESS_KEY_ID")
		secretKey = os.Getenv("CLOUDFLARE_SECRET_ACCESS_KEY")
		bucketName = os.Getenv("CLOUDFLARE_BUCKET_NAME")
	case ProviderBackblaze:
		endpointURL = os.Getenv("BACKBLAZE_ENDPOINT")
		accessKey = os.Getenv("BACKBLAZE_KEY_ID")
		secretKey = os.Getenv("BACKBLAZE_APPLICATION_KEY")
		bucketName = os.Getenv("BACKBLAZE_BUCKET_NAME")
	case ProviderGenericS3:
		endpointURL = os.Getenv("S3_ENDPOINT")
		if endpointURL == "" {
			endpointURL = "http://localhost:9332"
		}
		usePathStyle = true
		if forcePathStyle := os.Getenv("S3_FORCE_PATH_STYLE"); forcePathStyle == "false" {
			usePathStyle = false
		}
	}

	// Load AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with BaseEndpoint (replaces deprecated EndpointResolver)
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = usePathStyle
		if endpointURL != "" {
			o.BaseEndpoint = aws.String(endpointURL)
		}
	})

	// Create Presign client
	presignClient := s3.NewPresignClient(client)

	// Assign provider
	Provider = &S3AWSStorage{
		client:        client,
		presignClient: presignClient,
		bucketName:    bucketName,
	}

	// Ensure bucket exists (only for generic S3 which includes local/cluster)
	if provider == ProviderGenericS3 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String(bucketName),
		})

		if err != nil {
			// Try to create bucket
			_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				// Just log warning, don't fail - maybe we don't have permissions to create buckets
				log.Printf("Warning: Failed to create bucket %s: %v", bucketName, err)
			} else {
				log.Printf("Created new bucket: %s", bucketName)
			}
		}
	}

	return nil
}

// PutObject uploads an object to S3
func (s *S3AWSStorage) PutObject(ctx context.Context, objectName string, reader io.Reader, objectSize int64, opts PutObjectOptions) (UploadInfo, error) {
	input := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucketName),
		Key:           aws.String(objectName),
		Body:          reader,
		ContentLength: aws.Int64(objectSize),
		ContentType:   aws.String(opts.ContentType),
		Metadata:      opts.UserMetadata,
	}

	output, err := s.client.PutObject(ctx, input)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("failed to put object: %w", err)
	}

	return UploadInfo{
		Key:  objectName,
		ETag: aws.ToString(output.ETag),
		Size: objectSize,
	}, nil
}

// GetObject retrieves an object from S3
func (s *S3AWSStorage) GetObject(ctx context.Context, objectName string, opts GetObjectOptions) (ReadableStoredObject, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(objectName),
	}

	start, end, hasRange := opts.GetRange()
	if hasRange {
		input.Range = aws.String(fmt.Sprintf("bytes=%d-%d", start, end))
	}

	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	return &awsObjectWrapper{GetObjectOutput: output}, nil
}

// RemoveObject deletes an object from S3
func (s *S3AWSStorage) RemoveObject(ctx context.Context, objectName string, opts RemoveObjectOptions) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(objectName),
	}

	if opts.Force {
		input.BypassGovernanceRetention = aws.Bool(true)
	}

	_, err := s.client.DeleteObject(ctx, input)
	return err
}

// GetPresignedURL generates a presigned URL for an object
func (s *S3AWSStorage) GetPresignedURL(ctx context.Context, objectName string, expiry time.Duration) (string, error) {
	request, err := s.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(objectName),
	}, func(o *s3.PresignOptions) {
		o.Expires = expiry
	})

	if err != nil {
		return "", fmt.Errorf("failed to presign get object: %w", err)
	}

	return request.URL, nil
}

// InitiateMultipartUpload starts a multipart upload
func (s *S3AWSStorage) InitiateMultipartUpload(ctx context.Context, objectName string, metadata map[string]string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(s.bucketName),
		Key:         aws.String(objectName),
		ContentType: aws.String("application/octet-stream"),
		Metadata:    metadata,
	}

	output, err := s.client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to initiate multipart upload: %w", err)
	}

	return aws.ToString(output.UploadId), nil
}

// UploadPart uploads a part in a multipart upload.
// Callers must provide a seekable reader (e.g., bytes.NewReader) for
// compatibility with AWS SDK v2's SigV4 payload signing on non-TLS connections.
func (s *S3AWSStorage) UploadPart(ctx context.Context, objectName, uploadID string, partNumber int, reader io.Reader, size int64) (CompletePart, error) {
	input := &s3.UploadPartInput{
		Bucket:        aws.String(s.bucketName),
		Key:           aws.String(objectName),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(int32(partNumber)),
		Body:          reader,
		ContentLength: aws.Int64(size),
	}

	output, err := s.client.UploadPart(ctx, input)
	if err != nil {
		return CompletePart{}, fmt.Errorf("failed to upload part: %w", err)
	}

	return CompletePart{
		PartNumber: partNumber,
		ETag:       aws.ToString(output.ETag),
	}, nil
}

// CompleteMultipartUpload completes a multipart upload
func (s *S3AWSStorage) CompleteMultipartUpload(ctx context.Context, objectName, uploadID string, parts []CompletePart) error {
	var completedParts []types.CompletedPart
	for _, p := range parts {
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(p.PartNumber)),
			ETag:       aws.String(p.ETag),
		})
	}

	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s.bucketName),
		Key:      aws.String(objectName),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	_, err := s.client.CompleteMultipartUpload(ctx, input)
	return err
}

// AbortMultipartUpload aborts a multipart upload
func (s *S3AWSStorage) AbortMultipartUpload(ctx context.Context, objectName, uploadID string) error {
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(s.bucketName),
		Key:      aws.String(objectName),
		UploadId: aws.String(uploadID),
	}

	_, err := s.client.AbortMultipartUpload(ctx, input)
	return err
}

// GetObjectChunk retrieves a specific chunk of an object
func (s *S3AWSStorage) GetObjectChunk(ctx context.Context, objectName string, offset, length int64) (io.ReadCloser, error) {
	opts := GetObjectOptions{}
	opts.SetRange(offset, offset+length-1)
	return s.GetObject(ctx, objectName, opts)
}
