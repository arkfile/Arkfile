package storage

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
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

// S3ProviderConfig holds the configuration needed to create an S3 provider instance.
// Endpoint auto-generation (e.g. Wasabi from region) is done by the caller before
// calling NewS3Provider -- the factory always receives a fully-resolved endpoint.
type S3ProviderConfig struct {
	ProviderType   StorageProvider
	ProviderID     string
	Endpoint       string
	AccessKey      string
	SecretKey      string
	Bucket         string
	Region         string
	ForcePathStyle bool
}

// NewS3Provider creates a new S3AWSStorage instance from the given config.
// This factory can be called multiple times with different configs for multi-backend.
func NewS3Provider(cfg S3ProviderConfig) (*S3AWSStorage, error) {
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for %s: %w", cfg.ProviderID, err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.ForcePathStyle
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		// Disable automatic request checksum for non-TLS endpoints (e.g. local SeaweedFS).
		// AWS SDK v2 requires seekable streams for checksum computation on HTTP connections,
		// which is incompatible with streaming TeeReader used in cross-provider copies.
		if cfg.Endpoint != "" && !strings.HasPrefix(cfg.Endpoint, "https://") {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		}
	})

	presignClient := s3.NewPresignClient(client)

	return &S3AWSStorage{
		client:        client,
		presignClient: presignClient,
		bucketName:    cfg.Bucket,
	}, nil
}

// ensureBucketExists checks if a bucket exists and creates it if not (for local/generic-s3).
func ensureBucketExists(client *s3.Client, bucketName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			log.Printf("Warning: Failed to create bucket %s: %v", bucketName, err)
		} else {
			log.Printf("Created new bucket: %s", bucketName)
		}
	}
}

// readPrimaryEnvVars reads environment variables for the primary storage provider
// and returns a fully-resolved S3ProviderConfig.
func readPrimaryEnvVars() S3ProviderConfig {
	provider := StorageProvider(os.Getenv("STORAGE_PROVIDER"))
	if provider == "" {
		provider = ProviderGenericS3
	}

	region := os.Getenv("S3_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
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

	var endpointURL string
	usePathStyle := false

	switch provider {
	case ProviderWasabi:
		endpointURL = fmt.Sprintf("https://s3.%s.wasabisys.com", region)
		usePathStyle = true
	case ProviderVultr:
		endpointURL = fmt.Sprintf("https://%s.vultrobjects.com", region)
	case ProviderHetzner:
		endpointURL = fmt.Sprintf("https://%s.your-objectstorage.com", region)
		usePathStyle = true
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
	case ProviderAmazonS3:
		// AWS S3: SDK auto-resolves the endpoint from the region.
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

	providerID := os.Getenv("STORAGE_PROVIDER_ID")
	if providerID == "" {
		providerID = fmt.Sprintf("%s:%s", provider, bucketName)
	}

	return S3ProviderConfig{
		ProviderType:   provider,
		ProviderID:     providerID,
		Endpoint:       endpointURL,
		AccessKey:      accessKey,
		SecretKey:      secretKey,
		Bucket:         bucketName,
		Region:         region,
		ForcePathStyle: usePathStyle,
	}
}

// readSecondaryEnvVars reads environment variables for the secondary storage provider.
// Returns nil config if STORAGE_PROVIDER_2 is not set.
func readSecondaryEnvVars() *S3ProviderConfig {
	provider := StorageProvider(os.Getenv("STORAGE_PROVIDER_2"))
	if provider == "" {
		return nil
	}

	region := os.Getenv("STORAGE_2_REGION")
	if region == "" {
		region = "us-east-1"
	}

	endpointURL := os.Getenv("STORAGE_2_ENDPOINT")
	accessKey := os.Getenv("STORAGE_2_ACCESS_KEY")
	secretKey := os.Getenv("STORAGE_2_SECRET_KEY")
	bucketName := os.Getenv("STORAGE_2_BUCKET")
	usePathStyle := os.Getenv("STORAGE_2_FORCE_PATH_STYLE") != "false"

	// Endpoint auto-generation for known provider types
	if endpointURL == "" {
		switch provider {
		case ProviderWasabi:
			endpointURL = fmt.Sprintf("https://s3.%s.wasabisys.com", region)
		case ProviderVultr:
			endpointURL = fmt.Sprintf("https://%s.vultrobjects.com", region)
		case ProviderHetzner:
			endpointURL = fmt.Sprintf("https://%s.your-objectstorage.com", region)
			usePathStyle = true
		}
	}

	providerID := os.Getenv("STORAGE_PROVIDER_2_ID")
	if providerID == "" {
		providerID = fmt.Sprintf("%s:%s", provider, bucketName)
	}

	return &S3ProviderConfig{
		ProviderType:   provider,
		ProviderID:     providerID,
		Endpoint:       endpointURL,
		AccessKey:      accessKey,
		SecretKey:      secretKey,
		Bucket:         bucketName,
		Region:         region,
		ForcePathStyle: usePathStyle,
	}
}

// readTertiaryEnvVars reads environment variables for the tertiary storage provider.
// Returns nil config if STORAGE_PROVIDER_3 is not set.
func readTertiaryEnvVars() *S3ProviderConfig {
	provider := StorageProvider(os.Getenv("STORAGE_PROVIDER_3"))
	if provider == "" {
		return nil
	}

	region := os.Getenv("STORAGE_3_REGION")
	if region == "" {
		region = "us-east-1"
	}

	endpointURL := os.Getenv("STORAGE_3_ENDPOINT")
	accessKey := os.Getenv("STORAGE_3_ACCESS_KEY")
	secretKey := os.Getenv("STORAGE_3_SECRET_KEY")
	bucketName := os.Getenv("STORAGE_3_BUCKET")
	usePathStyle := os.Getenv("STORAGE_3_FORCE_PATH_STYLE") != "false"

	// Endpoint auto-generation for known provider types
	if endpointURL == "" {
		switch provider {
		case ProviderWasabi:
			endpointURL = fmt.Sprintf("https://s3.%s.wasabisys.com", region)
		case ProviderVultr:
			endpointURL = fmt.Sprintf("https://%s.vultrobjects.com", region)
		case ProviderHetzner:
			endpointURL = fmt.Sprintf("https://%s.your-objectstorage.com", region)
			usePathStyle = true
		}
	}

	providerID := os.Getenv("STORAGE_PROVIDER_3_ID")
	if providerID == "" {
		providerID = fmt.Sprintf("%s:%s", provider, bucketName)
	}

	return &S3ProviderConfig{
		ProviderType:   provider,
		ProviderID:     providerID,
		Endpoint:       endpointURL,
		AccessKey:      accessKey,
		SecretKey:      secretKey,
		Bucket:         bucketName,
		Region:         region,
		ForcePathStyle: usePathStyle,
	}
}

// InitS3 initializes the S3 storage provider(s) and builds the ProviderRegistry.
func InitS3() error {
	// Read and create primary provider
	primaryCfg := readPrimaryEnvVars()
	primaryProvider, err := NewS3Provider(primaryCfg)
	if err != nil {
		return fmt.Errorf("failed to initialize primary storage provider: %w", err)
	}

	// Build registry with primary
	Registry = NewProviderRegistry(primaryProvider, primaryCfg.ProviderID)
	log.Printf("Storage: primary provider initialized: %s (type=%s, bucket=%s)", primaryCfg.ProviderID, primaryCfg.ProviderType, primaryCfg.Bucket)

	// Ensure primary bucket exists (for generic-s3 / local providers)
	if primaryCfg.ProviderType == ProviderGenericS3 {
		ensureBucketExists(primaryProvider.client, primaryCfg.Bucket)
	}

	// Read and create optional secondary provider
	secondaryCfg := readSecondaryEnvVars()
	if secondaryCfg != nil {
		secondaryProvider, err := NewS3Provider(*secondaryCfg)
		if err != nil {
			log.Printf("Warning: Failed to initialize secondary storage provider %s: %v", secondaryCfg.ProviderID, err)
		} else {
			Registry.SetSecondary(secondaryProvider, secondaryCfg.ProviderID)
			log.Printf("Storage: secondary provider initialized: %s (type=%s, bucket=%s)", secondaryCfg.ProviderID, secondaryCfg.ProviderType, secondaryCfg.Bucket)

			if secondaryCfg.ProviderType == ProviderGenericS3 {
				ensureBucketExists(secondaryProvider.client, secondaryCfg.Bucket)
			}
		}
	}

	// Read and create optional tertiary provider (requires secondary)
	if Registry.HasSecondary() {
		tertiaryCfg := readTertiaryEnvVars()
		if tertiaryCfg != nil {
			tertiaryProvider, err := NewS3Provider(*tertiaryCfg)
			if err != nil {
				log.Printf("Warning: Failed to initialize tertiary storage provider %s: %v", tertiaryCfg.ProviderID, err)
			} else {
				Registry.SetTertiary(tertiaryProvider, tertiaryCfg.ProviderID)
				log.Printf("Storage: tertiary provider initialized: %s (type=%s, bucket=%s)", tertiaryCfg.ProviderID, tertiaryCfg.ProviderType, tertiaryCfg.Bucket)

				if tertiaryCfg.ProviderType == ProviderGenericS3 {
					ensureBucketExists(tertiaryProvider.client, tertiaryCfg.Bucket)
				}
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

// HeadObject returns the size of an object in bytes without downloading it.
// Uses the S3 HeadObject API. Returns an error if the object does not exist.
func (s *S3AWSStorage) HeadObject(ctx context.Context, objectName string) (int64, error) {
	output, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return 0, fmt.Errorf("HeadObject failed for %s: %w", objectName, err)
	}
	size := int64(0)
	if output.ContentLength != nil {
		size = *output.ContentLength
	}
	return size, nil
}
