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
		// Key is not available in GetObjectOutput, but usually known by caller.
		// We might need to pass it or store it if strictly required by interface usage.
		// For now, we'll leave it empty or see if we can get it.
		// Actually, the interface definition of Stat() returns ObjectInfo.
		// The caller of GetObject usually knows the key.
		// Let's see if we can populate what we have.
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

	// Handle specific providers
	var endpointResolver aws.EndpointResolverWithOptionsFunc
	usePathStyle := false

	switch provider {
	case ProviderWasabi:
		endpointResolver = func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: fmt.Sprintf("https://s3.%s.wasabi.com", region),
			}, nil
		}
	case ProviderVultr:
		endpointResolver = func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: fmt.Sprintf("https://%s.vultrobjects.com", region),
			}, nil
		}
	case ProviderCloudflareR2:
		endpoint := os.Getenv("CLOUDFLARE_ENDPOINT")
		accessKey = os.Getenv("CLOUDFLARE_ACCESS_KEY_ID")
		secretKey = os.Getenv("CLOUDFLARE_SECRET_ACCESS_KEY")
		bucketName = os.Getenv("CLOUDFLARE_BUCKET_NAME")
		endpointResolver = func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: endpoint,
			}, nil
		}
	case ProviderGenericS3:
		endpoint := os.Getenv("S3_ENDPOINT")
		if endpoint == "" {
			// Default to localhost if not specified (dev mode)
			endpoint = "http://localhost:9000"
		}

		endpointResolver = func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:           endpoint,
				SigningRegion: region,
			}, nil
		}

		// Check if path style is forced (default true for generic S3)
		usePathStyle = true
		if forcePathStyle := os.Getenv("S3_FORCE_PATH_STYLE"); forcePathStyle == "false" {
			usePathStyle = false
		}

	case ProviderBackblaze:
		endpoint := os.Getenv("BACKBLAZE_ENDPOINT")
		accessKey = os.Getenv("BACKBLAZE_KEY_ID")
		secretKey = os.Getenv("BACKBLAZE_APPLICATION_KEY")
		bucketName = os.Getenv("BACKBLAZE_BUCKET_NAME")
		endpointResolver = func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: endpoint,
			}, nil
		}
	}

	// Load configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Apply endpoint resolver if set
	if endpointResolver != nil {
		cfg.EndpointResolverWithOptions = endpointResolver
	}

	// Create S3 client
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = usePathStyle
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
		Body:          reader, // aws-sdk-go-v2 handles io.Reader
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
		Size: objectSize, // S3 PutObject output doesn't return size, assume success means full size
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

// UploadPart uploads a part in a multipart upload
func (s *S3AWSStorage) UploadPart(ctx context.Context, objectName, uploadID string, partNumber int, reader io.Reader, size int64) (CompletePart, error) {
	// AWS SDK v2 requires a Seekable reader for UploadPart if possible, but io.Reader works too.
	// However, for correct signing, it might need to read the body.
	// Let's try passing the reader directly.

	// Note: AWS SDK v2 might require reading the whole body into memory if it's not a file or bytes.Reader/Buffer
	// to calculate hash for signing. But we are streaming.
	// Hopefully the SDK handles streaming uploads correctly.

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

// RemoveChunkedFile removes a file and cleans up incomplete uploads
func (s *S3AWSStorage) RemoveChunkedFile(ctx context.Context, filename string, sessionID string) error {
	// Remove the object
	err := s.RemoveObject(ctx, filename, RemoveObjectOptions{})
	if err != nil {
		log.Printf("Warning: Failed to remove complete file %s: %v", filename, err)
	}

	// List incomplete uploads
	input := &s3.ListMultipartUploadsInput{
		Bucket: aws.String(s.bucketName),
		Prefix: aws.String(filename),
	}

	output, err := s.client.ListMultipartUploads(ctx, input)
	if err != nil {
		log.Printf("Warning: Failed to list multipart uploads for %s: %v", filename, err)
		return nil
	}

	for _, upload := range output.Uploads {
		if sessionID != "" && aws.ToString(upload.UploadId) != sessionID {
			continue
		}

		// Abort upload
		err := s.AbortMultipartUpload(ctx, filename, aws.ToString(upload.UploadId))
		if err != nil {
			log.Printf("Warning: Failed to abort upload %s: %v", aws.ToString(upload.UploadId), err)
		} else {
			log.Printf("Aborted incomplete upload %s for %s", aws.ToString(upload.UploadId), filename)
		}
	}

	return nil
}

// GetObjectChunk retrieves a specific chunk of an object
func (s *S3AWSStorage) GetObjectChunk(ctx context.Context, objectName string, offset, length int64) (io.ReadCloser, error) {
	opts := GetObjectOptions{}
	opts.SetRange(offset, offset+length-1)
	return s.GetObject(ctx, objectName, opts)
}

// PutObjectWithPadding uploads an object with padding
func (s *S3AWSStorage) PutObjectWithPadding(ctx context.Context, storageID string, reader io.Reader, originalSize, paddedSize int64, opts PutObjectOptions) (UploadInfo, error) {
	paddingSize := paddedSize - originalSize
	paddedReader := io.MultiReader(reader, &paddingReader{size: paddingSize})
	return s.PutObject(ctx, storageID, paddedReader, paddedSize, opts)
}

// GetObjectWithoutPadding retrieves an object without padding
func (s *S3AWSStorage) GetObjectWithoutPadding(ctx context.Context, storageID string, originalSize int64, opts GetObjectOptions) (io.ReadCloser, error) {
	object, err := s.GetObject(ctx, storageID, opts)
	if err != nil {
		return nil, err
	}
	return &limitedReadCloser{
		ReadCloser: object,
		limit:      originalSize,
	}, nil
}

// CompleteMultipartUploadWithPadding completes a multipart upload with padding
func (s *S3AWSStorage) CompleteMultipartUploadWithPadding(ctx context.Context, storageID, uploadID string, parts []CompletePart, originalSize, paddedSize int64) error {
	paddingSize := paddedSize - originalSize
	if paddingSize > 0 {
		paddingReader := &paddingReader{size: paddingSize}
		finalPartNumber := len(parts) + 1
		paddingPart, err := s.UploadPart(ctx, storageID, uploadID, finalPartNumber, paddingReader, paddingSize)
		if err != nil {
			return fmt.Errorf("failed to upload padding part: %w", err)
		}
		parts = append(parts, paddingPart)
	}
	return s.CompleteMultipartUpload(ctx, storageID, uploadID, parts)
}
