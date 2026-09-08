// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awssigner "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"

	"github.com/stacklok/toolhive-core/redisconn"
)

// AWS IAM signing constants and default connection lifetime.
const (
	RegionDetect                = "detect"
	ServiceElastiCache          = "elasticache"
	ServiceMemoryDB             = "memorydb"
	ResourceTypeServerlessCache = "ServerlessCache"
	DefaultConnMaxLifetime      = 12 * time.Minute
	imdsRegionTimeout           = 2 * time.Second
	tokenExpirySeconds          = "900"
	emptyPayloadHash            = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Config configures AWS IAM token signing.
type Config struct {
	Username     string
	Region       string
	ClusterName  string
	ServiceName  string
	ResourceType string
}

// Validate checks required and enum-constrained signing settings.
func (c Config) Validate() error {
	if c.Username == "" {
		return errors.New("username is required")
	}
	if c.Region == "" {
		return errors.New("AWS ElastiCache IAM region is not configured")
	}
	if c.ClusterName == "" {
		return errors.New("cluster name is required")
	}
	switch c.ServiceName {
	case "", ServiceElastiCache, ServiceMemoryDB:
	default:
		return fmt.Errorf("service name must be empty, %q, or %q, got %q", ServiceElastiCache, ServiceMemoryDB, c.ServiceName)
	}
	switch c.ResourceType {
	case "", ResourceTypeServerlessCache:
	default:
		return fmt.Errorf("resource type must be empty or %q, got %q", ResourceTypeServerlessCache, c.ResourceType)
	}
	return nil
}

// NewDynamicAuth resolves the AWS credential chain once and returns a callback
// that signs a fresh token for each new Redis connection.
func NewDynamicAuth(ctx context.Context, cfg Config) (*redisconn.DynamicAuth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, wrapError(err)
	}
	region, err := resolveRegion(ctx, cfg.Region)
	if err != nil {
		return nil, wrapError(err)
	}
	service := cfg.ServiceName
	if service == "" {
		service = ServiceElastiCache
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, wrapError(fmt.Errorf("failed to load AWS config: %w", err))
	}
	return dynamicAuth(cfg, loaded.Credentials, region, service), nil
}

func dynamicAuth(cfg Config, credentials awssdk.CredentialsProvider, region, service string) *redisconn.DynamicAuth {
	return &redisconn.DynamicAuth{
		ConnMaxLifetime: DefaultConnMaxLifetime,
		CredentialsProviderContext: func(ctx context.Context) (string, string, error) {
			token, err := buildToken(ctx, credentials, region, service, cfg.ClusterName, cfg.ResourceType, cfg.Username)
			if err != nil {
				return "", "", wrapError(err)
			}
			return cfg.Username, token, nil
		},
	}
}

func resolveRegion(ctx context.Context, region string) (string, error) {
	if region == "" {
		return "", errors.New("AWS ElastiCache IAM region is not configured")
	}
	if region != RegionDetect {
		return region, nil
	}
	client := imds.New(imds.Options{HTTPClient: &http.Client{Timeout: imdsRegionTimeout}})
	out, err := client.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return "", fmt.Errorf("failed to detect region from IMDS: %w", err)
	}
	return out.Region, nil
}

func buildToken(
	ctx context.Context,
	credentials awssdk.CredentialsProvider,
	region, service, cluster, resourceType, username string,
) (string, error) {
	creds, err := credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/", cluster), nil)
	if err != nil {
		return "", fmt.Errorf("failed to build presign request: %w", err)
	}
	query := req.URL.Query()
	query.Set("Action", "connect")
	query.Set("User", username)
	query.Set("X-Amz-Expires", tokenExpirySeconds)
	if resourceType != "" {
		query.Set("ResourceType", resourceType)
	}
	req.URL.RawQuery = query.Encode()
	signedURI, _, err := awssigner.NewSigner().PresignHTTP(ctx, creds, req, emptyPayloadHash, service, region, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to presign IAM auth token: %w", err)
	}
	return strings.TrimPrefix(signedURI, "https://"), nil
}

func wrapError(err error) error {
	return fmt.Errorf("dynamic auth (awsElastiCacheIam): %w", err)
}
