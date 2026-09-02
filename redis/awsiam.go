// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssigner "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// awsElastiCacheIAMRegionDetect is the sentinel value that triggers
// IMDS-based region discovery instead of using a statically configured
// region.
const awsElastiCacheIAMRegionDetect = "detect"

// imdsRegionTimeout is the upper bound on a single IMDS region lookup.
const imdsRegionTimeout = 2 * time.Second

// awsElastiCacheDefaultServiceName is the SigV4 signing name used when
// DynamicAuthAWSElastiCacheIAM.ServiceName is unset.
const awsElastiCacheDefaultServiceName = "elasticache"

// awsElastiCacheMemoryDBServiceName is the SigV4 signing name for MemoryDB
// clusters.
const awsElastiCacheMemoryDBServiceName = "memorydb"

// awsElastiCacheServerlessResourceType is the only supported non-empty
// DynamicAuthAWSElastiCacheIAM.ResourceType value, required by AWS for
// ElastiCache Serverless / MemoryDB Serverless caches.
const awsElastiCacheServerlessResourceType = "ServerlessCache"

// awsElastiCacheTokenExpirySeconds is the X-Amz-Expires value on the
// presigned "connect" request. ElastiCache/MemoryDB IAM auth tokens are
// bounded to a maximum lifetime of 15 minutes server-side regardless of a
// longer presign expiry, so 900 is both the ceiling and the value used here.
const awsElastiCacheTokenExpirySeconds = "900"

// awsElastiCacheEmptyPayloadHash is the SigV4 payload hash for a body-less
// GET request: the hex-encoded SHA-256 of the empty string. ElastiCache and
// MemoryDB IAM authentication requires this exact value — "UNSIGNED-PAYLOAD"
// (the alternative some services such as S3 accept) produces a signature
// the Redis service rejects.
const awsElastiCacheEmptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// DefaultAWSElastiCacheIAMTokenTTL bounds go-redis's ConnMaxLifetime for
// ElastiCache/MemoryDB IAM auth so pooled connections are retired, and
// redialed with a fresh token, well before the previous token's 15-minute
// server-side ceiling.
const DefaultAWSElastiCacheIAMTokenTTL = 12 * time.Minute

// resolveAWSElastiCacheRegion returns the AWS region to use for signing
// ElastiCache/MemoryDB IAM auth tokens. When the configured region is
// "detect", it queries the EC2 instance metadata service.
func resolveAWSElastiCacheRegion(ctx context.Context, iam *DynamicAuthAWSElastiCacheIAM) (string, error) {
	if iam.Region == "" {
		return "", errors.New("AWS ElastiCache IAM region is not configured")
	}
	if iam.Region != awsElastiCacheIAMRegionDetect {
		return iam.Region, nil
	}

	client := imds.New(imds.Options{
		HTTPClient: &http.Client{Timeout: imdsRegionTimeout},
	})
	out, err := client.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return "", fmt.Errorf("failed to detect region from IMDS: %w", err)
	}
	return out.Region, nil
}

// awsElastiCacheIAMCredentialsFunc returns a CredentialsFunc that signs a
// fresh ElastiCache/MemoryDB IAM auth token on every call. The region and
// AWS configuration (including its credential-provider chain) are resolved
// once, at construction time: aws.CredentialsCache already caches and
// refreshes the underlying credentials internally, so reloading the whole
// chain (env vars, shared config, IMDS/web-identity/STS clients) on every
// pooled reconnect would repeat that discovery work for no benefit.
func awsElastiCacheIAMCredentialsFunc(ctx context.Context, cfg *Config) (CredentialsFunc, error) {
	iam := cfg.DynamicAuth.AWSElastiCacheIAM
	region, err := resolveAWSElastiCacheRegion(ctx, iam)
	if err != nil {
		return nil, wrapAuthError("awsElastiCacheIam", err)
	}
	serviceName := iam.ServiceName
	if serviceName == "" {
		serviceName = awsElastiCacheDefaultServiceName
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, wrapAuthError("awsElastiCacheIam", fmt.Errorf("failed to load AWS config: %w", err))
	}

	clusterName := iam.ClusterName
	resourceType := iam.ResourceType
	user := cfg.Username

	return func(ctx context.Context) (string, string, error) {
		token, err := buildAWSElastiCacheToken(ctx, awsCfg.Credentials, region, serviceName, clusterName, resourceType, user)
		if err != nil {
			return "", "", wrapAuthError("awsElastiCacheIam", err)
		}
		return user, token, nil
	}, nil
}

// buildAWSElastiCacheToken signs a presigned "connect" request for
// ElastiCache/MemoryDB IAM authentication using credsProvider (the
// workload's ambient AWS credentials — env vars, instance profile, EKS
// web-identity, etc. — already resolved and cached by the caller) and
// returns it, with its scheme stripped, as a usable AUTH password.
//
// Unlike RDS, ElastiCache and MemoryDB have no auth.BuildAuthToken
// equivalent: this hand-builds the presigned URL following AWS's documented
// IAM-auth token format — a SigV4 query-signed GET to
// https://<cluster-name>/?Action=connect&User=<user>, with the resulting
// URL's scheme removed before use as a password. When resourceType is set
// (ElastiCache/MemoryDB Serverless), a ResourceType query parameter is
// included, as AWS requires for serverless caches.
func buildAWSElastiCacheToken(
	ctx context.Context, credsProvider aws.CredentialsProvider, region, serviceName, clusterName, resourceType, user string,
) (string, error) {
	creds, err := credsProvider.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/", clusterName), nil)
	if err != nil {
		return "", fmt.Errorf("failed to build presign request: %w", err)
	}
	query := req.URL.Query()
	query.Set("Action", "connect")
	query.Set("User", user)
	query.Set("X-Amz-Expires", awsElastiCacheTokenExpirySeconds)
	if resourceType != "" {
		query.Set("ResourceType", resourceType)
	}
	req.URL.RawQuery = query.Encode()

	signer := awssigner.NewSigner()
	signedURI, _, err := signer.PresignHTTP(ctx, creds, req, awsElastiCacheEmptyPayloadHash, serviceName, region, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to presign IAM auth token: %w", err)
	}
	return strings.TrimPrefix(signedURI, "https://"), nil
}
