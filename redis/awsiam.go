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
// DynamicAuthAWSElastiCacheIAM.ServiceName is unset. Use "memorydb" for
// MemoryDB clusters.
const awsElastiCacheDefaultServiceName = "elasticache"

// awsElastiCacheTokenExpirySeconds is the X-Amz-Expires value on the
// presigned "connect" request. ElastiCache/MemoryDB IAM auth tokens are
// bounded to a maximum lifetime of 15 minutes server-side regardless of a
// longer presign expiry, so 900 is both the ceiling and the value used here.
const awsElastiCacheTokenExpirySeconds = "900"

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

// awsElastiCacheIAMTokenFunc returns a TokenFunc that signs a fresh
// ElastiCache/MemoryDB IAM auth token on every call. The region and service
// name are resolved once, at construction time; per-call cost is a single
// signing operation.
func awsElastiCacheIAMTokenFunc(ctx context.Context, cfg *Config) (TokenFunc, error) {
	iam := cfg.DynamicAuth.AWSElastiCacheIAM
	region, err := resolveAWSElastiCacheRegion(ctx, iam)
	if err != nil {
		return nil, wrapAuthError("awsElastiCacheIam", err)
	}
	serviceName := iam.ServiceName
	if serviceName == "" {
		serviceName = awsElastiCacheDefaultServiceName
	}
	clusterName := iam.ClusterName
	user := cfg.Username

	return func(ctx context.Context) (string, error) {
		token, err := buildAWSElastiCacheToken(ctx, region, serviceName, clusterName, user)
		if err != nil {
			return "", wrapAuthError("awsElastiCacheIam", err)
		}
		return token, nil
	}, nil
}

// buildAWSElastiCacheToken signs a presigned "connect" request for
// ElastiCache/MemoryDB IAM authentication using the workload's ambient AWS
// credentials (env vars, instance profile, EKS web-identity, etc.) and
// returns it, with its scheme stripped, as a usable AUTH password.
//
// Unlike RDS, ElastiCache and MemoryDB have no auth.BuildAuthToken
// equivalent: this hand-builds the presigned URL following AWS's documented
// IAM-auth token format — a SigV4 query-signed GET to
// https://<cluster-name>/?Action=connect&User=<user>, with the resulting
// URL's scheme removed before use as a password.
func buildAWSElastiCacheToken(ctx context.Context, region, serviceName, clusterName, user string) (string, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}
	creds, err := awsCfg.Credentials.Retrieve(ctx)
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
	req.URL.RawQuery = query.Encode()

	signer := awssigner.NewSigner()
	signedURI, _, err := signer.PresignHTTP(ctx, creds, req, "UNSIGNED-PAYLOAD", serviceName, region, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to presign IAM auth token: %w", err)
	}
	return strings.TrimPrefix(signedURI, "https://"), nil
}
