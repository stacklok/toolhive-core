// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
)

// awsRDSIAMRegionDetect is the sentinel value that triggers IMDS-based
// region discovery instead of using a statically configured region.
const awsRDSIAMRegionDetect = "detect"

// imdsRegionTimeout is the upper bound on a single IMDS region lookup.
const imdsRegionTimeout = 2 * time.Second

// resolveAWSRegion returns the AWS region to use for RDS IAM token
// generation. When the configured region is "detect", it queries the EC2
// instance metadata service.
func resolveAWSRegion(ctx context.Context, cfg *Config) (string, error) {
	iam := cfg.DynamicAuth.AWSRDSIAM
	if iam.Region == "" {
		return "", errors.New("AWS RDS IAM region is not configured")
	}
	if iam.Region != awsRDSIAMRegionDetect {
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

// awsRDSIAMToken returns a single AWS RDS IAM token for user, signed for the
// resolved region. The token can be used as a PostgreSQL password.
func awsRDSIAMToken(ctx context.Context, cfg *Config, user string) (string, error) {
	region, err := resolveAWSRegion(ctx, cfg)
	if err != nil {
		return "", wrapAuthError("awsRdsIam", err)
	}
	creds, err := loadAWSCredentials(ctx, region)
	if err != nil {
		return "", wrapAuthError("awsRdsIam", err)
	}
	token, err := signAWSToken(ctx, cfg, region, user, creds)
	if err != nil {
		return "", wrapAuthError("awsRdsIam", err)
	}
	return token, nil
}

// awsRDSIAMBeforeConnect returns a BeforeConnect hook that generates a fresh
// RDS IAM token before each connection attempt. The region and the AWS
// credentials provider are both resolved once, at hook-construction time —
// the same shape as the Azure AD and GCP Cloud SQL IAM backends — so
// per-connection cost is a single SigV4 signing operation.
//
// Resolving credentials once matters here: aws.Config.Credentials is an
// aws.CredentialsCache that caches and auto-refreshes the underlying
// credentials internally, exactly like azidentity's credential and
// oauth2.TokenSource do for the other two backends. Calling
// awsconfig.LoadDefaultConfig fresh on every connection (the previous
// behavior) discarded that cache each time, so every new pooled connection
// re-ran the full credential chain — including, under EKS Pod Identity or
// IRSA, re-exchanging the pod's identity token — inline in the connection
// path. On a pool with idle connections reaped between requests, that extra
// round trip landed inside the caller's request deadline and could tip a
// tight caller (e.g. a webhook dispatch with its own timeout) into a
// context-canceled failure through no fault of Postgres itself.
func awsRDSIAMBeforeConnect(ctx context.Context, cfg *Config, user string) (BeforeConnectFn, error) {
	region, err := resolveAWSRegion(ctx, cfg)
	if err != nil {
		return nil, wrapAuthError("awsRdsIam", err)
	}
	creds, err := loadAWSCredentials(ctx, region)
	if err != nil {
		return nil, wrapAuthError("awsRdsIam", err)
	}
	return func(ctx context.Context, conn *pgx.ConnConfig) error {
		token, err := signAWSToken(ctx, cfg, region, user, creds)
		if err != nil {
			return wrapAuthError("awsRdsIam", err)
		}
		conn.Password = token
		return nil
	}, nil
}

// loadAWSCredentials resolves the workload's ambient AWS credentials
// provider (env vars, instance profile, EKS Pod Identity, IRSA web-identity,
// etc.) for region. Resolution is lazy — like azidentity.DefaultAzureCredential
// and unlike google.DefaultTokenSource — so this call does not itself contact
// AWS; the returned provider (an aws.CredentialsCache) contacts AWS and
// caches the result on its first Retrieve call, and transparently refreshes
// it as it nears expiry thereafter.
func loadAWSCredentials(ctx context.Context, region string) (aws.CredentialsProvider, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return awsCfg.Credentials, nil
}

// signAWSToken signs an RDS IAM token for user using creds, which callers
// resolve once (see loadAWSCredentials) and reuse across signing calls.
func signAWSToken(ctx context.Context, cfg *Config, region, user string, creds aws.CredentialsProvider) (string, error) {
	endpoint := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	token, err := auth.BuildAuthToken(ctx, endpoint, region, user, creds)
	if err != nil {
		return "", fmt.Errorf("failed to build authentication token: %w", err)
	}
	return token, nil
}
