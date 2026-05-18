// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

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
	return buildAWSToken(ctx, cfg, region, user)
}

// awsRDSIAMBeforeConnect returns a BeforeConnect hook that generates a fresh
// RDS IAM token before each connection attempt. The region is resolved once
// at construction time; per-connection cost is reduced to a single signing
// operation.
func awsRDSIAMBeforeConnect(ctx context.Context, cfg *Config, user string) (BeforeConnectFn, error) {
	region, err := resolveAWSRegion(ctx, cfg)
	if err != nil {
		return nil, wrapAuthError("awsRdsIam", err)
	}
	return func(ctx context.Context, conn *pgx.ConnConfig) error {
		token, err := buildAWSToken(ctx, cfg, region, user)
		if err != nil {
			return wrapAuthError("awsRdsIam", err)
		}
		conn.Password = token
		return nil
	}, nil
}

// buildAWSToken signs an RDS IAM token using the workload's ambient AWS
// credentials (env vars, instance profile, EKS web-identity, etc.).
func buildAWSToken(ctx context.Context, cfg *Config, region, user string) (string, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}
	endpoint := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	token, err := auth.BuildAuthToken(ctx, endpoint, region, user, awsCfg.Credentials)
	if err != nil {
		return "", fmt.Errorf("failed to build authentication token: %w", err)
	}
	return token, nil
}
