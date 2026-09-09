// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"

	redisconnaws "github.com/stacklok/toolhive-core/redisconn/aws"
)

const (
	awsElastiCacheIAMRegionDetect        = redisconnaws.RegionDetect
	awsElastiCacheDefaultServiceName     = redisconnaws.ServiceElastiCache
	awsElastiCacheMemoryDBServiceName    = redisconnaws.ServiceMemoryDB
	awsElastiCacheServerlessResourceType = redisconnaws.ResourceTypeServerlessCache
	// DefaultAWSElastiCacheIAMTokenTTL is retained for source compatibility.
	// Deprecated: use redisconnaws.DefaultConnMaxLifetime.
	DefaultAWSElastiCacheIAMTokenTTL = redisconnaws.DefaultConnMaxLifetime
)

func awsElastiCacheIAMCredentialsFunc(ctx context.Context, cfg *Config) (CredentialsFunc, error) {
	iam := cfg.DynamicAuth.AWSElastiCacheIAM
	auth, err := redisconnaws.NewDynamicAuth(ctx, redisconnaws.Config{
		Username: cfg.Username, Region: iam.Region, ClusterName: iam.ClusterName,
		ServiceName: iam.ServiceName, ResourceType: iam.ResourceType,
	})
	if err != nil {
		return nil, err
	}
	return CredentialsFunc(auth.CredentialsProviderContext), nil
}
