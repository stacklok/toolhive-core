module github.com/stacklok/toolhive-core/redisconn/aws

go 1.26.0

// Development-only replacement for the untagged sibling module. Dependency
// module replacements are ignored by downstream consumers.
replace github.com/stacklok/toolhive-core/redisconn => ..

require (
	github.com/aws/aws-sdk-go-v2 v1.45.1
	github.com/aws/aws-sdk-go-v2/config v1.32.40
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1
	github.com/stacklok/toolhive-core/redisconn v0.0.0
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.39 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.41 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.40 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.34.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.39.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.46.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/redis/go-redis/v9 v9.22.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
