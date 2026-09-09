module github.com/stacklok/toolhive-core/redisconn/gcp

go 1.26.0

// Development-only replacement for the untagged sibling module. Dependency
// module replacements are ignored by downstream consumers.
replace github.com/stacklok/toolhive-core/redisconn => ..

require (
	github.com/stacklok/toolhive-core/redisconn v0.0.0
	golang.org/x/oauth2 v0.36.0
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/redis/go-redis/v9 v9.22.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
