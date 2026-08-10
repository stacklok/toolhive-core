// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package networking provides outbound HTTP client construction with an
// SSRF/egress policy: private-IP and link-local dial blocking, a same-host
// redirect policy, and a body-capped JSON fetch helper.
//
// Status: Alpha. The API may change without notice.
package networking
