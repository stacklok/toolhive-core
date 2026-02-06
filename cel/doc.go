// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package cel provides a generic CEL expression engine for compiling and evaluating
expressions against arbitrary data contexts.

The engine provides lazy-initialized, thread-safe environment caching, expression
compilation with structured parse and type-check error reporting, boolean and
generic value evaluation helpers, and built-in safeguards against denial-of-service
via configurable expression length and runtime cost limits.

# Basic Usage

Create an engine with variable declarations, compile an expression, and evaluate it:

	engine := cel.NewEngine(
	    celgo.Variable("claims", celgo.MapType(celgo.StringType, celgo.DynType)),
	)

	expr, err := engine.Compile(`claims["sub"] == "user123"`)
	if err != nil {
	    // handle compilation error
	}

	ctx := map[string]any{"claims": map[string]any{"sub": "user123"}}
	result, err := expr.EvaluateBool(ctx)
	// result == true

# Expression Validation

Use Check to validate an expression without creating a compiled program. This is
useful for validating configuration at startup:

	err := engine.Check(`claims["sub"] == "user123"`)
	if err != nil {
	    // expression is invalid
	}

# Error Handling

Compilation errors are returned as structured types with location information:

	expr, err := engine.Compile(`claims["sub"`)
	var parseErr *cel.ParseError
	if errors.As(err, &parseErr) {
	    fmt.Println(parseErr.Source)  // the original expression
	    fmt.Println(parseErr.Errors) // line/column/message details
	}

	expr, err = engine.Compile(`undefined_var == "test"`)
	var checkErr *cel.CheckError
	if errors.As(err, &checkErr) {
	    fmt.Println(checkErr.AsJSON()) // structured JSON error details
	}

# DoS Protection

The engine includes configurable safeguards against denial-of-service:

	engine := cel.NewEngine(opts...).
	    WithMaxExpressionLength(5000). // reject overly long expressions
	    WithCostLimit(500000)          // limit runtime evaluation cost

# Concurrency

The Engine and CompiledExpression types are safe for concurrent use. A compiled
expression can be evaluated from multiple goroutines simultaneously.
*/
package cel
