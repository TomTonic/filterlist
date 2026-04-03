package automaton

import (
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Compile options
// ---------------------------------------------------------------------------

// TestCompileMaxStates verifies that operators can cap compilation growth in
// the automaton package by asserting that state explosion past MaxStates
// returns a descriptive error.
func TestCompileMaxStates(t *testing.T) {
	rules := []Pattern{
		{Expr: "*.*.*.example.com"},
	}
	_, err := Compile(rules, CompileOptions{MaxStates: 2})
	if err == nil {
		t.Error("expected MaxStates error")
	}
	if !strings.Contains(err.Error(), "MaxStates") {
		t.Errorf("expected MaxStates in error, got: %v", err)
	}
}

// TestCompileTimeout verifies that operators can bound compile latency in the
// automaton package by asserting that an unrealistically small deadline
// triggers a timeout error.
func TestCompileTimeout(t *testing.T) {
	ruleCount := scaledHeavyTestCount(10000, 1000)
	var rules []Pattern
	for i := 0; i < ruleCount; i++ {
		rules = append(rules, Pattern{Expr: "*.*.*.example.com"})
	}
	_, err := Compile(rules, CompileOptions{CompileTimeout: 1}) // 1 nanosecond
	if err == nil {
		t.Error("expected timeout error")
	}
}

// TestCompileInvalidPattern verifies that users get a compile error for
// unsupported pattern characters in the automaton package by asserting that
// invalid rules are rejected.
func TestCompileInvalidPattern(t *testing.T) {
	rules := []Pattern{
		{Expr: "invalid_domain!"},
	}
	_, err := Compile(rules, CompileOptions{})
	if err == nil {
		t.Error("expected error for invalid character in pattern")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkCompile(b *testing.B) {
	rules := make([]Pattern, 100)
	for i := range rules {
		rules[i] = Pattern{Expr: "subdomain" + string(rune('a'+i%26)) + ".example.com"}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Compile(rules, CompileOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileLarge(b *testing.B) {
	const n = 1000
	rules := make([]Pattern, n)
	for i := range n {
		rules[i] = Pattern{Expr: fmt.Sprintf("host%d.example.com", i), RuleID: uint32(i)}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Compile(rules, CompileOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
