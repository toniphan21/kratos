// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// MaxSchemaBodyBytes caps the raw byte size of an identity schema fetched
// from any source. Documents above this size cannot be cached or compiled.
// The cap protects against memory exhaustion from a customer-controlled URL
// returning an arbitrarily large body. It is independent of the schema's
// internal structure: realistic identity schemas are well under this limit.
const MaxSchemaBodyBytes = 1 << 20 // 1 MiB.

// preValidateSchema walks a parsed identity schema document and rejects
// patterns that would let a customer-supplied schema crash kratos at
// compile or validate time.
//
// Specifically, this function rejects:
//
//   - Any cycle in the document's `$ref` chain graph: a sequence of `$ref`
//     nodes P₀ → P₁ → … → Pₙ → P₀ in which every step is a `$ref`. The
//     upstream compiler memoizes ref resolution to terminate compilation,
//     but the resulting `*Schema` graph contains the cycle, and at
//     validate time `s.Ref.validate(v)` recurses indefinitely and crashes
//     the process via fatal stack overflow (jsonschema/v3
//     schema.go:155-169 has no validate-time cycle guard, and stack
//     overflow is unrecoverable).
//   - A `pattern` or `patternProperties` key whose value is not a valid
//     regular expression — the upstream compiler uses regexp.MustCompile,
//     which panics, and the compile path has no panic recovery.
//
// Cycles whose intermediate nodes have non-`$ref` validation (e.g. a
// `$ref` to an ancestor that contains a `properties` map) are NOT
// rejected: each cycle iteration consumes at least one level of input, so
// recursion is bounded by JSON parser depth. Detecting the dangerous
// pure-ref subgraph is the goal.
//
// This function does not bound the schema's structural size (nesting
// depth, key count, array arity). Realistic identity schemas vary widely,
// and bounding them at the loader layer rejected legitimate documents.
// The body size cap (MaxSchemaBodyBytes) plus Go stdlib's JSON nesting
// limit (10000) provide the structural backstop.
func preValidateSchema(doc any) error {
	v := &preValidator{refs: map[string]string{}}
	if err := v.walk(doc, ""); err != nil {
		return err
	}
	return v.detectRefCycles()
}

type preValidator struct {
	// refs maps each `$ref` location's JSON-pointer path to its target
	// JSON-pointer path. Targets that cannot be resolved as in-document
	// fragments (external URLs, malformed refs) are excluded — those go
	// through the loadRefURL scheme allowlist.
	refs map[string]string
}

func (p *preValidator) walk(v any, path string) error {
	switch v := v.(type) {
	case map[string]any:
		// Record `$ref` for cycle detection in detectRefCycles. Root
		// pointers (`#`, `#/`, empty) map to the empty path. Anything
		// without a `#/` prefix is external — out of scope here;
		// loadRefURL handles scheme enforcement.
		if ref, ok := v["$ref"].(string); ok {
			switch {
			case ref == "" || ref == "#" || ref == "#/":
				p.refs[path] = ""
			case strings.HasPrefix(ref, "#/"):
				p.refs[path] = strings.TrimPrefix(ref, "#")
			}
		}

		// Pre-compile `pattern` regexes so an invalid one returns a
		// kratos-side error instead of panicking deep in
		// regexp.MustCompile during the upstream compile.
		if pat, ok := v["pattern"].(string); ok {
			if _, err := regexp.Compile(pat); err != nil {
				return fmt.Errorf("identity schema rejected: invalid regex in pattern: %w", err)
			}
		}

		// patternProperties keys are themselves regexes.
		if patternProps, ok := v["patternProperties"].(map[string]any); ok {
			for raw := range patternProps {
				if _, err := regexp.Compile(raw); err != nil {
					return fmt.Errorf("identity schema rejected: invalid regex in patternProperties key %q: %w", raw, err)
				}
			}
		}

		for k, sub := range v {
			if err := p.walk(sub, path+"/"+escapeJSONPointer(k)); err != nil {
				return err
			}
		}

	case []any:
		for i, sub := range v {
			if err := p.walk(sub, path+"/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
	}

	return nil
}

// detectRefCycles reports an error if the document's `$ref` chain graph
// contains a cycle. Walking from each `$ref` location, follow the target
// path. If the target is itself a `$ref` location, continue. If the chain
// revisits a location, the resulting `*Schema` graph has a cycle that
// crashes Validate via stack overflow.
//
// The chain ends as soon as it reaches a node that is not itself a `$ref`
// — that node has its own validation logic (`properties`, `type`, etc.)
// which consumes input on each cycle iteration, so the recursion is
// bounded. Only pure `$ref` chains form unbounded loops.
func (p *preValidator) detectRefCycles() error {
	for start := range p.refs {
		visited := map[string]struct{}{}
		cur := start
		var chain []string
		for {
			if _, ok := visited[cur]; ok {
				idx := slices.Index(chain, cur)
				cycle := append(chain[idx:], cur)
				return fmt.Errorf("identity schema rejected: self-referential $ref cycle: %s",
					formatRefCycle(cycle))
			}
			visited[cur] = struct{}{}
			chain = append(chain, cur)
			next, ok := p.refs[cur]
			if !ok {
				break
			}
			cur = next
		}
	}
	return nil
}

// escapeJSONPointer encodes a property name as a JSON-pointer reference
// token (RFC 6901): `~` → `~0`, `/` → `~1`. The order matters — `~` must be
// escaped first so a literal `/` does not collide with the escape produced
// for `~`.
func escapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

// formatRefCycle renders a path slice as a human-readable arrow chain,
// rendering the empty (root) path as "#".
func formatRefCycle(paths []string) string {
	parts := make([]string, len(paths))
	for i, p := range paths {
		if p == "" {
			parts[i] = "#"
		} else {
			parts[i] = "#" + p
		}
	}
	return strings.Join(parts, " → ")
}
