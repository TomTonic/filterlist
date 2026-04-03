package automaton

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// DumpDot writes a Graphviz DOT representation of the DFA to w.
//
// The output is a directed graph that visualizes state transitions, accepting
// states (shown as doublecircles), and rule attribution labels. Edges sharing
// the same source and target are grouped with a compact label showing the
// covered characters.
//
// DumpDot returns an error when the receiver is nil or when writing to w
// fails. It is intended for CLI debugging and offline inspection of compiled
// filter behavior (see also the filterlist-check tool).
func (d *DFA) DumpDot(w io.Writer) error {
	if d == nil {
		return errors.New("nil DFA")
	}
	if d.start == nil {
		_, err := fmt.Fprintln(w, "digraph DFA {\n  rankdir=LR;\n  empty [shape=note, label=\"empty DFA\"];\n}")
		return err
	}

	// Build pointer → index map for output.
	stateIdx := make(map[*DFAState]int, len(d.states))
	for i := range d.states {
		stateIdx[&d.states[i]] = i
	}

	if _, err := fmt.Fprintln(w, "digraph DFA {"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  rankdir=LR;"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  start [shape=point];\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  start -> s%d;\n", stateIdx[d.start]); err != nil {
		return err
	}

	for i := range d.states {
		s := &d.states[i]
		shape := "circle"
		if s.Accept {
			shape = "doublecircle"
		}
		label := fmt.Sprintf("s%d", i)
		if s.Accept && len(s.RuleIDs) > 0 {
			label = fmt.Sprintf("s%d\\nrules:%v", i, s.RuleIDs)
		}
		if _, err := fmt.Fprintf(w, "  s%d [shape=%s, label=\"%s\"];\n", i, shape, label); err != nil {
			return err
		}

		// Group transitions by target to produce cleaner edge labels.
		targetChars := make(map[int][]rune)
		for idx, target := range s.Trans {
			if target != nil {
				targetChars[stateIdx[target]] = append(targetChars[stateIdx[target]], indexToRune(idx))
			}
		}
		for target, chars := range targetChars {
			sort.Slice(chars, func(a, b int) bool { return chars[a] < chars[b] })
			edgeLabel := compactRuneLabel(chars)
			if _, err := fmt.Fprintf(w, "  s%d -> s%d [label=\"%s\"];\n", i, target, edgeLabel); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "}"); err != nil {
		return err
	}
	return nil
}

// compactRuneLabel formats a character set into a human-readable DOT edge
// label. When the set covers the entire alphabet it returns "[dns]"; larger
// sets are abbreviated as "[N chars]"; small sets are spelled out.
func compactRuneLabel(chars []rune) string {
	if len(chars) == AlphabetSize {
		return "[dns]"
	}
	if len(chars) > 10 {
		return fmt.Sprintf("[%d chars]", len(chars))
	}
	var b strings.Builder
	for _, c := range chars {
		b.WriteRune(c)
	}
	return b.String()
}
