package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TTY reads answers from the controlling terminal, never from stdin, so approval cannot be
// piped in.
type TTY struct {
	f *os.File
	r *bufio.Reader
}

func openTTY() (*TTY, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("need an interactive terminal: %w", err)
	}
	return &TTY{f: f, r: bufio.NewReader(f)}, nil
}

func (t *TTY) readLine() (string, error) {
	s, err := t.r.ReadString('\n')
	return strings.TrimRight(s, "\r\n"), err
}

// Choose asks until the answer is one of choices. Input typed before the prompt appeared is
// discarded first.
func (t *TTY) Choose(prompt string, choices ...string) (string, error) {
	t.discard()
	for {
		fmt.Fprint(t.f, prompt)
		s, err := t.readLine()
		if err != nil {
			return "", err
		}
		ans := strings.ToLower(printable(s))
		for _, c := range choices {
			if ans == c {
				return ans, nil
			}
		}
		fmt.Fprintf(t.f, "Please answer %s (got %q, bytes % x).\n", strings.Join(choices, "/"), clean(s), s)
	}
}

func (t *TTY) discard() {
	flushInput(t.f)
	t.r.Reset(t.f)
}

func (t *TTY) stty(args ...string) error {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = t.f
	return cmd.Run()
}

// ReadSecret reads a line with echo off and restores echo even on Ctrl-C.
func (t *TTY) ReadSecret(prompt string) ([]byte, error) {
	t.discard()
	fmt.Fprint(t.f, prompt)
	if err := t.stty("-echo"); err != nil {
		return nil, fmt.Errorf("stty -echo: %w", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			t.stty("echo")
			fmt.Fprintln(t.f)
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sig)
		t.stty("echo")
		fmt.Fprintln(t.f)
	}()

	line, err := t.r.ReadBytes('\n')
	if err != nil {
		return nil, errors.New("no input")
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// printable keeps only printable, non-space runes: a stray byte from the terminal before
// the answer (seen in practice as invalid UTF-8) must not turn "y" into something else.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != utf8.RuneError && unicode.IsPrint(r) && !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// clean makes a string safe to print: GitHub API data could contain terminal escapes or
// bidi overrides meant to spoof the approval screen.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}
