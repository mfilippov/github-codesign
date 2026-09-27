package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	good := `{"repo":"mfilippov/foo","run_id":123,"run_attempt":1,"artifact":"foo-win-x64"}`
	if _, err := parseRequest([]byte(good)); err != nil {
		t.Fatalf("good request: %v", err)
	}
	bad := []string{
		`{"repo":"mfilippov/foo","run_id":123,"run_attempt":1,"artifact":"x","extra":1}`,
		`{"repo":"mfilippov/foo","run_id":0,"run_attempt":1,"artifact":"x"}`,
		`{"repo":"mfilippov/foo","run_id":1,"run_attempt":0,"artifact":"x"}`,
		`{"repo":"../etc","run_id":1,"run_attempt":1,"artifact":"x"}`,
		`{"repo":"a/b?x=1","run_id":1,"run_attempt":1,"artifact":"x"}`,
		`{"repo":"a/b","run_id":1,"run_attempt":1,"artifact":"../x"}`,
		`{"repo":"a/b","run_id":1,"run_attempt":1,"artifact":"x&name=y"}`,
		good + good,
	}
	for _, b := range bad {
		if _, err := parseRequest([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestCheckEntryName(t *testing.T) {
	for _, n := range []string{"foo.exe", "bin/foo.DLL", "foo-1.2.3+x.msi"} {
		if err := checkEntryName(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"", "/foo.exe", "../foo.exe", "a/../foo.exe", `a\foo.exe`,
		"./foo.exe", ".foo.exe", "a//foo.exe", "foo.txt", "foo", "foo.exe/"} {
		if err := checkEntryName(n); err == nil {
			t.Errorf("accepted %q", n)
		}
	}
}

func writeZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return p
}

func TestExtract(t *testing.T) {
	z := writeZip(t, map[string]string{"foo.exe": "MZfoo", "lib/bar.dll": "MZbar"})
	files, err := extract(z, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files", len(files))
	}
	for _, f := range files {
		if f.Size != 5 || len(f.SHA256) != 64 {
			t.Errorf("bad file %+v", f)
		}
	}

	if _, err := extract(writeZip(t, map[string]string{"../evil.exe": "x"}), t.TempDir(), 1<<20); err == nil {
		t.Error("accepted path traversal")
	}
	if _, err := extract(writeZip(t, map[string]string{"readme.txt": "x"}), t.TempDir(), 1<<20); err == nil {
		t.Error("accepted non-signable file")
	}
	if _, err := extract(writeZip(t, map[string]string{"big.exe": strings.Repeat("x", 100)}), t.TempDir(), 10); err == nil {
		t.Error("accepted oversize content")
	}
}

func TestExtractDuplicate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dup.zip")
	f, _ := os.Create(p)
	zw := zip.NewWriter(f)
	for range 2 {
		w, _ := zw.Create("foo.exe")
		w.Write([]byte("MZ"))
	}
	zw.Close()
	f.Close()
	if _, err := extract(p, t.TempDir(), 1<<20); err == nil {
		t.Error("accepted duplicate entry")
	}
}

func TestRuleBranches(t *testing.T) {
	r := RepoRule{Repo: "a/b", Workflows: []string{".github/workflows/release.yml"}, Branches: []string{"main", "v*"}}
	for b, want := range map[string]bool{"main": true, "v1.2.3": true, "feature": false, "": false} {
		if got := r.allowsBranch(b); got != want {
			t.Errorf("%q: got %v", b, got)
		}
	}
	if (&RepoRule{}).allowsBranch("anything") != true {
		t.Error("empty branch list should allow any")
	}
}

func TestClean(t *testing.T) {
	if got := clean("ok\x1b[2J‮txt.exe"); got != "ok?[2J?txt.exe" {
		t.Errorf("got %q", got)
	}
}

func TestSlotObjectID(t *testing.T) {
	for slot, want := range map[string]int{"9a": 1, "9A": 1, "9c": 2, "9d": 3, "9e": 4, "82": 5, "95": 24} {
		if got, err := slotObjectID(slot); err != nil || got != want {
			t.Errorf("%s: got %d, %v", slot, got, err)
		}
	}
	for _, slot := range []string{"", "9b", "81", "96", "f9", "9a0"} {
		if _, err := slotObjectID(slot); err == nil {
			t.Errorf("accepted %q", slot)
		}
	}
}

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{"y": "y", "\xd0y": "y", " y \r": "y", "\x1by": "y", "yes": "yes", "": ""} {
		if got := printable(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestSpoolRoundTrip(t *testing.T) {
	spool := t.TempDir()
	os.MkdirAll(filepath.Join(spool, "requests"), 0o755)
	os.MkdirAll(filepath.Join(spool, "results"), 0o755)
	os.WriteFile(filepath.Join(spool, "requests", "r1.json"),
		[]byte(`{"repo":"a/b","run_id":1,"run_attempt":1,"artifact":"x"}`), 0o644)
	os.WriteFile(filepath.Join(spool, "requests", "bad name!.json"), []byte(`{}`), 0o644)

	p, err := listPending(spool)
	if err != nil || len(p) != 1 || p[0].Err != nil {
		t.Fatalf("listPending: %v %+v", err, p)
	}
	src := filepath.Join(t.TempDir(), "s.exe")
	os.WriteFile(src, []byte("MZ"), 0o644)
	if err := writeResult(spool, "r1", Status{Status: "signed", Request: p[0].Req},
		map[string]string{"bin/s.exe": src}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(spool, "results", "r1", "bin", "s.exe")); err != nil {
		t.Fatal(err)
	}
	if p, _ := listPending(spool); len(p) != 0 {
		t.Fatalf("still pending: %+v", p)
	}
}
