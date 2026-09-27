package main

// Spool layout (everything the runner writes is untrusted):
//
//	<spool>/requests/<id>.json   written by github-runner: {"repo", "run_id", "run_attempt", "artifact"}
//	<spool>/results/<id>/        written by signer: status.json + signed files
//
// A request is pending while results/<id> does not exist. The result directory is
// assembled under a temporary name and renamed, so the runner never sees a partial result.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	idRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	repoRe     = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)
	artifactRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

const maxRequestBytes = 4096

type Request struct {
	Repo       string `json:"repo"`
	RunID      int64  `json:"run_id"`
	RunAttempt int    `json:"run_attempt"`
	Artifact   string `json:"artifact"`
}

type Pending struct {
	ID      string
	ModTime time.Time
	Req     Request
	Err     error // request file is unreadable or invalid
}

func parseRequest(data []byte) (Request, error) {
	var r Request
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, err
	}
	if dec.More() {
		return r, errors.New("trailing data")
	}
	switch {
	case !repoRe.MatchString(r.Repo):
		return r, fmt.Errorf("bad repo %q", r.Repo)
	case r.RunID <= 0:
		return r, fmt.Errorf("bad run_id %d", r.RunID)
	case r.RunAttempt <= 0:
		return r, fmt.Errorf("bad run_attempt %d", r.RunAttempt)
	case !artifactRe.MatchString(r.Artifact):
		return r, fmt.Errorf("bad artifact name %q", r.Artifact)
	}
	return r, nil
}

func readRequest(file string) (Request, error) {
	f, err := openNoFollow(file)
	if err != nil {
		return Request{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Request{}, err
	}
	if !st.Mode().IsRegular() {
		return Request{}, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRequestBytes+1))
	if err != nil {
		return Request{}, err
	}
	if len(data) > maxRequestBytes {
		return Request{}, errors.New("request file too large")
	}
	return parseRequest(data)
}

// listPending returns requests without a result, oldest first. Files with names that
// cannot be a request ID are ignored: no result can be written for them.
func listPending(spool string) ([]Pending, error) {
	reqDir := filepath.Join(spool, "requests")
	entries, err := os.ReadDir(reqDir)
	if err != nil {
		return nil, err
	}
	var out []Pending
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !idRe.MatchString(id) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(spool, "results", id)); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		p := Pending{ID: id}
		if info, err := e.Info(); err == nil {
			p.ModTime = info.ModTime()
		}
		p.Req, p.Err = readRequest(filepath.Join(reqDir, e.Name()))
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.Before(out[j].ModTime) })
	return out, nil
}

type ResultFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Status struct {
	Status   string       `json:"status"` // signed | rejected | failed
	Reason   string       `json:"reason,omitempty"`
	Request  Request      `json:"request"`
	Files    []ResultFile `json:"files,omitempty"`
	Finished time.Time    `json:"finished"`
}

// writeResult publishes results/<id>. files maps result names to local paths.
func writeResult(spool, id string, st Status, files map[string]string) error {
	resDir := filepath.Join(spool, "results")
	tmp, err := os.MkdirTemp(resDir, ".tmp-"+id+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	for name, src := range files {
		dst := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	st.Finished = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "status.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(resDir, id))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
