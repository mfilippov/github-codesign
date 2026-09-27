package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const apiBase = "https://api.github.com"

type GitHub struct {
	token  string
	client *http.Client
}

func newGitHub(token string) *GitHub {
	// Go drops the Authorization header when a redirect leaves api.github.com, so the
	// token is not sent to the blob storage that serves artifact downloads.
	return &GitHub{token: token, client: &http.Client{Timeout: 10 * time.Minute}}
}

type Run struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	DisplayTitle    string `json:"display_title"`
	Path            string `json:"path"`
	RunNumber       int    `json:"run_number"`
	RunAttempt      int    `json:"run_attempt"`
	Event           string `json:"event"`
	Status          string `json:"status"`
	HeadBranch      string `json:"head_branch"`
	HeadSHA         string `json:"head_sha"`
	HTMLURL         string `json:"html_url"`
	Actor           User   `json:"actor"`
	TriggeringActor User   `json:"triggering_actor"`
	Repository      Repo   `json:"repository"`
	HeadRepository  Repo   `json:"head_repository"`
}

type User struct {
	Login string `json:"login"`
}

type Repo struct {
	FullName string `json:"full_name"`
}

type Artifact struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	SizeInBytes int64  `json:"size_in_bytes"`
	Expired     bool   `json:"expired"`
	Digest      string `json:"digest"`
	WorkflowRun struct {
		ID      int64  `json:"id"`
		HeadSHA string `json:"head_sha"`
	} `json:"workflow_run"`
}

func (g *GitHub) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+g.token)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s: %s", u, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

func (g *GitHub) getJSON(ctx context.Context, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := g.get(ctx, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

func (g *GitHub) Run(ctx context.Context, repo string, id int64) (*Run, error) {
	var r Run
	err := g.getJSON(ctx, fmt.Sprintf("%s/repos/%s/actions/runs/%d", apiBase, repo, id), &r)
	return &r, err
}

func (g *GitHub) RunArtifacts(ctx context.Context, repo string, runID int64, name string) ([]Artifact, error) {
	var res struct {
		Artifacts []Artifact `json:"artifacts"`
	}
	u := fmt.Sprintf("%s/repos/%s/actions/runs/%d/artifacts?per_page=100&name=%s",
		apiBase, repo, runID, url.QueryEscape(name))
	err := g.getJSON(ctx, u, &res)
	return res.Artifacts, err
}

// Download saves the artifact zip to dst and checks its size and the digest reported by
// the API (sha256 of the zip as uploaded by actions/upload-artifact).
func (g *GitHub) Download(ctx context.Context, repo string, a *Artifact, dst string, max int64) error {
	algo, want, ok := strings.Cut(a.Digest, ":")
	if !ok || algo != "sha256" || len(want) != 64 {
		return fmt.Errorf("artifact has no sha256 digest (%q); use a current actions/upload-artifact", a.Digest)
	}
	if a.SizeInBytes > max {
		return fmt.Errorf("artifact is %d bytes, limit %d", a.SizeInBytes, max)
	}
	resp, err := g.get(ctx, fmt.Sprintf("%s/repos/%s/actions/artifacts/%d/zip", apiBase, repo, a.ID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if n > max {
		return fmt.Errorf("artifact download exceeds %d bytes", max)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		return fmt.Errorf("artifact digest mismatch: API says sha256:%s, downloaded sha256:%s", want, got)
	}
	return f.Close()
}
