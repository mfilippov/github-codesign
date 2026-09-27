// sign-pending shows pending signing requests from the runner spool, resolves their
// metadata through the GitHub API, and after explicit approval signs the artifact with the
// YubiKey. See docs/architecture.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// policyError means the request itself is not acceptable; it is answered with a
// "rejected" result. Other errors (network, YubiKey) leave the request pending.
type policyError struct{ msg string }

func (e *policyError) Error() string { return e.msg }

func reject(format string, a ...any) error {
	return &policyError{fmt.Sprintf(format, a...)}
}

var errSkipped = errors.New("skipped")

func main() {
	cfgPath := flag.String("config", filepath.Join(defaultConfigDir(), "config.json"), "config file")
	list := flag.Bool("list", false, "list pending requests and exit")
	local := flag.String("local", "", "test: sign this local file instead of processing requests")
	flag.Parse()

	if err := run(*cfgPath, *list, *local); err != nil {
		fmt.Fprintln(os.Stderr, "sign-pending:", err)
		os.Exit(1)
	}
}

func run(cfgPath string, listOnly bool, local string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if local != "" {
		return signLocal(cfg, local)
	}
	pending, err := listPending(cfg.Spool)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Println("No pending requests.")
		return nil
	}
	if listOnly {
		for _, p := range pending {
			if p.Err != nil {
				fmt.Printf("%s  %s  invalid: %s\n", p.ModTime.Format(time.DateTime), p.ID, clean(p.Err.Error()))
				continue
			}
			fmt.Printf("%s  %s  %s run %d/%d artifact %s\n", p.ModTime.Format(time.DateTime), p.ID,
				p.Req.Repo, p.Req.RunID, p.Req.RunAttempt, p.Req.Artifact)
		}
		return nil
	}

	tty, err := openTTY()
	if err != nil {
		return err
	}
	gh := newGitHub(cfg.token)
	ctx := context.Background()
	for i, p := range pending {
		fmt.Printf("\n━━━ Signing request %d of %d: %s\n\n", i+1, len(pending), p.ID)
		err := process(ctx, cfg, gh, tty, p)
		var pe *policyError
		switch {
		case err == nil:
		case errors.Is(err, errSkipped):
			fmt.Println("Skipped, request stays pending.")
		case errors.As(err, &pe):
			fmt.Println("✗ Rejected:", clean(pe.msg))
			finish(cfg, p, Status{Status: "rejected", Reason: pe.msg, Request: p.Req}, nil)
		default:
			fmt.Println("✗ Error:", clean(err.Error()))
			fmt.Println("Request stays pending.")
		}
	}
	return nil
}

func finish(cfg *Config, p Pending, st Status, files map[string]string) {
	if err := writeResult(cfg.Spool, p.ID, st, files); err != nil {
		fmt.Println("✗ Could not write result:", err)
	}
	logDecision(p, st)
}

func process(ctx context.Context, cfg *Config, gh *GitHub, tty *TTY, p Pending) error {
	if p.Err != nil {
		return reject("invalid request: %v", p.Err)
	}
	req := p.Req
	rule := cfg.rule(req.Repo)
	if rule == nil {
		return reject("repository %s is not in the allowlist", req.Repo)
	}

	run, err := gh.Run(ctx, req.Repo, req.RunID)
	if err != nil {
		return err
	}
	wfPath, _, _ := strings.Cut(run.Path, "@")
	switch {
	case !strings.EqualFold(run.Repository.FullName, req.Repo):
		return reject("run belongs to %s", run.Repository.FullName)
	case !strings.EqualFold(run.HeadRepository.FullName, req.Repo):
		return reject("run is for code from %s (fork?)", run.HeadRepository.FullName)
	case !rule.allowsWorkflow(wfPath):
		return reject("workflow %s is not allowed for %s", run.Path, req.Repo)
	case !rule.allowsBranch(run.HeadBranch):
		return reject("branch/tag %q is not allowed for %s", run.HeadBranch, req.Repo)
	case run.Status != "in_progress":
		return reject("run status is %q, expected in_progress", run.Status)
	case run.RunAttempt != req.RunAttempt:
		return reject("request is for attempt %d, run is at attempt %d", req.RunAttempt, run.RunAttempt)
	}

	arts, err := gh.RunArtifacts(ctx, req.Repo, req.RunID, req.Artifact)
	if err != nil {
		return err
	}
	var art *Artifact
	for i := range arts {
		if arts[i].Name == req.Artifact {
			if art != nil {
				return reject("several artifacts named %q", req.Artifact)
			}
			art = &arts[i]
		}
	}
	switch {
	case art == nil:
		return reject("artifact %q not found in run %d", req.Artifact, req.RunID)
	case art.Expired:
		return reject("artifact %q has expired", req.Artifact)
	case art.WorkflowRun.ID != req.RunID || art.WorkflowRun.HeadSHA != run.HeadSHA:
		return reject("artifact %q does not belong to run %d", req.Artifact, req.RunID)
	}

	work, err := os.MkdirTemp("", "sign-pending-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	fmt.Printf("Downloading artifact %s (%s)...\n", clean(art.Name), size(art.SizeInBytes))
	zipPath := filepath.Join(work, "artifact.zip")
	if err := gh.Download(ctx, req.Repo, art, zipPath, cfg.MaxArtifactBytes); err != nil {
		return err
	}
	files, err := extract(zipPath, filepath.Join(work, "in"), cfg.MaxArtifactBytes*4)
	if err != nil {
		return reject("artifact: %v", err)
	}
	for _, f := range files {
		if isSigned(f.Path, filepath.Join(work, "sig")) {
			return reject("%s is already signed", f.Name)
		}
	}
	provenance := "not required for this repo"
	if rule.RequireAttestation {
		fmt.Println("Verifying build provenance...")
		for _, f := range files {
			if err := verifyProvenance(cfg.token, f.Path, req.Repo, wfPath, run.HeadSHA); err != nil {
				return reject("%s: no valid build provenance: %v", f.Name, err)
			}
		}
		provenance = "✓ all files: " + wfPath + " at this commit, GitHub-hosted runner"
	}

	fmt.Printf("\nRepository:   %s\n", clean(run.Repository.FullName))
	fmt.Printf("Workflow:     %s (%s)\n", clean(run.Name), clean(run.Path))
	fmt.Printf("Run:          #%d, attempt %d — %s\n", run.RunNumber, run.RunAttempt, clean(run.DisplayTitle))
	fmt.Printf("              %s\n", clean(run.HTMLURL))
	fmt.Printf("Event:        %s\n", clean(run.Event))
	fmt.Printf("Ref:          %s\n", clean(run.HeadBranch))
	fmt.Printf("Commit:       %s\n", clean(run.HeadSHA))
	fmt.Printf("Actor:        %s (triggered by %s)\n", clean(run.Actor.Login), clean(run.TriggeringActor.Login))
	fmt.Printf("Artifact:     %s, %s\n", clean(art.Name), clean(art.Digest))
	fmt.Printf("Provenance:   %s\n\n", clean(provenance))
	out, resFiles, err := approveAndSign(cfg, tty, files, filepath.Join(work, "out"))
	if err != nil {
		return err
	}

	st := Status{Status: "signed", Request: req, Files: resFiles}
	if err := writeResult(cfg.Spool, p.ID, st, out); err != nil {
		return err
	}
	logDecision(p, st)
	fmt.Println("✓ Signed files returned to the runner")
	return nil
}

// approveAndSign shows the files, asks for approval and the PIN, then signs and verifies
// each file into outDir. Returns result names → signed paths.
func approveAndSign(cfg *Config, tty *TTY, files []File, outDir string) (map[string]string, []ResultFile, error) {
	for _, f := range files {
		fmt.Printf("File:         %s\n", clean(f.Name))
		fmt.Printf("Size:         %s\n", size(f.Size))
		fmt.Printf("SHA256:       %s\n\n", f.SHA256)
	}

	switch ans, err := tty.Choose("Approve signing? [y=yes/n=reject/s=skip] ", "y", "n", "s"); {
	case err != nil:
		return nil, nil, err
	case ans == "s":
		return nil, nil, errSkipped
	case ans == "n":
		return nil, nil, reject("rejected by operator")
	}

	tries, err := pinTries()
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("PIN tries remaining: %d of 3\n", tries)
	if tries < 2 {
		return nil, nil, fmt.Errorf("only %d PIN try left; check the PIN with ykman before signing", tries)
	}
	pin, err := tty.ReadSecret("YubiKey PIN: ")
	if err != nil {
		return nil, nil, err
	}
	defer clear(pin)
	if len(pin) < 6 || len(pin) > 64 {
		return nil, nil, errors.New("PIN must be 6–64 characters; nothing was sent to the YubiKey")
	}

	out := map[string]string{}
	var resFiles []ResultFile
	for _, f := range files {
		// The copy was hashed when extracted and lives in our 0700 work dir; re-check it
		// anyway right before signing.
		if sum, _, err := hashFile(f.Path); err != nil || sum != f.SHA256 {
			return nil, nil, fmt.Errorf("%s changed after approval", f.Name)
		}
		signed := filepath.Join(outDir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(signed), 0o700); err != nil {
			return nil, nil, err
		}
		fmt.Printf("\nSigning %s — touch the YubiKey when it blinks\n", clean(f.Name))
		if err := signFile(cfg, pin, f.Path, signed); err != nil {
			if t, terr := pinTries(); terr == nil {
				fmt.Printf("PIN tries remaining: %d of 3\n", t)
			}
			return nil, nil, fmt.Errorf("signing %s: %w", f.Name, err)
		}
		if err := verifyFile(cfg, signed); err != nil {
			return nil, nil, err
		}
		fmt.Println("✓ Signature and timestamp verified")
		sum, n, err := hashFile(signed)
		if err != nil {
			return nil, nil, err
		}
		out[f.Name] = signed
		resFiles = append(resFiles, ResultFile{Name: f.Name, Size: n, SHA256: sum})
	}
	return out, resFiles, nil
}

// signLocal signs one local file through the same code path as a request, for testing the
// YubiKey/osslsigncode/TSA part without GitHub. Output: <name>-signed<ext> next to the input.
func signLocal(cfg *Config, in string) error {
	tty, err := openTTY()
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "sign-pending-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	name := filepath.Base(in)
	copyPath := filepath.Join(work, "in", name)
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
		return err
	}
	if err := copyFile(in, copyPath); err != nil {
		return err
	}
	sum, n, err := hashFile(copyPath)
	if err != nil {
		return err
	}
	if isSigned(copyPath, filepath.Join(work, "sig")) {
		return fmt.Errorf("%s is already signed", in)
	}
	fmt.Printf("Local test signing (no GitHub request)\n\n")
	out, _, err := approveAndSign(cfg, tty, []File{{Name: name, Path: copyPath, Size: n, SHA256: sum}},
		filepath.Join(work, "out"))
	if err != nil {
		return err
	}
	ext := filepath.Ext(in)
	dst := strings.TrimSuffix(in, ext) + "-signed" + ext
	if err := copyFile(out[name], dst); err != nil {
		return err
	}
	fmt.Println("✓ Written", dst)
	return nil
}

// logDecision appends to an audit log in signer's home; failures only warn.
func logDecision(p Pending, st Status) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "state")
	}
	dir = filepath.Join(dir, "github-codesign")
	entry := struct {
		Time time.Time `json:"time"`
		ID   string    `json:"id"`
		Status
	}{time.Now().UTC(), p.ID, st}
	data, _ := json.Marshal(entry)
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err == nil {
			_, err = f.Write(append(data, '\n'))
			f.Close()
		}
	}
	if err != nil {
		fmt.Println("warning: audit log:", err)
	}
}

func size(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
