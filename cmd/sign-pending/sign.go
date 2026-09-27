package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
)

var pinTriesRe = regexp.MustCompile(`(?m)^PIN tries remaining:\s*(\d+)`)

func pinTries() (int, error) {
	out, err := exec.Command("ykman", "piv", "info").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ykman piv info: %w: %s", err, bytes.TrimSpace(out))
	}
	m := pinTriesRe.FindSubmatch(out)
	if m == nil {
		return 0, errors.New("ykman piv info: no \"PIN tries remaining\" line")
	}
	return strconv.Atoi(string(m[1]))
}

// isSigned reports whether the file already carries an Authenticode signature.
func isSigned(in, scratch string) bool {
	defer os.Remove(scratch)
	return exec.Command("osslsigncode", "extract-signature", "-in", in, "-out", scratch).Run() == nil
}

// signFile runs osslsigncode with the PIN passed through an inherited pipe (fd 3), so it
// never appears in argv, the environment or on disk. Every run is a new PKCS#11 session,
// which with PIN policy ONCE means the PIN is needed each time.
func signFile(cfg *Config, pin []byte, in, out string) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	if _, err := w.Write(pin); err != nil {
		w.Close()
		return err
	}
	w.Close()

	cmd := exec.Command("osslsigncode", "sign",
		"-provider", "pkcs11",
		"-key", cfg.KeyURI+"?pin-source=file:/dev/fd/3",
		"-certs", cfg.Certs,
		"-h", "sha256",
		"-ts", cfg.TSAURL,
		"-in", in,
		"-out", out)
	cmd.Env = append(os.Environ(), "PKCS11_PROVIDER_MODULE="+cfg.PKCS11Module)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// verifyProvenance checks the file's Sigstore build provenance with `gh attestation verify`:
// signed by the given workflow of repo, for exactly this commit, on a GitHub-hosted runner.
// This binds the bytes to the build itself, independent of the Actions artifact store (which
// a job on a self-hosted runner in the same run could overwrite).
func verifyProvenance(token, file, repo, workflowPath, commit string) error {
	cmd := exec.Command("gh", "attestation", "verify", file,
		"--repo", repo,
		"--signer-workflow", repo+"/"+workflowPath,
		"--source-digest", commit,
		"--deny-self-hosted-runners")
	cmd.Env = append(os.Environ(), "GH_TOKEN="+token, "GH_PROMPT_DISABLED=1", "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gh attestation verify: %w\n%s", err, bytes.TrimSpace(out))
	}
	return nil
}

func verifyFile(cfg *Config, in string) error {
	out, err := exec.Command("osslsigncode", "verify",
		"-in", in, "-CAfile", cfg.CABundle, "-TSA-CAfile", cfg.CABundle).CombinedOutput()
	if err != nil {
		return fmt.Errorf("osslsigncode verify: %w\n%s", err, out)
	}
	return nil
}
