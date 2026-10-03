package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Formats osslsigncode signs that we expect from builds. Anything else in the artifact is
// an error rather than silently passed through unsigned.
var signableExt = map[string]bool{".exe": true, ".dll": true, ".msi": true}

var nameComponentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$`)

const maxArtifactFiles = 64

type File struct {
	Name   string // slash-separated path inside the artifact
	Path   string // local copy
	Size   int64
	SHA256 string
}

func checkEntryName(name string) error {
	if name == "" || strings.Contains(name, `\`) || path.IsAbs(name) || path.Clean(name) != name {
		return fmt.Errorf("unsafe path %q", name)
	}
	for _, c := range strings.Split(name, "/") {
		if !nameComponentRe.MatchString(c) {
			return fmt.Errorf("unsafe path %q", name)
		}
	}
	if !signableExt[strings.ToLower(path.Ext(name))] {
		return fmt.Errorf("unexpected file %q (only %s)", name, "exe, dll, msi")
	}
	return nil
}

// extract unpacks the artifact zip into dir. Sizes are counted on the actual data, not
// taken from the zip headers.
func extract(zipPath, dir string, maxTotal int64) ([]File, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var files []File
	var total int64
	for _, zf := range zr.File {
		if strings.HasSuffix(zf.Name, "/") && zf.Mode().IsDir() {
			continue
		}
		if !zf.Mode().IsRegular() {
			return nil, fmt.Errorf("%q is not a regular file", zf.Name)
		}
		if err := checkEntryName(zf.Name); err != nil {
			return nil, err
		}
		if len(files) == maxArtifactFiles {
			return nil, fmt.Errorf("more than %d files in artifact", maxArtifactFiles)
		}
		f, err := extractOne(zf, filepath.Join(dir, filepath.FromSlash(zf.Name)), maxTotal-total)
		if err != nil {
			return nil, err
		}
		total += f.Size
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, errors.New("artifact contains no files to sign")
	}
	return files, nil
}

func extractOne(zf *zip.File, dst string, limit int64) (File, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return File{}, err
	}
	rc, err := zf.Open()
	if err != nil {
		return File{}, err
	}
	defer rc.Close()
	// O_EXCL also rejects duplicate names in the zip.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return File{}, err
	}
	defer out.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, limit+1))
	if err != nil {
		return File{}, fmt.Errorf("%s: %w", zf.Name, err)
	}
	if n > limit {
		return File{}, errors.New("artifact contents exceed size limit")
	}
	if err := out.Close(); err != nil {
		return File{}, err
	}
	return File{Name: zf.Name, Path: dst, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
