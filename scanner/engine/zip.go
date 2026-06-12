package engine

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"
)

// FilesFromZip explodes a (GitHub-style) zip archive into InputFiles.
// GitHub zipballs nest everything under a "{repo}-{ref}/" root, which is
// stripped. Limits guard against zip bombs.
func FilesFromZip(data []byte, maxFiles int, maxFileBytes int, maxTotalBytes int64) ([]InputFile, error) {
	if maxFiles <= 0 {
		maxFiles = 6000
	}
	if maxFileBytes <= 0 {
		maxFileBytes = 1 << 20 // 1 MiB
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = 250 << 20 // 250 MiB decompressed
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	// Detect the single shared root directory, if any.
	root := ""
	for i, f := range r.File {
		name := f.Name
		slash := strings.IndexByte(name, '/')
		var head string
		if slash >= 0 {
			head = name[:slash+1]
		}
		if i == 0 {
			root = head
		} else if head != root {
			root = ""
			break
		}
	}

	var out []InputFile
	var total int64
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.TrimPrefix(f.Name, root)
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			continue
		}
		if len(out) >= maxFiles {
			break
		}
		if int(f.UncompressedSize64) > maxFileBytes {
			// Keep an entry so the building still appears in the city,
			// but don't inflate the content.
			out = append(out, InputFile{Path: name, Size: int(f.UncompressedSize64)})
			continue
		}
		if total+int64(f.UncompressedSize64) > maxTotalBytes {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf, err := io.ReadAll(io.LimitReader(rc, int64(maxFileBytes)+1))
		rc.Close()
		if err != nil {
			continue
		}
		total += int64(len(buf))
		out = append(out, InputFile{Path: name, Data: buf})
	}
	if len(out) == 0 {
		return nil, errors.New("zip archive contained no readable files")
	}
	return out, nil
}
