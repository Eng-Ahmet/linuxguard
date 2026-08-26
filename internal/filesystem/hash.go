package filesystem

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

type FileInfoMetadata struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Permissions string `json:"permissions"`
	Mode        os.FileMode
	Owner       string `json:"owner"`
	Group       string `json:"group"`
}

// CalculateSHA256 computes SHA-256 checksum of a file using streaming io.Copy to avoid memory overhead.
func CalculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file for hashing: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed hashing file content: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// GetFileMetadata retrieves detailed POSIX metadata for a given path.
func GetFileMetadata(filePath string) (*FileInfoMetadata, error) {
	stat, err := os.Lstat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to lstat file: %w", err)
	}

	meta := &FileInfoMetadata{
		Path:        filePath,
		Size:        stat.Size(),
		Permissions: stat.Mode().String(),
		Mode:        stat.Mode(),
		Owner:       "unknown",
		Group:       "unknown",
	}

	// Read SHA-256 if regular file
	if stat.Mode().IsRegular() {
		hash, err := CalculateSHA256(filePath)
		if err == nil {
			meta.SHA256 = hash
		}
	}

	// POSIX owner/group lookup
	if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
		u, err := user.LookupId(strconv.Itoa(int(sys.Uid)))
		if err == nil {
			meta.Owner = u.Username
		} else {
			meta.Owner = strconv.Itoa(int(sys.Uid))
		}

		g, err := user.LookupGroupId(strconv.Itoa(int(sys.Gid)))
		if err == nil {
			meta.Group = g.Name
		} else {
			meta.Group = strconv.Itoa(int(sys.Gid))
		}
	}

	return meta, nil
}
