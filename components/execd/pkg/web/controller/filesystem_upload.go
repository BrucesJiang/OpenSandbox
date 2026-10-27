// Copyright 2025 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/alibaba/opensandbox/execd/pkg/log"
	"github.com/alibaba/opensandbox/execd/pkg/util/pathutil"
	"github.com/alibaba/opensandbox/execd/pkg/web/model"
)

type uploadError struct {
	status  int
	code    model.ErrorCode
	message string
}

func newUploadError(status int, code model.ErrorCode, message string) *uploadError {
	return &uploadError{status: status, code: code, message: message}
}

func (c *FilesystemController) UploadFile() {
	rec := beginFilesystemMetric("upload")
	defer rec.Finish(c.basicController)

	metadataParts, fileParts, uerr := c.parseUploadForm()
	if uerr != nil {
		c.RespondError(uerr.status, uerr.code, uerr.message)
		return
	}

	for i := range metadataParts {
		if uerr := c.processUploadPair(metadataParts[i], fileParts[i]); uerr != nil {
			c.RespondError(uerr.status, uerr.code, uerr.message)
			return
		}
	}

	rec.MarkSuccess()
	c.RespondSuccess(nil)
}

func (c *FilesystemController) parseUploadForm() ([]*multipart.FileHeader, []*multipart.FileHeader, *uploadError) {
	return parseUploadForm(c.ctx)
}

func parseUploadForm(ctx *gin.Context) ([]*multipart.FileHeader, []*multipart.FileHeader, *uploadError) {
	form, err := ctx.MultipartForm()
	if err != nil || form == nil {
		return nil, nil, newUploadError(http.StatusBadRequest, model.ErrorCodeInvalidFile, "multipart form is empty")
	}

	metadataParts := form.File["metadata"]
	fileParts := form.File["file"]

	if len(metadataParts) == 0 {
		return nil, nil, newUploadError(http.StatusBadRequest, model.ErrorCodeInvalidFileMetadata, "metadata file is missing")
	}
	if len(fileParts) == 0 {
		return nil, nil, newUploadError(http.StatusBadRequest, model.ErrorCodeInvalidFileContent, "file is missing")
	}
	if len(metadataParts) != len(fileParts) {
		return nil, nil, newUploadError(
			http.StatusBadRequest,
			model.ErrorCodeInvalidFile,
			fmt.Sprintf("metadata and file count mismatch: %d vs %d", len(metadataParts), len(fileParts)),
		)
	}
	return metadataParts, fileParts, nil
}

func (c *FilesystemController) processUploadPair(metadataHeader, fileHeader *multipart.FileHeader) *uploadError {
	meta, uerr := parseUploadMetadata(metadataHeader)
	if uerr != nil {
		return uerr
	}

	resolvedPath, uerr := resolveUploadTarget(meta.Path, meta.Permission)
	if uerr != nil {
		return uerr
	}

	if uerr := writeUploadFile(resolvedPath, fileHeader); uerr != nil {
		return uerr
	}

	return applyUploadPermission(resolvedPath, meta.Permission)
}

func parseUploadMetadata(header *multipart.FileHeader) (*model.FileMetadata, *uploadError) {
	metadataFile, err := header.Open()
	if err != nil {
		return nil, newUploadError(
			http.StatusBadRequest,
			model.ErrorCodeInvalidFileMetadata,
			fmt.Sprintf("error opening metadata file. %v", err),
		)
	}
	metaBytes, err := io.ReadAll(metadataFile)
	metadataFile.Close()
	if err != nil {
		return nil, newUploadError(
			http.StatusBadRequest,
			model.ErrorCodeInvalidFileMetadata,
			fmt.Sprintf("error reading metadata content. %v", err),
		)
	}

	var meta model.FileMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, newUploadError(
			http.StatusBadRequest,
			model.ErrorCodeInvalidFileMetadata,
			fmt.Sprintf("invalid metadata format. %v", err),
		)
	}
	if meta.Path == "" {
		return nil, newUploadError(http.StatusBadRequest, model.ErrorCodeInvalidFileMetadata, "metadata path is empty")
	}
	return &meta, nil
}

func resolveUploadTarget(targetPath string, perm model.Permission) (string, *uploadError) {
	resolvedPath, err := pathutil.ExpandPath(targetPath)
	if err != nil {
		return "", newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error resolving target path %s. %v", targetPath, err),
		)
	}
	targetDir := filepath.Dir(resolvedPath)
	if err := MkdirAllWithOwnership(targetDir, os.ModePerm, perm.Owner, perm.Group); err != nil {
		return "", newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error creating target directory %s. %v", targetDir, err),
		)
	}
	return resolvedPath, nil
}

func writeUploadFile(resolvedPath string, fileHeader *multipart.FileHeader) *uploadError {
	file, err := fileHeader.Open()
	if err != nil {
		return newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error opening file %s. %v", fileHeader.Filename, err),
		)
	}
	defer file.Close()

	return writeUploadStream(resolvedPath, file)
}

// uploadTempPattern prefixes the staging file an upload writes next to its
// destination. The leading dot keeps it out of a plain directory listing.
const uploadTempPattern = ".osb-upload-"

// maxUploadSymlinkDepth bounds the final-component symlink walk; it mirrors the
// kernel's ELOOP threshold closely enough to reject a link cycle.
const maxUploadSymlinkDepth = 40

// writeUploadStream replaces target with the bytes read from r.
//
// The bytes are staged in this directory and renamed into place only once they
// are fully written and synced, so a write that fails partway - ENOSPC, an I/O
// error, the daemon being killed mid-copy - leaves the file it was replacing
// intact. An in-place O_TRUNC write destroyed it, and a sandbox usually holds
// the only copy of the file an upload overwrites.
func writeUploadStream(target string, r io.Reader) *uploadError {
	resolvedTarget, uerr := resolveUploadTargetPath(target)
	if uerr != nil {
		return uerr
	}

	existing, statErr := os.Stat(resolvedTarget)
	switch {
	case statErr == nil && !existing.Mode().IsRegular():
		// A device or a FIFO cannot be staged and renamed over without being
		// replaced by a regular file, so keep refusing them as before.
		return newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error opening destination file %s. not a regular file", resolvedTarget),
		)
	case statErr == nil:
		// A rename only needs a writable directory, so probe the file itself to
		// keep rejecting a read-only destination the way an in-place write did.
		probe, err := os.OpenFile(resolvedTarget, os.O_WRONLY, 0)
		if err != nil {
			return newUploadError(
				http.StatusInternalServerError,
				model.ErrorCodeRuntimeError,
				fmt.Sprintf("error opening destination file %s. %v", resolvedTarget, err),
			)
		}
		_ = probe.Close()
	case !errors.Is(statErr, fs.ErrNotExist):
		return newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error opening destination file %s. %v", resolvedTarget, statErr),
		)
	}

	tmp, err := createUploadTemp(filepath.Dir(resolvedTarget))
	if err != nil {
		return newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error creating the upload staging file for %s. %v", resolvedTarget, err),
		)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if statErr == nil {
		// An in-place write kept the metadata of the file it overwrote: carry
		// the mode over, and the owner/group where the platform exposes them,
		// so replacing the file does not change who can read or write it.
		if err := tmp.Chmod(existing.Mode().Perm()); err != nil {
			return uploadWriteError(resolvedTarget, err)
		}
		if err := copyFileOwnership(tmpName, existing); err != nil {
			log.Warn("upload: preserve owner/group of %s: %v", resolvedTarget, err)
		}
	}

	if _, err := io.Copy(tmp, r); err != nil {
		return uploadWriteError(resolvedTarget, err)
	}
	if err := tmp.Sync(); err != nil {
		log.Error("upload: sync target file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return uploadWriteError(resolvedTarget, err)
	}
	if err := os.Rename(tmpName, resolvedTarget); err != nil {
		return uploadWriteError(resolvedTarget, err)
	}
	committed = true

	// fsync parent directory so the new dirent is durable and visible on
	// weakly-coherent filesystems (virtio-fs, 9pfs, etc.). Best-effort:
	// some filesystems return ENOTSUP for directory fsync.
	targetDir := filepath.Dir(resolvedTarget)
	if d, err := os.Open(targetDir); err == nil {
		if err := d.Sync(); err != nil {
			log.Warn("upload: sync parent dir %s: %v", targetDir, err)
		}
		_ = d.Close()
	}
	return nil
}

func uploadWriteError(path string, err error) *uploadError {
	return newUploadError(
		http.StatusInternalServerError,
		model.ErrorCodeRuntimeError,
		fmt.Sprintf("error writing file %s. %v", path, err),
	)
}

// createUploadTemp creates the staging file with the mode a plain create in
// this directory has today (os.ModePerm masked by the umask), so a client that
// sends no permission keeps the mode it used to get.
func createUploadTemp(dir string) (*os.File, error) {
	var suffix [8]byte
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, uploadTempPattern+hex.EncodeToString(suffix[:]))
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.ModePerm)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("could not allocate a unique staging file name")
}

// resolveUploadTargetPath follows a symlink in the final path component, so the
// rename replaces the file an in-place write would have written through the
// link instead of replacing the link itself.
func resolveUploadTargetPath(path string) (string, *uploadError) {
	resolved := path
	for i := 0; i < maxUploadSymlinkDepth; i++ {
		info, err := os.Lstat(resolved)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// A new file, or the target of a dangling link.
				return resolved, nil
			}
			return "", newUploadError(
				http.StatusInternalServerError,
				model.ErrorCodeRuntimeError,
				fmt.Sprintf("error resolving destination file %s. %v", path, err),
			)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return resolved, nil
		}
		link, err := os.Readlink(resolved)
		if err != nil {
			return "", newUploadError(
				http.StatusInternalServerError,
				model.ErrorCodeRuntimeError,
				fmt.Sprintf("error resolving destination symlink %s. %v", resolved, err),
			)
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(resolved), link)
		}
		resolved = link
	}
	return "", newUploadError(
		http.StatusInternalServerError,
		model.ErrorCodeRuntimeError,
		fmt.Sprintf("error resolving destination file %s. too many levels of symbolic links", path),
	)
}

// applyUploadPermission applies the metadata permission with one retry to
// absorb metadata-propagation delay on weakly-coherent filesystems
// (virtio-fs, 9pfs). ChmodFile always invokes chown under the hood, so a
// freshly-created dirent that has not yet propagated will surface as ENOENT
// here even though the file is fully written and synced.
func applyUploadPermission(resolvedPath string, permission model.Permission) *uploadError {
	chmodErr := ChmodFile(resolvedPath, permission)
	if chmodErr != nil {
		time.Sleep(20 * time.Millisecond)
		chmodErr = ChmodFile(resolvedPath, permission)
	}
	if chmodErr != nil {
		return newUploadError(
			http.StatusInternalServerError,
			model.ErrorCodeRuntimeError,
			fmt.Sprintf("error chmoding file %s. %v", resolvedPath, chmodErr),
		)
	}
	return nil
}
