// Copyright 2026 The OpenSandbox Authors
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
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

// requireNoUploadStaging asserts the staging file of a failed upload is gone.
func requireNoUploadStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotContainsf(t, entry.Name(), uploadTempPattern, "staging file %s was left behind", entry.Name())
	}
}

// A copy that fails after the destination was opened must not cost the sandbox
// the file it was replacing: the upload fails and the old content survives.
func TestWriteUploadStreamFailureKeepsTheReplacedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notes.md")
	original := []byte("previous content\n")
	require.NoError(t, os.WriteFile(target, original, 0o640))

	uerr := writeUploadStream(target, iotest.ErrReader(errors.New("source failed mid-copy")))

	require.NotNil(t, uerr)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, string(original), string(got))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o640), info.Mode().Perm(),
			"an in-place write kept the destination mode; a staged replace must keep it too")
	}
	requireNoUploadStaging(t, dir)
}

func TestWriteUploadStreamFailureLeavesNoNewFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "absent.txt")

	uerr := writeUploadStream(target, iotest.ErrReader(errors.New("source failed mid-copy")))

	require.NotNil(t, uerr)
	_, err := os.Stat(target)
	require.ErrorIs(t, err, os.ErrNotExist)
	requireNoUploadStaging(t, dir)
}

func TestWriteUploadStreamReplacesContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notes.md")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o644))

	uerr := writeUploadStream(target, bytes.NewReader([]byte("new content")))

	require.Nil(t, uerr)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "new content", string(got))
	requireNoUploadStaging(t, dir)
}

// An upload to a symlinked path keeps writing the link target, as an in-place
// write did, instead of replacing the link with a regular file.
func TestWriteUploadStreamFollowsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "current")
	require.NoError(t, os.WriteFile(realFile, []byte("old"), 0o644))
	if err := os.Symlink(realFile, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	uerr := writeUploadStream(link, bytes.NewReader([]byte("through the link")))

	require.Nil(t, uerr)
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink, "the symlink itself must survive the replace")
	got, err := os.ReadFile(realFile)
	require.NoError(t, err)
	require.Equal(t, "through the link", string(got))
}

// The multipart entry point keeps honoring the metadata path and mode.
func TestUploadFileWritesThroughMultipart(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "uploaded.txt")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	metadata, err := writer.CreateFormFile("metadata", "metadata")
	require.NoError(t, err)
	_, err = metadata.Write([]byte(`{"path":"` + filepath.ToSlash(target) + `","mode":644}`))
	require.NoError(t, err)
	filePart, err := writer.CreateFormFile("file", "uploaded.txt")
	require.NoError(t, err)
	_, err = filePart.Write([]byte("multipart payload"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	ctrl, rec := newFilesystemController(t, http.MethodPost, "/files/upload", body.Bytes())
	ctrl.ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())
	ctrl.UploadFile()

	require.Equal(t, http.StatusOK, rec.Code)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "multipart payload", string(got))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	}
	requireNoUploadStaging(t, dir)
}
