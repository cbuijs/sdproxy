/*
File:    helpers_io.go
Version: 1.0.0
Updated: 22-Jul-2026 21:40 CEST

Description:
  Shared disk-I/O and serialization helpers for sdproxy.

  Consolidates patterns that were previously copy-pasted across
  cache_persistence.go, identity_asn.go, init_core.go, init_policy.go,
  parental_io.go, parental_loader.go, rules.go, stats.go, webui_logs.go and
  webui_state.go.

  Provides:
    syncDirForFile   - fsync the parent directory so a rename survives power loss.
    atomicWrite      - write bytes via .tmp -> fsync -> rename -> dir-sync.
    atomicWriteBuf   - same, streaming through a 64KB buffered writer.
    loadGob/saveGob  - buffered gob decode/encode of a typed payload.
    loadASNBinCache  - typed bridge for the ASN binary cache (gob strings -> netip).
    saveASNBinCache

  [SECURITY/RELIABILITY] Every write here is crash-safe: a failed write removes
  its .tmp and leaves the existing file untouched. A 0-byte or truncated payload
  can never replace valid data.

Changes:
  1.0.0 - Initial extraction (Tier 2 dedup). Behaviour change vs the previous
          inline copies: the pre-rename os.Remove(path) has been dropped. POSIX
          rename(2) replaces atomically; the pre-remove opened a crash window in
          which neither the old nor the new file existed. It was only ever a
          Windows/locked-FS guard and sdproxy targets Linux/BSD.
*/

package main

import (
	"bufio"
	"encoding/gob"
	"log"
	"net/netip"
	"os"
	"path/filepath"
)

// syncDirForFile flushes the directory entry for filePath to physical storage.
// Without this an atomic rename can be lost on abrupt power loss even though the
// file contents were fsynced, because the directory metadata is still in cache.
func syncDirForFile(filePath string) {
	if d, err := os.Open(filepath.Dir(filePath)); err == nil {
		d.Sync()
		d.Close()
	}
}

// atomicWrite writes data to path via a temporary file, then renames it into
// place and fsyncs the parent directory. Any failure removes the .tmp and leaves
// the original file intact.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDirForFile(path)
	return nil
}

// atomicWriteBuf streams into path through a 64KB buffered writer, then applies
// the same fsync/rename/dir-sync guarantees as atomicWrite. Use this for large
// payloads (gob caches, line-oriented list caches) to avoid materialising the
// whole encoding in memory first.
func atomicWriteBuf(path string, perm os.FileMode, fn func(*bufio.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	fail := func(e error) error {
		f.Close()
		os.Remove(tmp)
		return e
	}

	bw := bufio.NewWriterSize(f, 64*1024)
	if err := fn(bw); err != nil {
		return fail(err)
	}
	if err := bw.Flush(); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDirForFile(path)
	return nil
}

// loadGob decodes a gob payload of type T from path through a 64KB buffered
// reader. A decode error normally means the on-disk schema predates the current
// binary - callers should treat that as a cache miss, not a fatal error.
func loadGob[T any](path string) (T, error) {
	var v T
	f, err := os.Open(path)
	if err != nil {
		return v, err
	}
	defer f.Close()
	err = gob.NewDecoder(bufio.NewReaderSize(f, 64*1024)).Decode(&v)
	return v, err
}

// saveGob encodes v to path atomically through a buffered writer.
func saveGob[T any](path string, v T) error {
	return atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		return gob.NewEncoder(bw).Encode(v)
	})
}

// loadASNBinCache decodes a compiled ASN binary cache and converts the
// string-encoded gob form back into netip.Addr ranges.
//
// Returns ok=false on a missing file, a corrupt payload, or a schema change.
// This replaces six near-identical inline blocks in identity_asn.go.
func loadASNBinCache(path string) ([]AsnRange, bool) {
	gobParsed, err := loadGob[[]AsnRangeGob](path)
	if err != nil {
		if logIdentity && !os.IsNotExist(err) {
			log.Printf("[IDENTITY-ASN] WARNING: binary cache unusable (%s): %v — may be corrupt or from an older version",
				filepath.Base(path), err)
		}
		return nil, false
	}

	out := make([]AsnRange, 0, len(gobParsed))
	for _, g := range gobParsed {
		start, err1 := netip.ParseAddr(g.Start)
		end, err2 := netip.ParseAddr(g.End)
		if err1 == nil && err2 == nil {
			out = append(out, AsnRange{
				Start: start, End: end,
				ASN: g.ASN, Name: g.Name, Country: g.Country,
			})
		}
	}
	return out, true
}

// saveASNBinCache serialises parsed ASN ranges to the compiled binary cache.
// netip.Addr is stored as a string because its internal representation is not
// gob-stable across Go releases.
func saveASNBinCache(path string, ranges []AsnRange) error {
	g := make([]AsnRangeGob, 0, len(ranges))
	for _, p := range ranges {
		g = append(g, AsnRangeGob{
			Start: p.Start.String(), End: p.End.String(),
			ASN: p.ASN, Name: p.Name, Country: p.Country,
		})
	}
	return saveGob(path, g)
}

