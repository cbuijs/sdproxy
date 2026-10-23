/*
File:    helpers_io.go
Version: 1.3.0
Last Updated: 23-Oct-2026 14:20 CEST

Description:
  Shared disk-I/O and serialization helpers for sdproxy.

  Consolidates patterns that were previously copy-pasted across
  cache_persistence.go, identity_asn.go, init_core.go, init_policy.go,
  parental_io.go, parental_loader.go, rules.go, stats.go, webui_logs.go and
  webui_state.go.

  Provides:
    syncDirForFile        - fsync the parent directory so a rename survives power loss.
    atomicWrite           - write bytes via os.CreateTemp -> fsync -> rename -> dir-sync.
    atomicWriteBuf        - same, streaming through a 64KB buffered writer.
    loadGobInto/saveGob   - buffered gob decode/encode without generic square brackets.
    loadCompiledPolicyGob - non-generic wrapper for CompiledPolicy gob loading.
    loadASNBinCache       - typed bridge for the ASN binary cache (gob strings -> netip).
    saveASNBinCache

  [SECURITY/RELIABILITY] Every write here is crash-safe: a failed write removes
  its .tmp and leaves the existing file untouched. A 0-byte or truncated payload
  can never replace valid data.

Changes:
  1.3.0 - [FIX] Replaced generic `loadGob` and `saveGob` declarations with
          bracket-free `loadGobInto(path string, dst any)` and `saveGob(path string, v any)`
          to prevent clipboard/markdown parsers from stripping `[T any]` syntax.
  1.2.0 - [FIX] Added `loadCompiledPolicyGob` non-generic helper so callers in
          `init_policy.go` never rely on square-bracket type instantiation syntax.
  1.1.0 - [SECURITY/FIX] Eradicated a critical Race Condition natively. 
          `atomicWrite` and `atomicWriteBuf` previously used deterministic `.tmp` 
          file names natively, exposing the daemon to severe data corruption 
          if multiple threads attempted to persist memory arrays simultaneously. 
          Upgraded to `os.CreateTemp` to securely guarantee collision-free 
          atomic saves.
  1.0.0 - Initial extraction (Tier 2 dedup).
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

// atomicWrite writes data to path via a temporary file securely.
// Utilizes os.CreateTemp to eradicate race conditions during concurrent filesystem operations.
// Any failure removes the .tmp and leaves the original file intact.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
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

// atomicWriteBuf streams into path through a 64KB buffered writer.
// Applies the same fsync/rename/dir-sync guarantees as atomicWrite.
func atomicWriteBuf(path string, perm os.FileMode, fn func(*bufio.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()

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
		return fail(err)
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(err)
	}
	syncDirForFile(path)
	return nil
}

// loadGobInto decodes a gob payload from path into the pointer dst through a 64KB
// buffered reader. A decode error normally means the on-disk schema predates the
// current binary - callers should treat that as a cache miss, not a fatal error.
func loadGobInto(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewDecoder(bufio.NewReaderSize(f, 64*1024)).Decode(dst)
}

// loadCompiledPolicyGob decodes a CompiledPolicy gob file without requiring
// generic type-bracket syntax at the call site.
func loadCompiledPolicyGob(path string) (CompiledPolicy, error) {
	var v CompiledPolicy
	err := loadGobInto(path, &v)
	return v, err
}

// saveGob encodes v to path atomically through a buffered writer.
func saveGob(path string, v any) error {
	return atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		return gob.NewEncoder(bw).Encode(v)
	})
}

// loadASNBinCache decodes a compiled ASN binary cache and converts the
// string-encoded gob form back into netip.Addr ranges.
//
// Returns ok=false on a missing file, a corrupt payload, or a schema change.
func loadASNBinCache(path string) ([]AsnRange, bool) {
	var gobParsed []AsnRangeGob
	if err := loadGobInto(path, &gobParsed); err != nil {
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
