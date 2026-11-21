/*
File:    helpers_io.go
Version: 1.4.0
Last Updated: 04-Nov-2026 19:38 CET

Description:
  Shared disk-I/O and serialization helpers for sdproxy.

Changes:
  1.4.0 - [FIX] Enabled binary cache corruption warnings in `loadASNBinCache`
          when `logSystem` or `logIdentity` is active so Simple Logging Mode
          (`logSimple: true`) retains all warnings.
  1.3.0 - [FIX] Replaced generic `loadGob` and `saveGob` declarations with
          bracket-free `loadGobInto(path string, dst any)` and `saveGob(path string, v any)`
          to prevent clipboard/markdown parsers from stripping `[T any]` syntax.
  1.2.0 - [FIX] Added `loadCompiledPolicyGob` non-generic helper so callers in
          `init_policy.go` never rely on square-bracket type instantiation syntax.
  1.1.0 - [SECURITY/FIX] Eradicated a critical Race Condition natively.
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

func syncDirForFile(filePath string) {
	if d, err := os.Open(filepath.Dir(filePath)); err == nil {
		d.Sync()
		d.Close()
	}
}

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

func loadGobInto(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewDecoder(bufio.NewReaderSize(f, 64*1024)).Decode(dst)
}

func loadCompiledPolicyGob(path string) (CompiledPolicy, error) {
	var v CompiledPolicy
	err := loadGobInto(path, &v)
	return v, err
}

func saveGob(path string, v any) error {
	return atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		return gob.NewEncoder(bw).Encode(v)
	})
}

func loadASNBinCache(path string) ([]AsnRange, bool) {
	var gobParsed []AsnRangeGob
	if err := loadGobInto(path, &gobParsed); err != nil {
		if (logIdentity || logSystem) && !os.IsNotExist(err) {
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
