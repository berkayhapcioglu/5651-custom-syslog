package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Search index.
//
// Next to every sealed hour <HH>.s5651 the sealer writes <HH>.idx, a Bloom
// filter of the words in that hour (IP addresses, user names, host names,
// key names, ...). A search first asks the filters and only decompresses the
// hours that may contain every searched word.
//
// The index is derived data. It is not listed in hours.jsonl or the manifest,
// so it never affects a seal: deleting or corrupting it only makes searches
// slower, and it can be rebuilt from the sealed files at any time.

// IndexExt is the extension of index files.
const IndexExt = ".idx"

const (
	indexMagic   = "S5IX"
	indexVersion = 1
	bitsPerToken = 10 // about 1% false positives with k=7
	indexK       = 7
	maxTokenLen  = 128
)

// isSep reports whether c separates words.
func isSep(c byte) bool {
	switch c {
	case ' ', '\t', '"', '\'', ',', ';', '=', '<', '>', '(', ')', '[', ']', '{', '}', '|', '\\', '`':
		return true
	}
	return false
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// indexable reports whether a word goes into the index. Pure numbers, times
// and dates (ports, byte counters, "14:05:03", "2026-11-10") change on almost
// every line, would make the index large and are rarely searched alone.
func indexable(tok []byte) bool {
	if len(tok) < 2 || len(tok) > maxTokenLen {
		return false
	}
	for _, c := range tok {
		if !(c >= '0' && c <= '9' || c == ':' || c == '-') {
			return true
		}
	}
	return false
}

// Tokens splits s into lowercase words, calling fn for each.
func Tokens(s []byte, fn func(tok []byte)) {
	var buf [maxTokenLen + 1]byte
	i := 0
	for i < len(s) {
		for i < len(s) && isSep(s[i]) {
			i++
		}
		j := i
		for j < len(s) && !isSep(s[j]) {
			j++
		}
		if j > i {
			tok := s[i:j]
			if len(tok) <= maxTokenLen {
				n := copy(buf[:], tok)
				for k := 0; k < n; k++ {
					buf[k] = lower(buf[k])
				}
				fn(buf[:n])
			}
		}
		i = j
	}
}

func hashes(tok []byte) (uint64, uint64) {
	// FNV-1a and FNV-1 64, combined by double hashing.
	const offset, prime = 14695981039346656037, 1099511628211
	a, b := uint64(offset), uint64(offset)
	for _, c := range tok {
		a ^= uint64(c)
		a *= prime
		b *= prime
		b ^= uint64(c)
	}
	return a, b | 1
}

// BuildIndex reads raw records (one per line) and returns the index file.
// The receive time and source address columns are skipped: they are
// searched through the date/hour/device filters instead.
func BuildIndex(r io.Reader) ([]byte, error) {
	set := map[string]struct{}{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		// <time>\t<source>\t<message>
		if t := bytes.IndexByte(line, '\t'); t >= 0 {
			line = line[t+1:]
			if t = bytes.IndexByte(line, '\t'); t >= 0 {
				line = line[t+1:]
			}
		}
		Tokens(line, func(tok []byte) {
			if indexable(tok) {
				if _, ok := set[string(tok)]; !ok {
					set[string(tok)] = struct{}{}
				}
			}
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	m := uint64(len(set)) * bitsPerToken
	m = max((m+63)/64*64, 64)
	bits := make([]uint64, m/64)
	for tok := range set {
		a, b := hashes([]byte(tok))
		for i := uint64(0); i < indexK; i++ {
			bit := (a + i*b) % m
			bits[bit/64] |= 1 << (bit % 64)
		}
	}
	out := make([]byte, 0, 4+1+1+4+8+len(bits)*8+32)
	out = append(out, indexMagic...)
	out = append(out, indexVersion, indexK)
	out = binary.BigEndian.AppendUint32(out, uint32(min(len(set), 1<<31))) // #nosec G115 -- bounded
	out = binary.BigEndian.AppendUint64(out, m)
	for _, w := range bits {
		out = binary.BigEndian.AppendUint64(out, w)
	}
	sum := sha256.Sum256(out)
	return append(out, sum[:]...), nil
}

// Index is a parsed index file.
type Index struct {
	k    uint64
	m    uint64
	bits []byte
}

// ParseIndex checks and parses an index file.
func ParseIndex(b []byte) (*Index, error) {
	const hdr = 4 + 1 + 1 + 4 + 8
	if len(b) < hdr+32 || string(b[:4]) != indexMagic || b[4] != indexVersion {
		return nil, errors.New("index: bad header")
	}
	body, sum := b[:len(b)-32], b[len(b)-32:]
	if s := sha256.Sum256(body); !bytes.Equal(s[:], sum) {
		return nil, errors.New("index: checksum mismatch")
	}
	ix := &Index{k: uint64(b[5]), m: binary.BigEndian.Uint64(b[10:18]), bits: body[hdr:]}
	if ix.k == 0 || ix.k > 16 || ix.m == 0 || ix.m%64 != 0 || uint64(len(ix.bits))*8 != ix.m {
		return nil, errors.New("index: bad size")
	}
	return ix, nil
}

// MayContain reports whether the hour may contain the word tok (lowercase).
func (ix *Index) MayContain(tok []byte) bool {
	a, b := hashes(tok)
	for i := uint64(0); i < ix.k; i++ {
		bit := (a + i*b) % ix.m
		w := bit / 64
		word := binary.BigEndian.Uint64(ix.bits[w*8 : w*8+8])
		if word&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

// QueryTokens returns the indexable words of a search text.
func QueryTokens(q []byte) [][]byte {
	var out [][]byte
	Tokens(q, func(tok []byte) {
		if indexable(tok) {
			out = append(out, append([]byte(nil), tok...))
		}
	})
	return out
}

// IndexPath is the index file for a sealed hour.
func IndexPath(dayDir, device, hour string) string {
	return filepath.Join(dayDir, device, hour+IndexExt)
}

// WriteIndex writes the index for one hour from its raw content.
func WriteIndex(dayDir, device, hour string, raw io.Reader) (int, error) {
	b, err := BuildIndex(raw)
	if err != nil {
		return 0, err
	}
	return len(b), writeFileSync(IndexPath(dayDir, device, hour), b, 0o400)
}

// SaveIndex stores an index built with BuildIndex.
func SaveIndex(dayDir, device, hour string, b []byte) error {
	return writeFileSync(IndexPath(dayDir, device, hour), b, 0o400)
}

// ReadIndex loads the index of one hour; an error means "no usable index".
func ReadIndex(dayDir string, e HourEntry) (*Index, error) {
	if !ValidDevice(e.Device) || !ValidHour(e.Hour) {
		return nil, errors.New("invalid entry")
	}
	f, err := os.OpenInRoot(dayDir, filepath.Join(e.Device, e.Hour+IndexExt))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<20))
	if err != nil {
		return nil, err
	}
	return ParseIndex(b)
}

// MatchWords reports whether line contains the words of q (both lowercase)
// one after another, ignoring the separators between them: the "whole word"
// search mode. So action=accept finds action="accept" and action=accept,
// but not action=accepted.
func MatchWords(lineLower, qLower []byte) bool {
	return NewWordQuery(qLower).Match(lineLower)
}

// WordQuery is a compiled whole-word query; it is not safe for concurrent use.
type WordQuery struct {
	words [][]byte
	q     []byte
	toks  [][2]int
}

// NewWordQuery splits a lowercase query into words.
func NewWordQuery(qLower []byte) *WordQuery {
	wq := &WordQuery{q: qLower}
	for i := 0; i < len(qLower); {
		for i < len(qLower) && isSep(qLower[i]) {
			i++
		}
		j := i
		for j < len(qLower) && !isSep(qLower[j]) {
			j++
		}
		if j > i {
			wq.words = append(wq.words, qLower[i:j])
		}
		i = j
	}
	return wq
}

// Match reports whether the lowercase line matches.
func (wq *WordQuery) Match(lineLower []byte) bool {
	if len(wq.words) == 0 {
		return len(wq.q) > 0 && bytes.Contains(lineLower, wq.q)
	}
	if !bytes.Contains(lineLower, wq.words[0]) {
		return false
	}
	wq.toks = wq.toks[:0]
	for i := 0; i < len(lineLower); {
		for i < len(lineLower) && isSep(lineLower[i]) {
			i++
		}
		j := i
		for j < len(lineLower) && !isSep(lineLower[j]) {
			j++
		}
		if j > i {
			wq.toks = append(wq.toks, [2]int{i, j})
		}
		i = j
	}
	n := len(wq.words)
	for s := 0; s+n <= len(wq.toks); s++ {
		ok := true
		for k := 0; k < n; k++ {
			t := wq.toks[s+k]
			if !bytes.Equal(lineLower[t[0]:t[1]], wq.words[k]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
