// Package colz implements the lossless columnar log container used for
// sealed hourly files.
//
// Firewall logs are mostly key=value pairs whose keys repeat on every line.
// colz splits each line into a template (the sequence of keys) and columns
// (all values of one key, in line order). Each column is then compressed on
// its own, so the compressor sees long runs of similar values (all source IPs
// together, all ports together) instead of interleaved text. Monotonic
// integer columns (receive time, eventtime) are stored as varint deltas.
//
// The transform is exactly reversible: Decode(Encode(x)) == x byte for byte.
// The sealer still decodes every file after encoding and compares SHA-256
// before deleting the raw file, and falls back to whole-file compression if
// the round trip ever differs.
package colz

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	magic        = "S5651C\x01"
	maxTemplates = 4096
	maxColumns   = 1024
	maxTokens    = 256
	timeLayout   = "2006-01-02T15:04:05.000000000Z07:00"

	colText     = 0
	colIntDelta = 1

	// Layout kinds stored in the container header.
	kindColumnar = 1
	kindPlain    = 2

	fallbackTemplate = 0 // template id 0 = line kept as one literal
)

// Codec compresses and decompresses a single stream.
type Codec interface {
	Name() string
	ID() byte
	Compress(dst io.Writer, src []byte) error
	Decompress(src []byte, rawLen int) ([]byte, error)
}

// ErrFormat is returned for malformed containers.
var ErrFormat = errors.New("colz: malformed container")

// Encode transforms raw (newline-terminated lines of the form
// "<RFC3339 UTC nanos>\t<source>\t<message>") into a compressed container.
// If the input does not have that shape it is stored as one plain stream.
func Encode(w io.Writer, raw []byte, c Codec) error {
	streams, err := split(raw)
	kind := byte(kindColumnar)
	if err != nil {
		streams = [][]byte{raw}
		kind = kindPlain
	}
	return writeContainer(w, kind, streams, c)
}

// EncodePlain stores raw as one compressed stream without the transform.
func EncodePlain(w io.Writer, raw []byte, c Codec) error {
	return writeContainer(w, kindPlain, [][]byte{raw}, c)
}

// Decode restores the original bytes from one or more concatenated containers.
func Decode(data []byte, codecs map[byte]Codec) ([]byte, error) {
	var out bytes.Buffer
	if err := DecodeTo(&out, data, codecs); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DecodeTo writes the decoded bytes to w one container at a time, so memory
// is bounded by the chunk size rather than the file size.
func DecodeTo(w io.Writer, data []byte, codecs map[byte]Codec) error {
	r := bytes.NewReader(data)
	for first := true; first || r.Len() > 0; first = false {
		b, err := decodeOne(r, int64(r.Len()), codecs)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// DecodeReader is DecodeTo for a stream: it decodes one container (one chunk
// of at most ChunkSize raw bytes) at a time, so memory stays bounded however
// large the sealed file is.
func DecodeReader(w io.Writer, r io.Reader, codecs map[byte]Codec) error {
	br := bufio.NewReaderSize(r, 1<<20)
	for first := true; ; first = false {
		if !first {
			if _, err := br.Peek(1); err == io.EOF {
				return nil
			}
		}
		b, err := decodeOne(br, maxStream+1<<20, codecs)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
}

type byteReader interface {
	io.Reader
	io.ByteReader
}

// decodeOne reads one container; maxComp bounds a compressed stream.
func decodeOne(r byteReader, maxComp int64, codecs map[byte]Codec) ([]byte, error) {
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(r, head); err != nil || string(head) != magic {
		return nil, ErrFormat
	}
	kind, err := r.ReadByte()
	if err != nil {
		return nil, ErrFormat
	}
	cid, err := r.ReadByte()
	if err != nil {
		return nil, ErrFormat
	}
	c, ok := codecs[cid]
	if !ok {
		return nil, fmt.Errorf("colz: unknown codec id %d", cid)
	}
	n, err := binary.ReadUvarint(r)
	if err != nil || n > maxColumns+8 {
		return nil, ErrFormat
	}
	streams := make([][]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		rawLen, err1 := binary.ReadUvarint(r)
		compLen, err2 := binary.ReadUvarint(r)
		if err1 != nil || err2 != nil || compLen > uint64(maxComp) || rawLen > maxStream { // #nosec G115 -- lengths and counts are non-negative and bounded
			return nil, ErrFormat
		}
		comp := make([]byte, compLen)
		if _, err := io.ReadFull(r, comp); err != nil {
			return nil, ErrFormat
		}
		s, err := c.Decompress(comp, int(rawLen))
		if err != nil {
			return nil, fmt.Errorf("colz: stream %d: %w", i, err)
		}
		if len(s) != int(rawLen) {
			return nil, ErrFormat
		}
		streams = append(streams, s)
	}
	switch kind {
	case kindPlain:
		if len(streams) != 1 {
			return nil, ErrFormat
		}
		return streams[0], nil
	case kindColumnar:
		return join(streams)
	}
	return nil, ErrFormat
}

func writeContainer(w io.Writer, kind byte, streams [][]byte, c Codec) error {
	bw := bufio.NewWriter(w)
	bw.WriteString(magic)
	bw.WriteByte(kind)
	bw.WriteByte(c.ID())
	putUvarint(bw, uint64(len(streams)))
	var buf bytes.Buffer
	for _, s := range streams {
		buf.Reset()
		if err := c.Compress(&buf, s); err != nil {
			return err
		}
		putUvarint(bw, uint64(len(s)))
		putUvarint(bw, uint64(buf.Len())) // #nosec G115 -- lengths and counts are non-negative and bounded
		bw.Write(buf.Bytes())
	}
	return bw.Flush()
}

func putUvarint(w *bufio.Writer, v uint64) {
	var b [binary.MaxVarintLen64]byte
	w.Write(b[:binary.PutUvarint(b[:], v)])
}

// column is one value stream.
type column struct {
	name   []byte
	keyed  bool
	values [][]byte
}

type template []int // column index per token

// split builds the logical streams:
//
//	0 meta      line count, column table, templates
//	1 tids      template id per line (uvarint)
//	2 times     receive time, zigzag varint delta of unix nanos
//	3 sources   source column, newline separated
//	4 pri       syslog <PRI> digits or empty, newline separated
//	5 fallback  messages kept whole, newline separated
//	6..         one stream per column
func split(raw []byte) ([][]byte, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("colz: input must end with a newline")
	}
	var (
		cols      []*column
		colIndex  = map[string]int{}
		templates = []template{nil} // id 0 = fallback
		tplIndex  = map[string]int{}
		tids      bytes.Buffer
		times     bytes.Buffer
		sources   bytes.Buffer
		pri       bytes.Buffer
		fallback  bytes.Buffer
		lines     uint64
		lastNano  int64
		vb        [binary.MaxVarintLen64]byte
		tplKey    []byte
		toks      [][]byte
		tpl       template
	)
	getCol := func(name []byte, keyed bool) (int, bool) {
		k := string(name)
		if !keyed {
			k = "\x00" + k
		}
		if i, ok := colIndex[k]; ok {
			return i, true
		}
		if len(cols) >= maxColumns {
			return 0, false
		}
		cols = append(cols, &column{name: append([]byte(nil), name...), keyed: keyed})
		colIndex[k] = len(cols) - 1
		return len(cols) - 1, true
	}

	for len(raw) > 0 {
		nl := bytes.IndexByte(raw, '\n')
		line := raw[:nl]
		raw = raw[nl+1:]
		lines++

		t1 := bytes.IndexByte(line, '\t')
		if t1 < 0 {
			return nil, errors.New("colz: missing time field")
		}
		t2 := bytes.IndexByte(line[t1+1:], '\t')
		if t2 < 0 {
			return nil, errors.New("colz: missing source field")
		}
		t2 += t1 + 1
		ts, err := time.Parse(time.RFC3339Nano, string(line[:t1]))
		n := ts.UnixNano()
		// The decoder rebuilds the field from unix nanos, so it must survive
		// that trip exactly (this also rejects years outside 1678-2262).
		if err != nil || time.Unix(0, n).UTC().Format(timeLayout) != string(line[:t1]) {
			return nil, errors.New("colz: time field is not canonical")
		}
		times.Write(vb[:binary.PutVarint(vb[:], n-lastNano)])
		lastNano = n
		sources.Write(line[t1+1 : t2])
		sources.WriteByte('\n')

		msg := line[t2+1:]
		if p := priLen(msg); p > 0 {
			pri.Write(msg[1 : p-1])
			msg = msg[p:]
		}
		pri.WriteByte('\n')

		toks = splitSpaces(toks[:0], msg)
		ok := len(toks) <= maxTokens
		tpl = tpl[:0]
		tplKey = tplKey[:0]
		if ok {
			for i, tok := range toks {
				var ci int
				if k := keyLen(tok); k > 0 {
					ci, ok = getCol(tok[:k], true)
				} else {
					ci, ok = getCol([]byte(fmt.Sprintf("%d", i)), false)
				}
				if !ok {
					break
				}
				tpl = append(tpl, ci)
				tplKey = binary.AppendUvarint(tplKey, uint64(ci)) // #nosec G115 -- lengths and counts are non-negative and bounded
			}
		}
		tid := fallbackTemplate
		if ok {
			id, seen := tplIndex[string(tplKey)]
			if !seen && len(templates) < maxTemplates {
				id = len(templates)
				templates = append(templates, append(template(nil), tpl...))
				tplIndex[string(tplKey)] = id
				seen = true
			}
			if seen {
				tid = id
			}
		}
		tids.Write(vb[:binary.PutUvarint(vb[:], uint64(tid))])
		if tid == fallbackTemplate {
			fallback.Write(msg)
			fallback.WriteByte('\n')
			continue
		}
		for i, tok := range toks {
			c := cols[tpl[i]]
			if c.keyed {
				tok = tok[len(c.name)+1:]
			}
			c.values = append(c.values, tok)
		}
	}

	var meta bytes.Buffer
	meta.Write(binary.AppendUvarint(nil, lines))
	meta.Write(binary.AppendUvarint(nil, uint64(len(cols))))
	for _, c := range cols {
		meta.Write(binary.AppendUvarint(nil, uint64(len(c.name))))
		meta.Write(c.name)
		if c.keyed {
			meta.WriteByte(1)
		} else {
			meta.WriteByte(0)
		}
	}
	meta.Write(binary.AppendUvarint(nil, uint64(len(templates))))
	for _, t := range templates {
		meta.Write(binary.AppendUvarint(nil, uint64(len(t))))
		for _, ci := range t {
			meta.Write(binary.AppendUvarint(nil, uint64(ci))) // #nosec G115 -- lengths and counts are non-negative and bounded
		}
	}

	streams := [][]byte{meta.Bytes(), tids.Bytes(), times.Bytes(), sources.Bytes(), pri.Bytes(), fallback.Bytes()}
	for _, c := range cols {
		streams = append(streams, encodeColumn(c.values))
	}
	return streams, nil
}

// encodeColumn stores mostly increasing integer columns as varint deltas and
// everything else as newline separated text.
func encodeColumn(vals [][]byte) []byte {
	if ints, ok := monotonicInts(vals); ok {
		out := []byte{colIntDelta}
		var last int64
		for _, v := range ints {
			out = binary.AppendVarint(out, v-last)
			last = v
		}
		return out
	}
	n := 1
	for _, v := range vals {
		n += len(v) + 1
	}
	out := make([]byte, 0, n)
	out = append(out, colText)
	for _, v := range vals {
		out = append(out, v...)
		out = append(out, '\n')
	}
	return out
}

func monotonicInts(vals [][]byte) ([]int64, bool) {
	if len(vals) < 16 {
		return nil, false
	}
	ints := make([]int64, len(vals))
	up := 0
	for i, v := range vals {
		x, ok := canonicalInt(v)
		if !ok {
			return nil, false
		}
		ints[i] = x
		if i > 0 && x >= ints[i-1] {
			up++
		}
	}
	return ints, up*10 >= (len(vals)-1)*9
}

// canonicalInt accepts only forms that format back identically.
func canonicalInt(v []byte) (int64, bool) {
	if len(v) == 0 || len(v) > 18 || (v[0] == '0' && len(v) > 1) {
		return 0, false
	}
	var x int64
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		x = x*10 + int64(ch-'0')
	}
	return x, true
}

func priLen(msg []byte) int {
	if len(msg) < 3 || msg[0] != '<' {
		return 0
	}
	for i := 1; i < len(msg) && i <= 4; i++ {
		if msg[i] == '>' {
			if i == 1 {
				return 0
			}
			return i + 1
		}
		if msg[i] < '0' || msg[i] > '9' {
			return 0
		}
	}
	return 0
}

func splitSpaces(dst [][]byte, b []byte) [][]byte {
	for {
		i := bytes.IndexByte(b, ' ')
		if i < 0 {
			return append(dst, b)
		}
		dst = append(dst, b[:i])
		b = b[i+1:]
	}
}

// keyLen returns the length of a key=value key, or 0 when tok is not one.
func keyLen(tok []byte) int {
	for i, ch := range tok {
		if ch == '=' {
			if i == 0 {
				return 0
			}
			return i
		}
		if i >= 64 || !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
			return 0
		}
	}
	return 0
}

// reader walks a newline separated text stream.
type textReader struct{ b []byte }

func (t *textReader) next() ([]byte, error) {
	i := bytes.IndexByte(t.b, '\n')
	if i < 0 {
		return nil, ErrFormat
	}
	v := t.b[:i]
	t.b = t.b[i+1:]
	return v, nil
}

type colReader struct {
	text  *textReader
	ints  *bytes.Reader
	last  int64
	isInt bool
}

func (c *colReader) next(dst []byte) ([]byte, error) {
	if !c.isInt {
		v, err := c.text.next()
		return append(dst, v...), err
	}
	d, err := binary.ReadVarint(c.ints)
	if err != nil {
		return nil, ErrFormat
	}
	c.last += d
	return fmt.Appendf(dst, "%d", c.last), nil
}

func join(streams [][]byte) ([]byte, error) {
	if len(streams) < 6 {
		return nil, ErrFormat
	}
	meta := bytes.NewReader(streams[0])
	lines, err := binary.ReadUvarint(meta)
	if err != nil {
		return nil, ErrFormat
	}
	ncol, err := binary.ReadUvarint(meta)
	if err != nil || ncol > maxColumns || int(ncol) != len(streams)-6 {
		return nil, ErrFormat
	}
	type colDef struct {
		name  []byte
		keyed bool
	}
	defs := make([]colDef, ncol)
	readers := make([]*colReader, ncol)
	for i := range defs {
		l, err := binary.ReadUvarint(meta)
		if err != nil || l > 1<<16 || l > uint64(meta.Len()) { // #nosec G115 -- lengths and counts are non-negative and bounded
			return nil, ErrFormat
		}
		name := make([]byte, l)
		io.ReadFull(meta, name)
		k, err := meta.ReadByte()
		if err != nil {
			return nil, ErrFormat
		}
		defs[i] = colDef{name, k == 1}
		s := streams[6+i]
		if len(s) == 0 {
			return nil, ErrFormat
		}
		switch s[0] {
		case colText:
			readers[i] = &colReader{text: &textReader{s[1:]}}
		case colIntDelta:
			readers[i] = &colReader{ints: bytes.NewReader(s[1:]), isInt: true}
		default:
			return nil, ErrFormat
		}
	}
	ntpl, err := binary.ReadUvarint(meta)
	if err != nil || ntpl > maxTemplates || ntpl == 0 {
		return nil, ErrFormat
	}
	templates := make([]template, ntpl)
	for i := range templates {
		l, err := binary.ReadUvarint(meta)
		if err != nil || l > maxTokens {
			return nil, ErrFormat
		}
		t := make(template, l)
		for j := range t {
			ci, err := binary.ReadUvarint(meta)
			if err != nil || ci >= ncol {
				return nil, ErrFormat
			}
			t[j] = int(ci) // #nosec G115 -- lengths and counts are non-negative and bounded
		}
		templates[i] = t
	}

	tids := bytes.NewReader(streams[1])
	times := bytes.NewReader(streams[2])
	sources := &textReader{streams[3]}
	pris := &textReader{streams[4]}
	fallback := &textReader{streams[5]}

	var out bytes.Buffer
	var last int64
	for l := uint64(0); l < lines; l++ {
		d, err := binary.ReadVarint(times)
		if err != nil {
			return nil, ErrFormat
		}
		last += d
		out.WriteString(time.Unix(0, last).UTC().Format(timeLayout))
		out.WriteByte('\t')
		src, err := sources.next()
		if err != nil {
			return nil, err
		}
		out.Write(src)
		out.WriteByte('\t')
		p, err := pris.next()
		if err != nil {
			return nil, err
		}
		if len(p) > 0 {
			out.WriteByte('<')
			out.Write(p)
			out.WriteByte('>')
		}
		tid, err := binary.ReadUvarint(tids)
		if err != nil || tid >= ntpl {
			return nil, ErrFormat
		}
		if tid == fallbackTemplate {
			v, err := fallback.next()
			if err != nil {
				return nil, err
			}
			out.Write(v)
			out.WriteByte('\n')
			continue
		}
		var tok []byte
		for i, ci := range templates[tid] {
			if i > 0 {
				out.WriteByte(' ')
			}
			if defs[ci].keyed {
				out.Write(defs[ci].name)
				out.WriteByte('=')
			}
			tok, err = readers[ci].next(tok[:0])
			if err != nil {
				return nil, err
			}
			out.Write(tok)
		}
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}
