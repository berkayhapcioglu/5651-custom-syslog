package colz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Codec ids stored in containers. Never renumber.
const (
	IDZstd byte = 1
	IDXZ   byte = 2
)

// maxStream bounds a single decompressed stream (decompression-bomb guard).
// Chunks hold at most ChunkSize plus one message, so 256 MiB is ample.
const maxStream = 256 << 20

// Zstd uses the built-in encoder at its strongest level.
type Zstd struct{}

func (Zstd) Name() string { return "zstd" }
func (Zstd) ID() byte     { return IDZstd }

func (Zstd) Compress(dst io.Writer, src []byte) error {
	e, err := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithWindowSize(1<<27), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	if _, err := e.Write(src); err != nil {
		e.Close()
		return err
	}
	return e.Close()
}

func (Zstd) Decompress(src []byte, rawLen int) ([]byte, error) {
	if rawLen > maxStream {
		return nil, ErrFormat
	}
	d, err := zstd.NewReader(bytes.NewReader(src), zstd.WithDecoderMaxMemory(uint64(rawLen)+1<<20), zstd.WithDecoderConcurrency(1)) // #nosec G115 -- rawLen checked against maxStream above
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return readExact(d, rawLen)
}

// XZ compresses with xz. When Command is set (e.g. "xz") the external binary
// is run with -9e, which compresses better than the built-in encoder;
// decompression always uses the built-in decoder.
type XZ struct {
	Command string
	Timeout time.Duration
}

func (XZ) Name() string { return "xz" }
func (XZ) ID() byte     { return IDXZ }

func (x XZ) Compress(dst io.Writer, src []byte) error {
	if x.Command != "" {
		t := x.Timeout
		if t == 0 {
			t = 30 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), t)
		defer cancel()
		// #nosec G204 -- binary path comes from the operator's config, args are fixed
		cmd := exec.CommandContext(ctx, x.Command, "-9e", "-T1", "-c", "-q")
		cmd.Stdin = bytes.NewReader(src)
		cmd.Stdout = dst
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("xz: %w: %s", err, stderr.String())
		}
		return nil
	}
	cfg := xz.WriterConfig{DictCap: 64 << 20, CheckSum: xz.SHA256}
	w, err := cfg.NewWriter(dst)
	if err != nil {
		return err
	}
	if _, err := w.Write(src); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func (XZ) Decompress(src []byte, rawLen int) ([]byte, error) {
	if rawLen > maxStream {
		return nil, ErrFormat
	}
	r, err := xz.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	return readExact(r, rawLen)
}

// readExact reads exactly n bytes and fails if the stream holds more.
func readExact(r io.Reader, n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	var one [1]byte
	if m, _ := r.Read(one[:]); m != 0 {
		return nil, ErrFormat
	}
	return out, nil
}

// Codecs returns all decoders by id.
func Codecs() map[byte]Codec {
	return map[byte]Codec{IDZstd: Zstd{}, IDXZ: XZ{}}
}
