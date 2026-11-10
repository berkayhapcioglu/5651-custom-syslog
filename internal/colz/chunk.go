package colz

import (
	"bufio"
	"bytes"
	"io"
)

// ChunkSize bounds how much raw data one container holds, which bounds memory.
var ChunkSize = 128 << 20

// EncodeStream reads newline-terminated records from r and writes one
// container per chunk. Chunks are cut at line boundaries.
func EncodeStream(w io.Writer, r io.Reader, c Codec, plain bool) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var chunk bytes.Buffer
	flush := func() error {
		if chunk.Len() == 0 {
			return nil
		}
		var err error
		if plain {
			err = EncodePlain(w, chunk.Bytes(), c)
		} else {
			err = Encode(w, chunk.Bytes(), c)
		}
		chunk.Reset()
		return err
	}
	for {
		line, err := br.ReadSlice('\n')
		chunk.Write(line)
		if err == bufio.ErrBufferFull {
			continue // very long line: keep reading it into the chunk
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if chunk.Len() >= ChunkSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}
