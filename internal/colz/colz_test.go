package colz

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"
)

func sample(n int) []byte {
	r := rand.New(rand.NewSource(1))
	var b bytes.Buffer
	t := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(r.Intn(50)) * time.Millisecond)
		fmt.Fprintf(&b, "%s\t10.0.0.%d\t<189>date=%s time=%s devname=\"FGT60F\" type=\"traffic\" eventtime=%d srcip=192.168.1.%d srcport=%d dstport=443 action=\"accept\" sentbyte=%d\n",
			t.Format(timeLayout), r.Intn(3)+1, t.Format("2006-01-02"), t.Format("15:04:05"), t.UnixNano(), r.Intn(250), 1024+r.Intn(60000), r.Intn(99999))
		if i%97 == 0 {
			fmt.Fprintf(&b, "%s\t10.0.0.1\tfree text line with  double  space and = sign =x a=\n", t.Format(timeLayout))
		}
	}
	return b.Bytes()
}

func roundTrip(t *testing.T, raw []byte, c Codec) int {
	t.Helper()
	var buf bytes.Buffer
	if err := Encode(&buf, raw, c); err != nil {
		t.Fatal(err)
	}
	codecs := Codecs()
	codecs[99] = storeCodec{}
	got, err := Decode(buf.Bytes(), codecs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("round trip mismatch (%d vs %d bytes)", len(got), len(raw))
	}
	return buf.Len()
}

func TestRoundTrip(t *testing.T) {
	raw := sample(5000)
	for _, c := range []Codec{Zstd{}, XZ{}} {
		n := roundTrip(t, raw, c)
		t.Logf("%s: %.1fx", c.Name(), float64(len(raw))/float64(n))
	}
}

func TestPlainFallback(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("not a record\n"),
		[]byte("2026-11-10T10:00:00Z\tx\tnot canonical time\n"),
		[]byte("no trailing newline"),
	} {
		roundTrip(t, raw, Zstd{})
	}
}

func TestEdgeLines(t *testing.T) {
	ts := "2026-11-10T10:00:00.000000000Z"
	raw := []byte(ts + "\t1.2.3.4\t\n" +
		ts + "\t1.2.3.4\t<>x\n" +
		ts + "\t1.2.3.4\t<13>\n" +
		ts + "\t1.2.3.4\t<1234>a=b\n" +
		ts + "\t1.2.3.4\t a=1  a=2 =3 b==4 \n" +
		ts + "\t\tk=007 k=7\n")
	roundTrip(t, raw, XZ{})
}

func TestRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte("S5651C\x01\x01\x01\xff\xff\xff"), Codecs()); err == nil {
		t.Fatal("expected error")
	}
}

// storeCodec copies bytes unchanged so fuzzing exercises the transform fast.
type storeCodec struct{}

func (storeCodec) Name() string { return "store" }
func (storeCodec) ID() byte     { return 99 }
func (storeCodec) Compress(dst io.Writer, src []byte) error {
	_, err := dst.Write(src)
	return err
}
func (storeCodec) Decompress(src []byte, n int) ([]byte, error) {
	if len(src) != n {
		return nil, ErrFormat
	}
	return append([]byte(nil), src...), nil
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("2026-11-10T10:00:00.000000000Z\t1.2.3.4\t<1>a=1 b c=\n"))
	f.Add(sample(40))
	codecs := map[byte]Codec{99: storeCodec{}}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var buf bytes.Buffer
		if err := Encode(&buf, raw, storeCodec{}); err != nil {
			return
		}
		got, err := Decode(buf.Bytes(), codecs)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("mismatch: %v", err)
		}
	})
}

// FuzzDecode feeds arbitrary bytes to the decoder: it must never panic.
func FuzzDecode(f *testing.F) {
	var buf bytes.Buffer
	Encode(&buf, sample(20), storeCodec{})
	f.Add(buf.Bytes())
	codecs := map[byte]Codec{99: storeCodec{}}
	f.Fuzz(func(t *testing.T, data []byte) {
		Decode(data, codecs)
	})
}

func TestDecodeReaderMatchesDecode(t *testing.T) {
	old := ChunkSize
	ChunkSize = 4 << 10
	defer func() { ChunkSize = old }()
	var raw bytes.Buffer
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&raw, "2026-11-09T07:00:%02d.000000000Z\t10.0.0.1\tsrcip=10.0.0.%d dstport=%d\n", i%60, i%250, 1000+i)
	}
	var enc bytes.Buffer
	if err := EncodeStream(&enc, bytes.NewReader(raw.Bytes()), Zstd{}, false); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := DecodeReader(&out, bytes.NewReader(enc.Bytes()), Codecs()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), raw.Bytes()) {
		t.Fatal("DecodeReader output differs")
	}
	if err := DecodeReader(io.Discard, bytes.NewReader(enc.Bytes()[:enc.Len()-3]), Codecs()); err == nil {
		t.Fatal("truncated input accepted")
	}
}
