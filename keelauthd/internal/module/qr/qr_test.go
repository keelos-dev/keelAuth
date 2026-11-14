package qr

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeSizes(t *testing.T) {
	for _, tc := range []struct {
		n, size int
	}{{1, 21}, {14, 21}, {15, 25}, {26, 25}, {42, 29}, {100, 41}, {150, 49}, {412, 77}} {
		c, err := Encode(strings.Repeat("a", tc.n))
		if err != nil {
			t.Fatalf("%d bytes: %v", tc.n, err)
		}
		if c.Size != tc.size {
			t.Errorf("%d bytes: size %d, want %d", tc.n, c.Size, tc.size)
		}
	}
	if _, err := Encode(strings.Repeat("a", 413)); err == nil {
		t.Error("413 bytes: no error")
	}
	c, _ := Encode("hello")
	if !strings.HasPrefix(c.SVG(4), "<svg") || !c.Dark[0][0] || !c.Dark[c.Size-8][8] {
		t.Error("svg or finder or dark module")
	}
}

// TestDecode reads the symbols back with zxing (a venv with zxing-cpp and pillow, its python
// in QR_PYTHON; default python3); skipped when it is not there.
func TestDecode(t *testing.T) {
	py := os.Getenv("QR_PYTHON")
	if py == "" {
		py = "python3"
	}
	if err := exec.Command(py, "-c", "import zxingcpp, PIL").Run(); err != nil {
		t.Skip("no zxingcpp")
	}
	dir := t.TempDir()
	texts := []string{"hello", "keelauth://login?o=https://192.0.2.10:8443&c=" + strings.Repeat("x", 43) + "&n=" + strings.Repeat("y", 43),
		strings.Repeat("0123456789", 20), strings.Repeat("Z", 412), "日本語 ünïcode"}
	for n := 20; n <= 412; n += 25 { // every version
		texts = append(texts, strings.Repeat("k", n))
	}
	for i, text := range texts {
		c, err := Encode(text)
		if err != nil {
			t.Fatal(err)
		}
		sc := 8
		img := image.NewGray(image.Rect(0, 0, (c.Size+8)*sc, (c.Size+8)*sc))
		for y := range img.Pix {
			img.Pix[y] = 255
		}
		for y := 0; y < c.Size; y++ {
			for x := 0; x < c.Size; x++ {
				if c.Dark[y][x] {
					for dy := 0; dy < sc; dy++ {
						for dx := 0; dx < sc; dx++ {
							img.Set((x+4)*sc+dx, (y+4)*sc+dy, color.Gray{0})
						}
					}
				}
			}
		}
		p := filepath.Join(dir, "q.png")
		f, _ := os.Create(p)
		png.Encode(f, img)
		f.Close()
		out, err := exec.Command(py, "-I", "-c", "import sys,zxingcpp,PIL.Image\nr=zxingcpp.read_barcode(PIL.Image.open(sys.argv[1]))\nprint(r.text if r else 'NONE', end='')", p).CombinedOutput()
		if err != nil || string(out) != text {
			t.Errorf("%d (%d bytes, size %d): decoded %q, err %v", i, len(text), c.Size, out, err)
		}
	}
}
