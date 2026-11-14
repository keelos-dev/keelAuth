// Package qr makes QR codes (ISO/IEC 18004, byte mode, error correction level M, versions
// 1 to 15: up to 412 bytes) and draws them as SVG. Standard library only; the phone module
// shows them on the login page and for enrolling a phone.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// versions: per version (1-based) the total codewords, the error-correction codewords per
// block, and the blocks at level M: g1 blocks of g1n data codewords, g2 blocks of g2n.
type versionInfo struct {
	total, ec, g1, g1n, g2, g2n int
	align                       []int // alignment pattern centres
}

var versions = [...]versionInfo{
	{26, 10, 1, 16, 0, 0, nil},
	{44, 16, 1, 28, 0, 0, []int{6, 18}},
	{70, 26, 1, 44, 0, 0, []int{6, 22}},
	{100, 18, 2, 32, 0, 0, []int{6, 26}},
	{134, 24, 2, 43, 0, 0, []int{6, 30}},
	{172, 16, 4, 27, 0, 0, []int{6, 34}},
	{196, 18, 4, 31, 0, 0, []int{6, 22, 38}},
	{242, 22, 2, 38, 2, 39, []int{6, 24, 42}},
	{292, 22, 3, 36, 2, 37, []int{6, 26, 46}},
	{346, 26, 4, 43, 1, 44, []int{6, 28, 50}},
	{404, 30, 1, 50, 4, 51, []int{6, 30, 54}},
	{466, 22, 6, 36, 2, 37, []int{6, 32, 58}},
	{532, 22, 8, 37, 1, 38, []int{6, 34, 62}},
	{581, 24, 4, 40, 5, 41, []int{6, 26, 46, 66}},
	{655, 24, 5, 41, 5, 42, []int{6, 26, 48, 70}},
}

func (v versionInfo) data() int { return v.g1*v.g1n + v.g2*v.g2n }

// forceMask: tests pick the mask (-1: the best by penalty).
var forceMask = -1

// Code is a finished symbol: Size modules a side, Dark[y][x].
type Code struct {
	Size int
	Dark [][]bool
}

// Encode makes the smallest symbol (level M) that holds the text as bytes.
func Encode(text string) (*Code, error) {
	data := []byte(text)
	vi := -1
	for i, v := range versions {
		head := 4 + 8
		if i+1 >= 10 {
			head = 4 + 16
		}
		if (head+8*len(data)+7)/8 <= v.data() {
			vi = i
			break
		}
	}
	if vi < 0 {
		return nil, errors.New("qr: text too long")
	}
	v := versions[vi]
	ver := vi + 1
	// the bit stream: mode, count, bytes, terminator, pad
	var bits bitWriter
	bits.write(0b0100, 4)
	if ver >= 10 {
		bits.write(len(data), 16)
	} else {
		bits.write(len(data), 8)
	}
	for _, b := range data {
		bits.write(int(b), 8)
	}
	cap := v.data() * 8
	term := min(4, cap-bits.n)
	bits.write(0, term)
	for bits.n%8 != 0 {
		bits.write(0, 1)
	}
	for i := 0; bits.n < cap; i++ {
		if i%2 == 0 {
			bits.write(0xEC, 8)
		} else {
			bits.write(0x11, 8)
		}
	}
	cw := bits.bytes()
	// blocks, error correction, interleaving
	var blocks [][]byte
	pos := 0
	for i := 0; i < v.g1; i++ {
		blocks = append(blocks, cw[pos:pos+v.g1n])
		pos += v.g1n
	}
	for i := 0; i < v.g2; i++ {
		blocks = append(blocks, cw[pos:pos+v.g2n])
		pos += v.g2n
	}
	gen := rsGenerator(v.ec)
	var ecs [][]byte
	for _, b := range blocks {
		ecs = append(ecs, rsRemainder(b, gen))
	}
	var out []byte
	maxData := max(v.g1n, v.g2n)
	for i := 0; i < maxData; i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < v.ec; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	if len(out) != v.total {
		return nil, fmt.Errorf("qr: %d codewords, want %d", len(out), v.total)
	}
	// the matrix
	size := 17 + 4*ver
	m := newMatrix(size)
	m.functionPatterns(ver, v.align)
	m.placeData(out)
	best, bestScore := 0, int(^uint(0)>>1)
	for mask := 0; mask < 8 && forceMask < 0; mask++ {
		m.applyMask(mask)
		m.formatBits(mask)
		if sc := m.penalty(); sc < bestScore {
			best, bestScore = mask, sc
		}
		m.applyMask(mask) // undo (xor)
	}
	if forceMask >= 0 { // tests
		best = forceMask
	}
	m.applyMask(best)
	m.formatBits(best)
	return &Code{Size: size, Dark: m.dark}, nil
}

// SVG draws the symbol with a 4-module quiet zone, scale px per module.
func (c *Code) SVG(scale int) string {
	q := 4
	w := (c.Size + 2*q) * scale
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, w, w, w, w, w, w)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Dark[y][x] {
				fmt.Fprintf(&b, "M%d %dh%dv%dh-%dz", (x+q)*scale, (y+q)*scale, scale, scale, scale)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// ---- bits ----

type bitWriter struct {
	buf []byte
	n   int
}

func (w *bitWriter) write(v, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.buf = append(w.buf, 0)
		}
		if v>>uint(i)&1 == 1 {
			w.buf[w.n/8] |= 0x80 >> uint(w.n%8)
		}
		w.n++
	}
}

func (w *bitWriter) bytes() []byte { return w.buf }

// ---- Reed-Solomon over GF(256), polynomial 0x11D ----

var gfExp, gfLog [256]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	gfExp[255] = gfExp[0]
}

func gfMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(gfLog[a]+gfLog[b])%255]
}

func rsGenerator(n int) []int {
	g := []int{1}
	for i := 0; i < n; i++ {
		ng := make([]int, len(g)+1)
		for j, c := range g {
			ng[j] ^= c
			ng[j+1] ^= gfMul(c, gfExp[i])
		}
		g = ng
	}
	return g
}

func rsRemainder(data []byte, gen []int) []byte {
	n := len(gen) - 1
	rem := make([]int, n)
	for _, d := range data {
		f := int(d) ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for j := 0; j < n; j++ {
			rem[j] ^= gfMul(gen[j+1], f)
		}
	}
	out := make([]byte, n)
	for i, r := range rem {
		out[i] = byte(r)
	}
	return out
}

// ---- the matrix ----

type matrix struct {
	size int
	dark [][]bool
	fn   [][]bool // function pattern (not data, not masked)
}

func newMatrix(size int) *matrix {
	m := &matrix{size: size}
	m.dark = make([][]bool, size)
	m.fn = make([][]bool, size)
	for i := range m.dark {
		m.dark[i] = make([]bool, size)
		m.fn[i] = make([]bool, size)
	}
	return m
}

func (m *matrix) set(x, y int, d bool) {
	if x >= 0 && y >= 0 && x < m.size && y < m.size {
		m.dark[y][x] = d
		m.fn[y][x] = true
	}
}

func (m *matrix) finder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			d := max(abs(dx), abs(dy))
			m.set(cx+dx, cy+dy, d != 4 && d != 2)
		}
	}
}

func (m *matrix) functionPatterns(ver int, align []int) {
	m.finder(3, 3)
	m.finder(m.size-4, 3)
	m.finder(3, m.size-4)
	for i := 8; i < m.size-8; i++ { // timing
		m.set(i, 6, i%2 == 0)
		m.set(6, i, i%2 == 0)
	}
	n := len(align)
	for i, cy := range align {
		for j, cx := range align {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					d := max(abs(dx), abs(dy))
					m.set(cx+dx, cy+dy, d != 1)
				}
			}
		}
	}
	// format areas (filled later) and the dark module
	for i := 0; i < 8; i++ {
		if i != 6 { // (6,8) and (8,6) are timing modules
			m.set(i, 8, false)
			m.set(8, i, false)
		}
		m.set(m.size-1-i, 8, false)
		m.set(8, m.size-1-i, false)
	}
	m.set(8, 8, false)
	m.set(8, m.size-8, true)
	if ver >= 7 {
		bits := ver << 12
		rem := bits
		for i := 17; i >= 12; i-- {
			if rem>>uint(i)&1 == 1 {
				rem ^= 0x1F25 << uint(i-12)
			}
		}
		bits |= rem
		for i := 0; i < 18; i++ {
			d := bits>>uint(i)&1 == 1
			m.set(i/3, m.size-11+i%3, d)
			m.set(m.size-11+i%3, i/3, d)
		}
	}
}

func (m *matrix) placeData(cw []byte) {
	bit := 0
	total := len(cw) * 8
	up := true
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for i := 0; i < m.size; i++ {
			y := i
			if up {
				y = m.size - 1 - i
			}
			for _, x := range []int{right, right - 1} {
				if m.fn[y][x] {
					continue
				}
				d := false
				if bit < total {
					d = cw[bit/8]>>uint(7-bit%8)&1 == 1
				}
				m.dark[y][x] = d
				bit++
			}
		}
		up = !up
	}
}

func maskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	}
	return ((x+y)%2+x*y%3)%2 == 0
}

func (m *matrix) applyMask(mask int) {
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if !m.fn[y][x] && maskBit(mask, x, y) {
				m.dark[y][x] = !m.dark[y][x]
			}
		}
	}
}

// formatBits writes the format information (level M = 00, mask) in both places.
func (m *matrix) formatBits(mask int) {
	data := mask // level M bits are 00
	bits := data << 10
	for i := 14; i >= 10; i-- {
		if bits>>uint(i)&1 == 1 {
			bits ^= 0x537 << uint(i-10)
		}
	}
	bits = (data<<10 | bits) ^ 0x5412
	for i := 0; i < 15; i++ { // i: position; the most significant bit first
		d := bits>>uint(14-i)&1 == 1
		// around the top-left finder
		switch {
		case i < 6:
			m.dark[8][i] = d
		case i < 8:
			m.dark[8][i+1] = d
		case i == 8:
			m.dark[7][8] = d
		default:
			m.dark[14-i][8] = d
		}
		// the other two
		if i < 7 {
			m.dark[m.size-1-i][8] = d
		} else {
			m.dark[8][m.size-15+i] = d
		}
	}
}

func (m *matrix) penalty() int {
	n := m.size
	score := 0
	// rule 1: runs of 5+ same colour in rows and columns
	for i := 0; i < n; i++ {
		for _, col := range []bool{false, true} {
			run, last := 0, false
			for j := 0; j < n; j++ {
				var d bool
				if col {
					d = m.dark[j][i]
				} else {
					d = m.dark[i][j]
				}
				if j > 0 && d == last {
					run++
				} else {
					if run >= 5 {
						score += run - 2
					}
					run = 1
				}
				last = d
			}
			if run >= 5 {
				score += run - 2
			}
		}
	}
	// rule 2: 2x2 blocks
	for y := 0; y < n-1; y++ {
		for x := 0; x < n-1; x++ {
			d := m.dark[y][x]
			if m.dark[y][x+1] == d && m.dark[y+1][x] == d && m.dark[y+1][x+1] == d {
				score += 3
			}
		}
	}
	// rule 3: finder-like 1011101 with 4 light on a side
	pat := []bool{true, false, true, true, true, false, true}
	for i := 0; i < n; i++ {
		for j := 0; j+7 <= n; j++ {
			for _, col := range []bool{false, true} {
				at := func(k int) bool {
					if k < 0 || k >= n {
						return false
					}
					if col {
						return m.dark[k][i]
					}
					return m.dark[i][k]
				}
				ok := true
				for k, p := range pat {
					if at(j+k) != p {
						ok = false
						break
					}
				}
				if !ok {
					continue
				}
				light := func(from int) bool {
					for k := from; k < from+4; k++ {
						if k >= 0 && k < n && at(k) {
							return false
						}
					}
					return true
				}
				if light(j-4) || light(j+7) {
					score += 40
				}
			}
		}
	}
	// rule 4: dark proportion
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if m.dark[y][x] {
				dark++
			}
		}
	}
	pct := dark * 100 / (n * n)
	k := abs(pct-50) / 5
	score += k * 10
	return score
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
