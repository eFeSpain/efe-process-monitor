// Command genicon renders the app icon (hexagon + risk-colored nodes) to a
// multi-size PNG-based .ico, with 4x supersampling for smooth edges.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

var (
	bg     = color.RGBA{0x0d, 0x11, 0x17, 0xff}
	border = color.RGBA{0x30, 0x36, 0x3d, 0xff}
	blue   = color.RGBA{0x58, 0xa6, 0xff, 0xff}
	green  = color.RGBA{0x3f, 0xb9, 0x50, 0xff}
	red    = color.RGBA{0xf8, 0x51, 0x49, 0xff}
)

func render(size int) *image.RGBA {
	ss := 4
	S := size * ss
	img := image.NewRGBA(image.Rect(0, 0, S, S))
	f := float64(S)
	rr := 0.22 * f // corner radius

	inRounded := func(x, y float64) bool {
		if x >= rr && x <= f-rr {
			return y >= 0 && y <= f
		}
		if y >= rr && y <= f-rr {
			return x >= 0 && x <= f
		}
		cx, cy := clamp(x, rr, f-rr), clamp(y, rr, f-rr)
		return math.Hypot(x-cx, y-cy) <= rr
	}
	for py := 0; py < S; py++ {
		for px := 0; px < S; px++ {
			x, y := float64(px)+0.5, float64(py)+0.5
			if !inRounded(x, y) {
				continue
			}
			if inRounded(x, y) && (x < 3 || y < 3 || x > f-3 || y > f-3) {
				img.Set(px, py, border)
			} else {
				img.Set(px, py, bg)
			}
		}
	}

	cx, cy := f/2, f/2
	R := 0.36 * f
	// hexagon vertices (pointy-top)
	var vx, vy [6]float64
	for i := 0; i < 6; i++ {
		a := math.Pi/2 + float64(i)*math.Pi/3
		vx[i], vy[i] = cx+R*math.Cos(a), cy-R*math.Sin(a)
	}
	for i := 0; i < 6; i++ {
		j := (i + 1) % 6
		drawLine(img, vx[i], vy[i], vx[j], vy[j], 0.045*f, blue)
	}
	// links + peripheral nodes
	type node struct {
		ax, ay float64
		c      color.RGBA
	}
	nodes := []node{
		{cx, cy - 0.30*f, green},
		{cx - 0.26*f, cy + 0.22*f, blue},
		{cx + 0.26*f, cy + 0.22*f, red},
	}
	for _, n := range nodes {
		drawLine(img, cx, cy, n.ax, n.ay, 0.03*f, n.c)
	}
	for _, n := range nodes {
		fillCircle(img, n.ax, n.ay, 0.06*f, n.c)
	}
	fillCircle(img, cx, cy, 0.09*f, blue)
	fillCircle(img, cx, cy, 0.035*f, bg)

	return downscale(img, ss)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func fillCircle(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	for py := int(cy - r); py <= int(cy+r); py++ {
		for px := int(cx - r); px <= int(cx+r); px++ {
			if math.Hypot(float64(px)+0.5-cx, float64(py)+0.5-cy) <= r {
				img.Set(px, py, c)
			}
		}
	}
}

func drawLine(img *image.RGBA, x0, y0, x1, y1, w float64, c color.RGBA) {
	minx, maxx := int(math.Min(x0, x1)-w), int(math.Max(x0, x1)+w)
	miny, maxy := int(math.Min(y0, y1)-w), int(math.Max(y0, y1)+w)
	hw := w / 2
	for py := miny; py <= maxy; py++ {
		for px := minx; px <= maxx; px++ {
			if distToSeg(float64(px)+0.5, float64(py)+0.5, x0, y0, x1, y1) <= hw {
				img.Set(px, py, c)
			}
		}
	}
}

func distToSeg(px, py, x0, y0, x1, y1 float64) float64 {
	dx, dy := x1-x0, y1-y0
	l2 := dx*dx + dy*dy
	if l2 == 0 {
		return math.Hypot(px-x0, py-y0)
	}
	t := clamp(((px-x0)*dx+(py-y0)*dy)/l2, 0, 1)
	return math.Hypot(px-(x0+t*dx), py-(y0+t*dy))
}

func downscale(src *image.RGBA, ss int) *image.RGBA {
	S := src.Bounds().Dx()
	d := S / ss
	out := image.NewRGBA(image.Rect(0, 0, d, d))
	for y := 0; y < d; y++ {
		for x := 0; x < d; x++ {
			var r, g, b, a int
			for dy := 0; dy < ss; dy++ {
				for dx := 0; dx < ss; dx++ {
					c := src.RGBAAt(x*ss+dx, y*ss+dy)
					r += int(c.R)
					g += int(c.G)
					b += int(c.B)
					a += int(c.A)
				}
			}
			n := ss * ss
			out.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(b / n), uint8(a / n)})
		}
	}
	return out
}

func main() {
	sizes := []int{256, 64, 48, 32, 16}
	var pngs [][]byte
	for _, s := range sizes {
		var buf bytes.Buffer
		png.Encode(&buf, render(s))
		pngs = append(pngs, buf.Bytes())
	}

	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&ico, binary.LittleEndian, uint16(1)) // type icon
	binary.Write(&ico, binary.LittleEndian, uint16(len(sizes)))
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		b := byte(s)
		if s >= 256 {
			b = 0
		}
		ico.WriteByte(b)                                    // width
		ico.WriteByte(b)                                    // height
		ico.WriteByte(0)                                    // colors
		ico.WriteByte(0)                                    // reserved
		binary.Write(&ico, binary.LittleEndian, uint16(1))  // planes
		binary.Write(&ico, binary.LittleEndian, uint16(32)) // bpp
		binary.Write(&ico, binary.LittleEndian, uint32(len(pngs[i])))
		binary.Write(&ico, binary.LittleEndian, uint32(offset))
		offset += len(pngs[i])
	}
	for _, p := range pngs {
		ico.Write(p)
	}
	if err := os.WriteFile("web/static/icon.ico", ico.Bytes(), 0o644); err != nil {
		panic(err)
	}
	// also a 256 png for non-windows tray
	png.Encode(mustCreate("web/static/icon.png"), render(256))
}

func mustCreate(p string) *os.File {
	f, err := os.Create(p)
	if err != nil {
		panic(err)
	}
	return f
}
