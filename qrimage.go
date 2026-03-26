package main

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"

	qrcode "github.com/skip2/go-qrcode"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

//go:embed amneziawg.jpg
var awgIconData []byte

//go:embed amneziavpn.jpg
var vpnIconData []byte

var (
	bgColor   = color.RGBA{0x2D, 0x2D, 0x2D, 0xFF}
	textColor = color.RGBA{0xCC, 0xCC, 0xCC, 0xFF}
)

const (
	qrSize  = 400
	padding = 16
	textH   = 18
)

// buildQRPng generates a QR code PNG with icon in center and label text below.
func buildQRPng(data string, ecLevel qrcode.RecoveryLevel, iconData []byte, label string) ([]byte, error) {
	qr, err := qrcode.New(data, ecLevel)
	if err != nil {
		return nil, err
	}
	qrImg := qr.Image(qrSize)

	// Canvas: dark background, QR centered, label below
	totalW := qrSize + padding*2
	totalH := padding + qrSize + 8 + textH + padding
	canvas := image.NewRGBA(image.Rect(0, 0, totalW, totalH))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Place QR
	qrX := padding
	qrY := padding
	draw.Draw(canvas, image.Rect(qrX, qrY, qrX+qrSize, qrY+qrSize), qrImg, qrImg.Bounds().Min, draw.Over)

	// Overlay icon
	overlayIcon(canvas, iconData)

	// Draw label
	if label != "" {
		drawCenteredText(canvas, label, 0, totalW, qrY+qrSize+8+13)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func overlayIcon(dst *image.RGBA, iconData []byte) {
	if len(iconData) == 0 {
		return
	}
	icon, err := jpeg.Decode(bytes.NewReader(iconData))
	if err != nil {
		return
	}

	bounds := dst.Bounds()
	// Icon is 18% of QR size, centered on the QR area
	iconSz := int(float64(qrSize) * 0.18)
	if iconSz < 10 {
		return
	}

	scaled := image.NewRGBA(image.Rect(0, 0, iconSz, iconSz))
	xdraw.BiLinear.Scale(scaled, scaled.Bounds(), icon, icon.Bounds(), xdraw.Over, nil)

	cx := bounds.Min.X + (bounds.Dx()-iconSz)/2
	cy := padding + (qrSize-iconSz)/2

	for y := 0; y < iconSz; y++ {
		for x := 0; x < iconSz; x++ {
			dst.Set(cx+x, cy+y, scaled.At(x, y))
		}
	}
}

func drawCenteredText(dst *image.RGBA, text string, x1, x2, y int) {
	f := basicfont.Face7x13
	textWidth := font.MeasureString(f, text).Ceil()
	x := x1 + (x2-x1-textWidth)/2
	d := &font.Drawer{
		Dst:  dst,
		Src:  &image.Uniform{textColor},
		Face: f,
		Dot:  fixed.P(x, y),
	}
	d.DrawString(text)
}
