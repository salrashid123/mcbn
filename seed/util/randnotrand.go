package util

// from https://gist.github.com/jpillora/5a0471b246d541b984ab

import (
	"crypto/sha512"
	"io"
)

func NewDetermRand(seed []byte) io.Reader {
	return &DetermRand{next: seed}
}

type DetermRand struct {
	next []byte
}

func (d *DetermRand) cycle() []byte {
	result := sha512.Sum512(d.next)
	d.next = result[:sha512.Size/2]
	return result[sha512.Size/2:]
}

func (d *DetermRand) Read(b []byte) (int, error) {
	if len(b) == 1 {
		return 1, nil
	}
	n := 0
	for n < len(b) {
		out := d.cycle()
		n += copy(b[n:], out)
	}
	return n, nil
}
