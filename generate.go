package main

import (
	"math/rand"
	"net"
	"time"
)

func (M *Main) Generate() {
	s := time.Millisecond * time.Duration(M.opt.s)

	var pay []byte
	if M.opt.protob == PROTO_UDP {
		pay = M.opt.payload
	}

	for i := 0; M.opt.n == 0 || i < M.opt.n; i++ {
		// target packet mem
		pkt := M.outputP.Get().(*OutputPkt)

		// generate random IPs
		pkt.L3src = gen_randip(pkt.L3src, M.opt.srcp.IP, M.opt.srcl)
		pkt.L3dst = gen_randip(pkt.L3dst, M.opt.dstp.IP, M.opt.dstl)

		// proto, port, payload
		pkt.L4proto = M.opt.protob
		pkt.L4port = 0
		pkt.L7pay = pay

		// send and wait
		M.output <- pkt
		if s > 0 {
			time.Sleep(s)
		}
	}
}

func gen_randip(dst, src net.IP, plen int) net.IP {
	// start verbatim
	dst = append(dst[:0], src...)
	if plen == 128 {
		return dst // done
	}

	// this can cost
	r := rand.Int63()

	// handle non-aligned masks
	i := plen / 8 // starting byte
	j := plen % 8 // starting bit
	if j > 0 {
		m := byte(0xff) << (8 - j) // mask
		v := dst[i] & m            // what should stay
		w := byte(r) & (^m)        // new part

		dst[i] = v | w
		i++
		j = 0
		r /= 0xff
	}

	// fill the rest byte-by-byte
	for i < 16 {
		if r == 0 {
			r = rand.Int63()
		}

		dst[i] = byte(r)
		r /= 0xff
		i++
	}

	return dst
}
