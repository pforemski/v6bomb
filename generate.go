package main

import (
	"math/rand"
	"time"
)

func (M *Main) Generate() {
	for i := 0; M.opt.n == 0 || i < M.opt.n; i++ {
		pkt := M.outputP.Get().(*OutputPkt)

		// TODO: FIXME
		pkt.L3src = append(pkt.L3src[:0], M.opt.srcip...)
		pkt.L3src[15] = byte(rand.Int63n(256))
		pkt.L3src[14] = byte(rand.Int63n(256))
		pkt.L3src[13] = byte(rand.Int63n(256))
		pkt.L3src[12] = byte(rand.Int63n(256))

		// TODO: support dest net
		pkt.L3dst = append(pkt.L3dst[:0], M.opt.dstip...)

		pkt.L4proto = M.opt.protob
		pkt.L4port = 0

		if M.opt.protob == PROTO_UDP {
			pkt.L7pay = M.opt.payload
		}

		// send and wait
		M.output <- pkt
		time.Sleep(time.Millisecond * time.Duration(M.opt.s))
	}
}
