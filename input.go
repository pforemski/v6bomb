package main

import (
	"encoding/binary"
	"net"
	"sync"
)

func (M *Main) Input(wgStart, wgStop *sync.WaitGroup) {
	if wgStart != nil {
		wgStart.Done()
	}

	for pkt := range M.input {
		// dbg(5, "received %#v", pkt)

		switch pkt.L4proto {
		case PROTO_ICMP6:
			M.handleICMP(pkt)
		case PROTO_TCP:
			M.handleTCP(pkt)
		case PROTO_UDP:
			M.handleUDP(pkt)
		default:
			dbg(1, "TODO: process %d", pkt.L4proto)
		}

		M.inputP.Put(pkt)
	}

	if wgStop != nil {
		wgStop.Done()
	}
}
func (M *Main) handleUDP(pkt *InputPkt) {
	raw := pkt.L4bytes
	if len(raw) < 8 {
		return
	}

	dbg(5, "handling UDP %s -> %s: %x", pkt.L3src, pkt.L3dst, raw[8:])
	// that's it - drop it :)

	// NB: will return pkt to pool NOW
}

func (M *Main) handleTCP(pkt *InputPkt) {
	// long enough?
	raw := pkt.L4bytes
	if len(raw) < 20 {
		return
	}

	// parse
	be := binary.BigEndian
	srcport := be.Uint16(raw[0:2])
	dstport := be.Uint16(raw[2:4])
	seq := be.Uint32(raw[4:8])
	ack := be.Uint32(raw[8:12])
	flags := raw[13]

	// wrong source port? drop
	if srcport != M.opt.portn {
		return
	}

	// not SYN ACK? drop
	if flags & 0b00010010 != 0b00010010 {
		return
	}

	dbg(5, "handling TCP %s -> %s (seq %d, ack %d): %x",
		pkt.L3src, pkt.L3dst, seq, ack, raw[20:])

	// reply with an ACK
	rep := M.outputP.Get().(*OutputPkt)
	rep.L3src = append(rep.L3src[:0], pkt.L3dst...)
	rep.L3dst = append(rep.L3dst[:0], pkt.L3src...)
	rep.L4proto = PROTO_TCP
	rep.L4port = dstport
	rep.L4seq = ack
	rep.L4ack = seq + 1
	rep.L7pay = M.opt.payload
	M.output <- rep

	// NB: will return pkt to pool NOW
}

func (M *Main) handleICMP(pkt *InputPkt) {
	// long enough and NDP neighbor disc?
	if len(pkt.L4bytes) < 4 + 4 + 16 {
		return
	} else if pkt.L4bytes[0] != NDP_SOLICIT {
		return
	}

	// check if target in M.opt.src
	tgt := net.IP(pkt.L4bytes[8:24])
	if !M.opt.srcp.Contains(tgt) {
		return
	}

	dbg(5, "handling NDP %s -> %s: who-has %s?",
		pkt.L3src, pkt.L3dst, tgt)

	// reply - NB: copy bytes!
	rep := M.outputP.Get().(*OutputPkt)
	rep.L2me = pkt.L2me // read-only borrow
	rep.L3src = append(rep.L3src[:0], tgt...)
	rep.L3dst = append(rep.L3dst[:0], pkt.L3src...)
	rep.L4proto = PROTO_ICMP6
	rep.L7pay = nil
	M.output <- rep

	// NB: will return pkt to pool NOW
}
