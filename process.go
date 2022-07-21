package main

import (
	"encoding/binary"
	"net"
)

// TODO: check if we're NOT receiving what we're sending here
func (M *Main) Process() {
	for pkt := range M.input {
		// dbg(0, "received %#v", pkt)

		switch pkt.L4proto {
		case PROTO_ICMP6:
			M.processIcmp6(pkt)
		case PROTO_TCP:
			M.processTcp(pkt)
		default:
			dbg(1, "TODO: process %d", pkt.L4proto)
		}

		M.inputP.Put(pkt)
	}
}

func (M *Main) processTcp(pkt *SniffPkt) {
	// long enough?
	raw := pkt.L4bytes
	if len(raw) < 20 {
		return
	}

	// parse
	be := binary.BigEndian
	dstport := be.Uint16(raw[2:4])
	seq := be.Uint32(raw[4:8])
	ack := be.Uint32(raw[8:12])
	flags := raw[13]

	// not SYN ACK? drop
	if flags & 0b00010010 != 0b00010010 {
		return
	}

	dbg(5, "TCP %s -> %s: %x\n", pkt.L3src, pkt.L3dst, raw[20:])

	// reply with an ACK
	rep := M.outputP.Get().(*WritePkt)
	rep.L3src = append(rep.L3src[:0], pkt.L3dst...)
	rep.L3dst = append(rep.L3dst[:0], pkt.L3src...)
	rep.L4proto = PROTO_TCP
	rep.L4port = dstport
	rep.L4seq = ack
	rep.L4ack = seq + 1
	rep.L7pay = rep.L7pay[:0]
	M.output <- rep

	// NB: will return pkt to pool NOW
}

func (M *Main) processIcmp6(pkt *SniffPkt) {
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

	dbg(5, "NDP %s -> %s // %s -> %s: who-has %s?\n",
		pkt.L2src, pkt.L2dst, pkt.L3src, pkt.L3dst, tgt)

	// reply - NB: copy bytes!
	rep := M.outputP.Get().(*WritePkt)
	rep.L2me = pkt.L2me // read-only borrow
	rep.L3src = append(rep.L3src[:0], tgt...)
	rep.L3dst = append(rep.L3dst[:0], pkt.L3src...)
	rep.L4proto = PROTO_ICMP6
	rep.L7pay = rep.L7pay[:0]
	M.output <- rep

	// NB: will return pkt to pool NOW
}
