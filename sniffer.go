package main

import (
	"net"
	"time"

	"github.com/google/gopacket/pcapgo" // slow but portable
)

type SniffPkt struct {
	L2me net.HardwareAddr
	L2src net.HardwareAddr
	L2dst net.HardwareAddr

	L3src net.IP
	L3dst net.IP

	L4len uint16
	L4proto byte
	L4bytes []byte
}

func (M *Main) Sniff() {
	for inerr := 0; true; time.Sleep(time.Second) {
		// prepare for listening
		h, err := pcapgo.NewEthernetHandle(M.opt.iface)
		if err != nil {
			if inerr != 1 { dbgErr(2, err); inerr = 1; }
			continue
		} else if inerr == 1 {
			inerr = 0
		}
		me := h.LocalAddr()

		// set capture length
		err = h.SetCaptureLength(100)
		if err != nil {
			dieErr("setting capture length failed", err)
		}

		// listen for multicast targets for NDP?
		if M.opt.ndp {
			err = h.SetPromiscuous(true)
			if err != nil {
				dieErr("setting promiscious failed", err)
			}
		}

		// attach a BPF filter
		switch M.opt.protob {
		case PROTO_TCP:
			if M.opt.ndp {
				err = h.SetBPF(filterTcpNdp)
			} else {
				err = h.SetBPF(filterTcp)
			}
		case PROTO_UDP:
			if M.opt.ndp {
				err = h.SetBPF(filterUdpNdp)
			} else {
				err = h.SetBPF(filterUdp)
			}
		default:
			panic("invalid protob")
		}
		if err != nil {
			dieErr("setting BPF filter failed", err)
		}

		// read packets
		pkt := M.inputP.Get().(*SniffPkt)
		for {
			raw, ci, err := h.ZeroCopyReadPacketData()
			if err != nil {
				if inerr != 2 { dbgErr(2, err); inerr = 2; }
				break
			} else if inerr == 2 {
				inerr = 0
			}

			// packet too short?
			if len(raw) < 54 { continue }

			// get source MAC
			pkt.L2me = me
			pkt.L2dst = append(pkt.L2dst[:0], raw[:6]...)
			pkt.L2src = append(pkt.L2src[:0], raw[6:12]...)
			off := 12 // point at ethertype

			// is source MAC broadcast or multicast? or VLAN?
			if IsMACBroadcast(pkt.L2src) || IsMACMulticastIPv6(pkt.L2src){
				dbg(5, "MAC %s: ignoring broadcast / multicast source", pkt.L2src)
				continue
			} else if len(ci.AncillaryData) > 0 {
				if vlan, ok := ci.AncillaryData[0].(int); ok {
					dbg(5, "MAC %s: ignoring VLAN %d frame", pkt.L2src, vlan)
					continue
				}
			}

			// read ethertype, check if IPv6
			etype := uint16(raw[off]) << 8 | uint16(raw[off+1])
			if etype != 0x86DD {
				continue
			}
			off += 2 // point at ip6 header

			// read ip header
			off += 4 // point at payload length
			pkt.L4len = uint16(raw[off]) << 8 | uint16(raw[off+1])
			pkt.L4proto = raw[off+2]
			off += 4 // point at src addr

			// read src / dst ips
			pkt.L3src = append(pkt.L3src[:0], raw[off:off+16]...)
			pkt.L3dst = append(pkt.L3dst[:0], raw[off+16:off+32]...)
			off += 32 // point at pkt.l4bytes

			// check next header
			switch pkt.L4proto {
			case M.opt.protob:
				break
			case PROTO_ICMP6:
				if !M.opt.ndp {
					continue
				} // else break
			default:
				continue
			}

			// check dest IP
			switch {
			case M.opt.srcp.Contains(pkt.L3dst):
				break
			case M.opt.ndp && pkt.L3dst.IsMulticast():
				break
			default:
				continue
			}

			// copy what's left, send for processing
			pkt.L4bytes = append(pkt.L4bytes[:0], raw[off:]...)
			M.input <- pkt

			// get new packet
			pkt = M.inputP.Get().(*SniffPkt)
		}

		// prepare to re-open
		h.Close()
	}
}

func IsMACBroadcast(addr net.HardwareAddr) bool {
	return addr[0] == 0xFF && addr[1] == 0xFF && addr[2] == 0xFF &&
	       addr[3] == 0xFF && addr[4] == 0xFF && addr[5] == 0xFF
}

func IsMACMulticastIPv6(addr net.HardwareAddr) bool {
	return addr[0] == 0x33 && addr[1] == 0x33
}