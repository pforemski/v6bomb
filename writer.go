package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv6"
)

type WritePkt struct {
	L2me net.HardwareAddr

	L3src net.IP
	L3dst net.IP

	L4proto byte
	L4port uint16
	L4ack uint32
	L4seq uint32

	L7pay []byte
}

func (M *Main) Write() {
	// raw IPv6 conn
	var raddr net.IPAddr
	conn, err := net.DialIP("ip6:255", nil, &raddr)
	if err != nil {
		dieErr("could not dial", err)
	}
	pconn := ipv6.NewPacketConn(conn)

	// TODO: instantiate writer

	// IPv6
	ipv6 := layers.IPv6{
		Version: 6,
	}

	// TCP skeleton
	tcp := layers.TCP{
		DstPort: layers.TCPPort(M.opt.portn),
		Window: M.opt.windu16,
	}
	tcp.SetNetworkLayerForChecksum(&ipv6)

	// UDP skeleton
	udp := layers.UDP{
		DstPort: layers.UDPPort(M.opt.portn),
	}
	udp.SetNetworkLayerForChecksum(&ipv6)

	// ICMPv6 + NDP templates
	icmp := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	icmp.SetNetworkLayerForChecksum(&ipv6)
	ndp := layers.ICMPv6NeighborAdvertisement{
		Flags: 0b01100000, // solicited + override
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{
				Type: layers.ICMPv6OptTargetAddress,
			},
		},
	}

	// for serialization
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	var dst net.IPAddr
	for pkt := range M.output {
		// dbg(0, "sending %#v", pkt)

		ipv6.SrcIP = pkt.L3src
		ipv6.DstIP = pkt.L3dst

		// serialize to buf
		switch pkt.L4proto {
		case PROTO_ICMP6:
			ipv6.NextHeader = layers.IPProtocolICMPv6
			ipv6.HopLimit = 255

			ndp.TargetAddress = pkt.L3src
			ndp.Options[0].Data = pkt.L2me

			gopacket.SerializeLayers(buf, opts, &ipv6, &icmp, &ndp)

		case PROTO_TCP:
			ipv6.NextHeader = layers.IPProtocolTCP
			ipv6.HopLimit = uint8(55 + pkt.L3src[15] & 0x0f)

			if pkt.L4port == 0 {
				tcp.SrcPort = 31337 + layers.TCPPort(pkt.L3src[15])
				tcp.Ack = 0
				tcp.Seq = 31337 + uint32(pkt.L3src[15])
				tcp.SYN = true
				tcp.ACK = false
			} else {
				tcp.SrcPort = layers.TCPPort(pkt.L4port)
				tcp.Ack = pkt.L4ack
				tcp.Seq = pkt.L4seq
				tcp.SYN = false
				tcp.ACK = true
			}

			// TODO: payload
			gopacket.SerializeLayers(buf, opts, &ipv6, &tcp)

		case PROTO_UDP:
			ipv6.NextHeader = layers.IPProtocolUDP
			ipv6.HopLimit = uint8(55 + pkt.L3src[15] & 0x0f)

			if pkt.L4port == 0 {
				udp.SrcPort = 31337 + layers.UDPPort(pkt.L3src[15])
			} else {
				udp.SrcPort = layers.UDPPort(pkt.L4port)
			}

			// TODO: payload
			gopacket.SerializeLayers(buf, opts, &ipv6, &udp)
		}

		// send!
		dbg(1, "send %d %s -> %s", pkt.L4proto, pkt.L3src, pkt.L3dst)
		dst.IP = ipv6.DstIP
		_, err := pconn.WriteTo(buf.Bytes(), nil, &dst)
		if err != nil {
			dbgErr(0, err)
		}

		// re-use
		M.outputP.Put(pkt)
	}
}
