package main

import (
	"math/rand"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv6"
)

type OutputPkt struct {
	L2me net.HardwareAddr

	L3src net.IP
	L3dst net.IP

	L4proto byte
	L4port uint16
	L4ack uint32
	L4seq uint32

	L7pay []byte
}

type Output struct {
	M *Main

	conn *net.IPConn
	pconn *ipv6.PacketConn

	ipv6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP
	icmp layers.ICMPv6
	ndp layers.ICMPv6NeighborAdvertisement

	buf gopacket.SerializeBuffer
	opts gopacket.SerializeOptions
}

func (M *Main) Output(wgStart, wgStop *sync.WaitGroup) {
	var O Output
	O.M = M

	// raw IPv6 conn
	var raddr net.IPAddr
	var err error
	O.conn, err = net.DialIP("ip6:255", nil, &raddr)
	if err != nil {
		dieErr("could not dial", err)
	}
	O.pconn = ipv6.NewPacketConn(O.conn)

	// layers templates
	O.ipv6 = layers.IPv6{
		Version: 6,
	}
	O.tcp = layers.TCP{
		DstPort: layers.TCPPort(M.opt.portn),
		Window: M.opt.windu16,
	}
	O.tcp.SetNetworkLayerForChecksum(&O.ipv6)
	O.udp = layers.UDP{
		DstPort: layers.UDPPort(M.opt.portn),
	}
	O.udp.SetNetworkLayerForChecksum(&O.ipv6)
	O.icmp = layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	O.icmp.SetNetworkLayerForChecksum(&O.ipv6)
	O.ndp = layers.ICMPv6NeighborAdvertisement{
		Flags: 0b01100000, // solicited + override
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{
				Type: layers.ICMPv6OptTargetAddress,
			},
		},
	}

	// for serialization
	O.buf = gopacket.NewSerializeBuffer()
	O.opts = gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	if wgStart != nil {
		wgStart.Done()
	}

	// done with setup, process the M.output chan
	O.process()

	if wgStop != nil {
		wgStop.Done()
	}
}

func (O *Output) process() {
	M := O.M
	var dst net.IPAddr

	for rep := range M.output {
		// common stuff
		O.ipv6.SrcIP = rep.L3src
		O.ipv6.DstIP = rep.L3dst

		// create response and serialize to O.buf
		switch rep.L4proto {
		case PROTO_ICMP6:
			O.processICMP(rep)
		case PROTO_TCP:
			O.processTCP(rep)
		case PROTO_UDP:
			O.processUDP(rep)
		}

		// send O.buf
		dst.IP = O.ipv6.DstIP
		_, err := O.pconn.WriteTo(O.buf.Bytes(), nil, &dst)
		if err != nil {
			dbgErr(0, err)
		}

		// re-use pkt
		M.outputP.Put(rep)
	}
}

func (O *Output) processICMP(rep *OutputPkt) {
	O.ipv6.NextHeader = layers.IPProtocolICMPv6
	O.ipv6.HopLimit = 255

	O.ndp.TargetAddress = rep.L3src
	O.ndp.Options[0].Data = rep.L2me

	gopacket.SerializeLayers(O.buf, O.opts, &O.ipv6, &O.icmp, &O.ndp)
}

func (O *Output) processTCP(rep *OutputPkt) {
	O.ipv6.NextHeader = layers.IPProtocolTCP
	O.ipv6.HopLimit = uint8(55 + rep.L3src[15] & 0x0f)

	switch rep.L4port {
	case 0: // new connection
		O.tcp.SrcPort = layers.TCPPort(32768 + rand.Int31n(28232))
		O.tcp.Ack = 0
		O.tcp.Seq = rand.Uint32()
		O.tcp.SYN = true
		O.tcp.ACK = false
		O.tcp.PSH = false

		dbg(1, "open TCP %s -> %s", rep.L3src, rep.L3dst)
		gopacket.SerializeLayers(O.buf, O.opts, &O.ipv6, &O.tcp)

	default: // established connection
		O.tcp.SrcPort = layers.TCPPort(rep.L4port)
		O.tcp.Ack = rep.L4ack
		O.tcp.Seq = rep.L4seq
		O.tcp.SYN = false
		O.tcp.ACK = true
		O.tcp.PSH = len(rep.L7pay) > 0

		gopacket.SerializeLayers(O.buf, O.opts, &O.ipv6, &O.tcp, gopacket.Payload(rep.L7pay))
	}
}

func (O *Output) processUDP(rep *OutputPkt) {
	O.ipv6.NextHeader = layers.IPProtocolUDP
	O.ipv6.HopLimit = uint8(55 + rep.L3src[15] & 0x0f)

	switch rep.L4port {
	case 0: // first packet
		O.udp.SrcPort = layers.UDPPort(32768 + rand.Int31n(28232))
		dbg(1, "open UDP %s -> %s", rep.L3src, rep.L3dst)

	default: // 2nd+ packet
		O.udp.SrcPort = layers.UDPPort(rep.L4port)
	}

	gopacket.SerializeLayers(O.buf, O.opts, &O.ipv6, &O.udp, gopacket.Payload(rep.L7pay))
}
