package main

import (
	"flag"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
)

type Main struct {
	opt struct {
		iface string
		ndp bool

		src string
		srcip net.IP
		srcp *net.IPNet

		dst string
		dstip net.IP
		dstp *net.IPNet

		proto string
		protob byte

		port string
		portn uint16

		window int
		windu16 uint16
	}

	input chan *SniffPkt
	inputP sync.Pool

	output chan *WritePkt
	outputP sync.Pool
}

func (M *Main) parseArgs() {
	flag.IntVar(&dbgLevel, "dbg", 2, "debugging level")
	flag.BoolVar(&M.opt.ndp, "ndp", false, "answer NDP queries for source prefix")
	flag.IntVar(&M.opt.window, "window", 16, "TCP window size")
	flag.Parse()

	if flag.NArg() < 5 {
		die("Usage: v6bomb <v6-iface> <src-prefix> <dst-prefix> tcp|udp <port>")
	}

	args := flag.Args()
	M.opt.iface = args[0]
	M.opt.src = args[1]
	M.opt.dst = args[2]
	M.opt.proto = args[3]
	M.opt.port = args[4]

	switch M.opt.proto {
	case "tcp":
		M.opt.protob = PROTO_TCP
	case "udp":
		M.opt.protob = PROTO_UDP
	default:
		die("Invalid protocol: %s", M.opt.proto)
	}

	var err error
	M.opt.srcip, M.opt.srcp, err = net.ParseCIDR(M.opt.src)
	if err != nil {
		dieErr("invalid source prefix", err)
	}

	M.opt.dstip, M.opt.dstp, err = net.ParseCIDR(M.opt.dst)
	if err != nil {
		dieErr("invalid destination prefix", err)
	}

	v, err := strconv.ParseUint(M.opt.port, 10, 16)
	if err != nil {
		dieErr("invalid port number", err)
	}
	M.opt.portn = uint16(v)

	if M.opt.window < 0 || M.opt.window > math.MaxUint16 {
		die("invalid TCP window size: %d", M.opt.window)
	}
	M.opt.windu16 = uint16(M.opt.window)
}

func main() {
	M := new(Main)

	M.input = make(chan *SniffPkt, 10)
	M.inputP.New = func() any {
		return new(SniffPkt)
	}

	M.output = make(chan *WritePkt, 1000) // TODO: len
	M.outputP.New = func() any {
		return new(WritePkt)
	}

	M.parseArgs()
	dbg(2, "hello world")

	// TODO: real source gen
	for i := 0; i < 100; i++ {
		pkt := M.outputP.Get().(*WritePkt)
		pkt.L3src = append(pkt.L3src, M.opt.srcip...)
		pkt.L3src[15] = byte(rand.Int63n(256))
		pkt.L3dst = M.opt.dstip
		pkt.L4proto = M.opt.protob

		M.output <- pkt
	}

	go M.Process()
	go M.Write()
	M.Sniff()
}
