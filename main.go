package main

import (
	"flag"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type Main struct {
	opt struct {
		seed int64

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

		payload []byte

		n int
		s int64
	}

	input chan *InputPkt
	inputP sync.Pool

	output chan *OutputPkt
	outputP sync.Pool
}

func (M *Main) parseArgs() {
	flag.IntVar(&dbgLevel, "dbg", 1, "debugging level")
	flag.BoolVar(&M.opt.ndp, "ndp", false, "answer NDP queries for source prefix")
	flag.IntVar(&M.opt.window, "window", 16, "TCP window size")
	flag.Int64Var(&M.opt.seed, "seed", time.Now().UnixNano(), "random seed")
	flag.IntVar(&M.opt.n, "n", 1, "number of connections to open")
	flag.Int64Var(&M.opt.s, "s", 1000, "number of miliseconds to sleep")
	flag.Parse()

	if flag.NArg() < 5 {
		die("Usage: v6bomb <v6-iface> <src-prefix> <dst-prefix> tcp|udp <port> [<payload-file>]")
	}

	args := flag.Args()
	M.opt.iface = args[0]
	M.opt.src = args[1]
	M.opt.dst = args[2]
	M.opt.proto = args[3]
	M.opt.port = args[4]

	if len(args) > 5 {
		var err error
		M.opt.payload, err = os.ReadFile(args[5])
		if err != nil {
			dieErr("could not read payload file", err)
		}
	}

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
	M.input = make(chan *InputPkt, 10)
	M.inputP.New = func() any {
		return new(InputPkt)
	}

	M.output = make(chan *OutputPkt, 1000) // TODO: len
	M.outputP.New = func() any {
		return new(OutputPkt)
	}

	M.parseArgs()
	rand.Seed(M.opt.seed)

	// init back-end
	var wgStart, wgStop sync.WaitGroup
	wgStart.Add(3)
	wgStop.Add(3)
	go M.Sniff(&wgStart, &wgStop)
	go M.Input(&wgStart, &wgStop)
	go M.Output(&wgStart, &wgStop)

	wgStart.Wait()
	dbg(0, "initialized, sending traffic...")

	M.Generate()
	dbg(0, "done")

	// TODO: real shut-down?
	for {
		time.Sleep(time.Second)
	}
}
