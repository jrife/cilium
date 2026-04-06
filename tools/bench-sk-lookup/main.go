package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/tools/bench-sk-lookup/bpf"
)

const (
	warmup        = 1000000
	defaultRepeat = 12500000
)

// Usage: bench-sk-lookup SIP:SPORT DIP:DPORT
func main() {
	var skLookupObjects bpf.BenchSkLookupObjects
	var ctx [14]byte

	bindAddr := flag.String("bind", "", "")
	connectAddr := flag.String("connect", "", "")
	lookupSrc := flag.String("lookup-src", "0.0.0.0:0", "")
	lookupDst := flag.String("lookup-dst", "0.0.0.0:0", "")
	repeat := flag.Int("repeat", defaultRepeat, "")

	flag.Parse()

	lookupSrcAddr, err := net.ResolveUDPAddr("udp", *lookupSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing bind address \"%s\": %v\n", *bindAddr, err)
		os.Exit(1)
	}
	lookupDstAddr, err := net.ResolveUDPAddr("udp", *lookupDst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing connect address \"%s\": %v\n", *connectAddr, err)
		os.Exit(1)
	}

	sock, err := setupSocket(*bindAddr, *connectAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up socket: %v\n", err)
		os.Exit(1)
	}
	defer sock.Close()

	if err := bpf.LoadBenchSkLookupObjects(&skLookupObjects, nil); err != nil {
		maybeReportVerifierError(err)
		fmt.Fprintf(os.Stderr, "Error loading objects: %v\n", err)
		os.Exit(1)
	}
	defer skLookupObjects.Close()

	if lookupSrcAddr.IP.To4() != nil && lookupDstAddr.IP.To4() != nil {
		if err := skLookupObjects.BenchSkLookupVariables.Family.Set(uint8(syscall.AF_INET)); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring family: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Saddr.Set(lookupSrcAddr.IP.To4()); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring saddr: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Sport.Set(uint16(lookupSrcAddr.Port)); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring sport: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Daddr.Set(lookupDstAddr.IP.To4()); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring daddr: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Dport.Set(uint16(lookupDstAddr.Port)); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring dport: %v\n", err)
			os.Exit(1)
		}
	} else if lookupSrcAddr.IP.To16() != nil && lookupDstAddr.IP.To16() != nil {
		if err := skLookupObjects.BenchSkLookupVariables.Family.Set(uint8(syscall.AF_INET6)); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring family: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Saddr6.Set(lookupSrcAddr.IP.To16()); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring saddr6: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Sport.Set(uint16(lookupSrcAddr.Port)); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring sport: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Daddr6.Set(lookupDstAddr.IP.To16()); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring daddr6: %v\n", err)
			os.Exit(1)
		}
		if err := skLookupObjects.BenchSkLookupVariables.Dport.Set(uint16(lookupDstAddr.Port)); err != nil {
			fmt.Fprintf(os.Stderr, "Configuring dport: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Both lookup addresses must either be IPv4 or IPv6\n")
		os.Exit(1)
	}

	fmt.Printf("Warming up...\n")
	if _, _, err = skLookupObjects.BenchSkLookup.Benchmark(ctx[:], warmup, func() {
		fmt.Fprintf(os.Stderr, "Benchmark reset\n")
		os.Exit(1)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error running warm up: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Running benchmark...\n")
	result, avg, err := skLookupObjects.BenchSkLookup.Benchmark(ctx[:], *repeat, func() {
		fmt.Fprintf(os.Stderr, "Benchmark reset\n")
		os.Exit(1)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running benchmark: %v\n", err)
		os.Exit(1)
	}
	lookupResult := ""
	if result == 0 {
		lookupResult = "socket found"
	} else {
		lookupResult = "socket not found"
	}
	fmt.Printf("Lookup Result: %v\n", lookupResult)
	fmt.Printf("Total Lookups: %v\n", *repeat)
	fmt.Printf("Average Lookup Time: %v\n", avg)
}

func setupSocket(bindAddrStr string, connectAddrStr string) (net.Conn, error) {
	var bindAddr *net.UDPAddr
	var connectAddr *net.UDPAddr
	var err error

	if bindAddrStr != "" {
		bindAddr, err = net.ResolveUDPAddr("udp", bindAddrStr)
		if err != nil {
			return nil, fmt.Errorf("parsing bind address \"%s\": %v\n", bindAddrStr, err)
		}
	}
	if connectAddrStr != "" {
		connectAddr, err = net.ResolveUDPAddr("udp", connectAddrStr)
		if err != nil {
			return nil, fmt.Errorf("parsing connect address \"%s\": %v\n", connectAddrStr, err)
		}
	}

	if connectAddr != nil {
		return net.DialUDP("udp", bindAddr, connectAddr)
	} else if bindAddr != nil {
		return net.ListenUDP("udp", bindAddr)
	}

	return nil, fmt.Errorf("must specify at least one of bind or connect address")
}

func maybeReportVerifierError(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve)
	}

	return err
}
