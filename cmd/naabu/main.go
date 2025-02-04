package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/stuchl4n3k/naabu-probe/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			naabuRunner.ShowScanResultOnExit()
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	// Setup progressbar.
	go func() {
		tick := time.NewTicker(1 * time.Second)
		defer tick.Stop()

		prevPackets := uint64(0)
		for range tick.C {
			totalPackets, _ := naabuRunner.Stats().GetCounter("total")
			packets, _ := naabuRunner.Stats().GetCounter("packets")
			if packets > prevPackets {
				gologger.Info().Msgf("Progress: %3.0f %% (%d/%d packets)\n", float64(packets)*100/float64(totalPackets), packets, totalPackets)
				prevPackets = packets
			}
		}
	}()

	// Start the scan.
	if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
