package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/pflag"

	"sendpcap/pkg/config"
	"sendpcap/pkg/modifier"
	"sendpcap/pkg/processor"
	"sendpcap/pkg/util"
)

func main() {
	// Register all flags on the default FlagSet
	configPath := pflag.StringP("config", "c", "", "Config file path (YAML)")
	quiet := pflag.BoolP("quiet", "q", false, "Quiet mode (no .osp suffix)")
	noWait := pflag.Bool("no-wait", false, "Don't wait for file consumption, continue immediately")
	config.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	args := pflag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-q] [-c config] <file_or_directory> <target_directory> [replay_count]\n", os.Args[0])
		os.Exit(1)
	}

	input := args[0]
	targetDir := "/home/updpi/pcap_dir"
	replayCount := 1

	if len(args) >= 2 {
		targetDir = args[1]
	}
	if len(args) >= 3 {
		if rc, err := strconv.Atoi(args[2]); err == nil {
			replayCount = rc
		}
	}

	// Load and merge config (YAML + CLI overrides)
	cfg, err := config.LoadConfig(*configPath, pflag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Collect input files
	files, err := util.CollectInputFiles(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting files: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No pcap files found in %s\n", input)
		os.Exit(1)
	}

	// Create modifier from config
	mod := &modifier.PacketModifier{
		SrcMAC:   cfg.SrcMAC,
		DstMAC:   cfg.DstMAC,
		VLAN:     cfg.VLAN,
		SrcIP:    cfg.SrcIP,
		DstIP:    cfg.DstIP,
		SrcPort:  cfg.SrcPort,
		DstPort:  cfg.DstPort,
		TTL:      cfg.TTL,
		Protocol: cfg.Protocol,
	}

	// Create processor
	proc, err := processor.NewProcessor(targetDir, *quiet, *noWait)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating processor: %v\n", err)
		os.Exit(1)
	}
	defer proc.Cleanup()

	// Replay loop
	count := 0
	if replayCount == 0 {
		// Infinite loop
		for {
			if err := processAll(files, cfg, mod, proc); err != nil {
				fmt.Fprintf(os.Stderr, "Error processing: %v\n", err)
			}
			count++
			fmt.Printf("[%d] %s >> %s\n", count, input, targetDir)
			time.Sleep(10 * time.Second)
		}
	} else {
		for i := 0; i < replayCount; i++ {
			if err := processAll(files, cfg, mod, proc); err != nil {
				fmt.Fprintf(os.Stderr, "Error processing: %v\n", err)
				os.Exit(1)
			}
		}
	}
}

func processAll(files []string, cfg *config.Config, mod *modifier.PacketModifier, proc *processor.Processor) error {
	for _, f := range files {
		if err := proc.ProcessFile(f, cfg, mod); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Skipping %s: %v\n", f, err)
		}
	}
	return nil
}
