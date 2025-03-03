package runner

import (
	"os"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/stuchl4n3k/naabu-probe/pkg/privileges"
	"github.com/stuchl4n3k/naabu-probe/pkg/result"
	"github.com/stuchl4n3k/naabu-probe/pkg/scan"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
// nolint:maligned // just an option structure
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	NoColor        bool // No-Color disables the colored output
	Silent         bool // Silent suppresses any extra text and only writes found host:port to screen
	Verify         bool // Verify is used to check if the ports found were valid using CONNECT method
	Version        bool // Version specifies if we should just show version and exit
	Debug          bool // Prints out debug information
	InterfacesList bool // InterfacesList show interfaces list

	Retries            int                 // Retries is the number of retries for the port
	Rate               int                 // Rate is the rate of port scan requests
	PerHostConcurrency int                 // PerHostConcurrency is the max number of concurrent port scan requests for each host
	Timeout            time.Duration       // Timeout is the milliseconds to wait for ports to respond
	WarmUpTime         int                 // WarmUpTime between scan phases
	Host               goflags.StringSlice // Host is the single host or comma-separated list of hosts to find ports for
	Output             string              // Output is the file to write found ports to.
	Ports              string              // Ports is the ports to use for enumeration
	TopPorts           string              // Tops ports to scan
	Interface          string              // Interface to use for TCP packets
	ConfigFile         string              // Config file contains a scan configuration
	Threads            int                 // Internal worker threads
	IPVersion          goflags.StringSlice // IP Version to use while resolving hostnames
	ScanType           string              // Scan Type
	Proxy              string              // Socks5 proxy
	ProxyAuth          string              // Socks5 proxy authentication (username:password)
	Resolvers          string              // Resolvers (comma separated or file)
	baseResolvers      []string
	OnResult           result.ResultCallback // callback on final host result
	OnReceive          result.ResultCallback // callback on response receive
	CSV                bool
	HealthCheck        bool
	TcpSynPingProbes   goflags.StringSlice
	TcpAckPingProbes   goflags.StringSlice
	// UdpPingProbes               goflags.StringSlice - planned
	// STcpInitPingProbes          goflags.StringSlice - planned
	IcmpEchoRequestProbe        bool
	IcmpTimestampRequestProbe   bool
	IcmpAddressMaskRequestProbe bool
	// IpProtocolPingProbes        goflags.StringSlice - planned
	ArpPing                   bool
	IPv6NeighborDiscoveryPing bool
	// HostDiscoveryIgnoreRST      bool - planned
	InputReadTimeout time.Duration
	// ReversePTR lookup for ips
	ReversePTR bool
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Naabu is a port scanning tool written in Go that allows you to enumerate open ports for hosts in a fast and reliable manner.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Host, "host", "h", nil, "hosts to scan ports for (comma-separated)", goflags.NormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "top ports to scan (default 100) [full,100,1000]"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "general internal worker threads"),
		flagSet.IntVar(&options.Rate, "rate", DefaultRateSynScan, "packets to send per second"),
		flagSet.IntVar(&options.PerHostConcurrency, "host-concurrency", DefaultHostConcurrency, "max number of concurrent packets for each host"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to (optional)"),
		flagSet.BoolVar(&options.CSV, "csv", false, "write output in csv format"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&cfgFile, "config", "", "path to the naabu configuration file (default $HOME/.config/naabu/config.yaml)"),
		flagSet.StringSliceVarP(&options.IPVersion, "iv", "ip-version", []string{scan.IPv4}, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", ConnectScan, "type of port scan (SYN/CONNECT)"),
		flagSet.BoolVarP(&options.InterfacesList, "il", "interface-list", false, "list available interfaces and public ip"),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "network Interface to use for port scan"),
		flagSet.StringVar(&options.Resolvers, "r", "", "list of custom resolver dns resolution (comma separated or from file)"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "socks5 proxy (ip[:port] / fqdn[:port]"),
		flagSet.StringVar(&options.ProxyAuth, "proxy-auth", "", "socks5 proxy authentication (username:password)"),
		flagSet.DurationVarP(&options.InputReadTimeout, "input-read-timeout", "irt", 3*time.Minute, "timeout on input read"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "number of retries for the port scan"),
		flagSet.DurationVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "millisecond to wait before timing out"),
		flagSet.IntVar(&options.WarmUpTime, "warm-up-time", 2, "time in seconds between scan phases"),
		flagSet.BoolVar(&options.Verify, "verify", false, "validate the ports again with TCP verification"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.HealthCheck, "hc", "health-check", false, "run diagnostic check up"),
		flagSet.BoolVar(&options.Debug, "debug", false, "display debugging information"),
		flagSet.BoolVarP(&options.Verbose, "v", "verbose", false, "display verbose output"),
		flagSet.BoolVarP(&options.NoColor, "nc", "no-color", false, "disable colors in CLI output"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display only results in output"),
		flagSet.BoolVar(&options.Version, "version", false, "display version of naabu"),
	)

	_ = flagSet.Parse()

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options, flagSet))
		os.Exit(0)
	}

	options.ConfigureOutput()

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := ShowNetworkInterfaces()
		if err != nil {
			gologger.Error().Msgf("Could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.ValidateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

func (options *Options) hasProbes() bool {
	return options.ArpPing || options.IPv6NeighborDiscoveryPing || options.IcmpAddressMaskRequestProbe ||
		options.IcmpEchoRequestProbe || options.IcmpTimestampRequestProbe || len(options.TcpAckPingProbes) > 0 ||
		len(options.TcpAckPingProbes) > 0
}

func (options *Options) shouldUseRawPackets() bool {
	return isOSSupported() && privileges.IsPrivileged && options.ScanType == SynScan && scan.PkgRouter != nil
}

func (options *Options) ShouldScanIPv4() bool {
	return sliceutil.Contains(options.IPVersion, "4")
}

func (options *Options) ShouldScanIPv6() bool {
	return sliceutil.Contains(options.IPVersion, "6")
}

func (options *Options) GetTimeout() time.Duration {
	if options.Timeout < time.Millisecond*500 {
		if options.ScanType == SynScan {
			return DefaultPortTimeoutSynScan
		}
		return DefaultPortTimeoutConnectScan
	}
	return options.Timeout
}
