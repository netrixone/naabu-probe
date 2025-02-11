package runner

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Mzack9999/gcache"
	"github.com/miekg/dns"
	"github.com/modern-go/concurrent"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/ratelimit"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	"github.com/remeh/sizedwaitgroup"
	"github.com/stuchl4n3k/naabu-probe/pkg/port"
	"github.com/stuchl4n3k/naabu-probe/pkg/privileges"
	"github.com/stuchl4n3k/naabu-probe/pkg/protocol"
	"github.com/stuchl4n3k/naabu-probe/pkg/result"
	"github.com/stuchl4n3k/naabu-probe/pkg/scan"
	"golang.org/x/exp/slices"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	scanner        *scan.Scanner
	limiter        *ratelimit.Limiter
	hostSemaphores *concurrent.Map
	wgscan         sizedwaitgroup.SizedWaitGroup
	dnsclient      *dnsx.DNSX
	stats          *clistats.Statistics
	streamChannel  chan Target

	unique gcache.Cache[string, struct{}]
}

type Target struct {
	Ip   string
	Cidr string
	Fqdn string
	Port string
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	options.ConfigureOutput()

	// automatically disable host discovery when less than two ports for scan are provided
	ports, err := ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	// default to ipv4 if no ipversion was specified
	if len(options.IPVersion) == 0 {
		options.IPVersion = []string{scan.IPv4}
	}

	if options.Retries == 0 {
		options.Retries = DefaultRetriesSynScan
	}

	runner := &Runner{
		options: options,
	}

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if slices.Contains(options.IPVersion, "6") {
		dnsOptions.QuestionTypes = append(dnsOptions.QuestionTypes, dns.TypeAAAA)
	}
	if len(runner.options.baseResolvers) > 0 {
		dnsOptions.BaseResolvers = runner.options.baseResolvers
	}
	dnsclient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsclient = dnsclient

	runner.streamChannel = make(chan Target)

	uniqueCache := gcache.New[string, struct{}](1500).Build()
	runner.unique = uniqueCache

	scanOpts := &scan.Options{
		Timeout:   options.GetTimeout(),
		Rate:      options.Rate,
		OnReceive: options.OnReceive,
		ScanType:  options.ScanType,
	}

	if scanOpts.OnReceive == nil {
		scanOpts.OnReceive = runner.onReceive
	}

	scanner, err := scan.NewScanner(scanOpts)
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner

	runner.scanner.Ports = ports

	if runner.stats, err = clistats.NewWithOptions(context.Background(), &clistats.Options{}); err != nil {
		gologger.Warning().Msgf("Couldn't create progress engine: %s\n", err)
	}

	return runner, nil
}

func (r *Runner) onReceive(hostResult *result.HostResult) {
	if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
		return
	}

	dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
	if err != nil {
		return
	}

	// receive event has only one port
	for _, p := range hostResult.Ports {
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
		if r.unique.Has(ipPort) {
			return
		}
	}

	// Recover hostnames from ip:port combination.
	for _, p := range hostResult.Ports {
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
		if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
			if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
				// Replace bare ip:port with host.
				for idx, ipCandidate := range dt {
					if iputil.IsIP(ipCandidate) {
						dt[idx] = otherName
					}
				}
			}
		}
		_ = r.unique.Set(ipPort, struct{}{})
	}

	csvHeaderEnabled := true

	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	for _, host := range dt {
		buffer.Reset()
		if host == "ip" {
			host = hostResult.IP
		}

		// console output
		if r.options.CSV {
			data := &Result{IP: hostResult.IP, TimeStamp: time.Now().UTC()}
			if host != hostResult.IP {
				data.Host = host
			}
			for _, p := range hostResult.Ports {
				data.Port = p.Port
				data.Protocol = p.Protocol.String()
				data.Label = p.Label
				if r.options.CSV {
					if csvHeaderEnabled {
						writeCSVHeaders(data, writer)
						csvHeaderEnabled = false
					}
					writeCSVRow(data, writer)
				}
			}
		}

		if r.options.CSV {
			writer.Flush()
		} else {
			for _, p := range hostResult.Ports {
				gologger.Silent().Msgf("%s:%d\n", host, p.Port)
			}
		}
	}
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration(pctx context.Context) error {
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	if privileges.IsPrivileged && r.options.ScanType == SynScan {
		// Set values if those were specified via cli, errors are fatal
		if r.options.Interface != "" {
			err := r.SetInterface(r.options.Interface)
			if err != nil {
				return err
			}
		}
		r.BackgroundWorkers(ctx)
	}

	// Load targets and pre-process them.
	err := r.LoadTargets(r.options.Host)
	if err != nil {
		return err
	}

	// Init scan workers.
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)
	r.hostSemaphores = concurrent.NewMap()

	shouldUseRawPackets := r.options.shouldUseRawPackets()

	ShowNetworkCapabilities(r.options)
	ipsCallback := r.getPreprocessedIps

	// shrinks the ips to the minimum amount of cidr
	targets, targetsV4, targetsv6, err := r.GetTargetIps(ipsCallback)
	if err != nil {
		return err
	}
	var targetsCount, portsCount uint64
	for _, target := range append(targetsV4, targetsv6...) {
		if target == nil {
			continue
		}
		targetsCount += mapcidr.AddressCountIpnet(target)
	}

	portsCount = uint64(len(r.scanner.Ports))
	Range := targetsCount * portsCount
	r.scanner.ListenHandler.Phase.Set(scan.Scan)

	r.stats.AddStatic("ports", portsCount)
	r.stats.AddStatic("hosts", targetsCount)
	r.stats.AddStatic("retries", r.options.Retries)
	r.stats.AddStatic("startedAt", time.Now())
	r.stats.AddCounter("packets", uint64(0))
	r.stats.AddCounter("errors", uint64(0))
	r.stats.AddCounter("total", Range*uint64(r.options.Retries))

	// Retries are performed regardless of the previous scan results due to network unreliability
	for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
		// Use current time as seed
		currentSeed := time.Now().UnixNano()

		b := blackrock.New(int64(Range), currentSeed)
		for index := int64(0); index < int64(Range); index++ {
			xxx := b.Shuffle(index)
			ipIndex := xxx / int64(portsCount)
			portIndex := int(xxx % int64(portsCount))
			ip := r.PickIP(targets, ipIndex)
			port := r.PickPort(portIndex)

			// connect scan
			if shouldUseRawPackets {
				r.RawSocketEnumeration(ctx, ip, port)
			} else {
				r.wgscan.Add()
				go r.handleHostPort(ctx, ip, port)
			}

			r.stats.IncrementCounter("packets", 1)
		}

		r.wgscan.Wait()
	}

	if r.options.WarmUpTime > 0 {
		time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
	}

	r.scanner.ListenHandler.Phase.Set(scan.Done)

	// Validate the hosts if the user has asked for second step validation
	if r.options.Verify {
		r.ConnectVerification()
	}

	r.handleOutput(r.scanner.ScanResults)

	return nil
}

func (r *Runner) getPreprocessedIps() (cidrs []*net.IPNet) {
	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		if cidr := iputil.ToCidr(string(ip)); cidr != nil {
			cidrs = append(cidrs, cidr)
		} else {
			gologger.Error().Msgf("Could not convert host %q to CIDR\n", ip)
		}

		return nil
	})
	return
}

func (r *Runner) IPs() *ipranger.IPRanger {
	return r.scanner.IPRanger
}

func (r *Runner) GetTargetIps(ipsCallback func() []*net.IPNet) (targets, targetsV4, targetsV6 []*net.IPNet, err error) {
	targets = ipsCallback()

	// shrinks the ips to the minimum amount of cidr
	targetsV4, targetsV6 = mapcidr.CoalesceCIDRs(targets)
	if len(targetsV4) == 0 && len(targetsV6) == 0 {
		return nil, nil, nil, errors.New("no valid ipv4 or ipv6 targets were found")
	}

	targets = make([]*net.IPNet, 0, len(targets))
	if r.options.ShouldScanIPv4() {
		targets = append(targets, targetsV4...)
	} else {
		targetsV4 = make([]*net.IPNet, 0)
	}

	if r.options.ShouldScanIPv6() {
		targets = append(targets, targetsV6...)
	} else {
		targetsV6 = make([]*net.IPNet, 0)
	}

	return targets, targetsV4, targetsV6, nil
}

func (r *Runner) ShowScanResultOnExit() {
	r.handleOutput(r.scanner.ScanResults)
}

// Close runner instance
func (r *Runner) Close() {
	_ = r.scanner.IPRanger.Hosts.Close()
	if r.scanner != nil {
		r.scanner.Close()
	}
	if r.limiter != nil {
		r.limiter.Stop()
	}
}

// PickIP randomly
func (r *Runner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return r.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func (r *Runner) PickSubnetIP(network *net.IPNet, index int64) string {
	ipInt, bits, err := mapcidr.IPToInteger(network.IP)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return ""
	}
	subnetIpInt := big.NewInt(0).Add(ipInt, big.NewInt(index))
	ip := mapcidr.IntegerToIP(subnetIpInt, bits)
	return ip.String()
}

func (r *Runner) PickPort(index int) *port.Port {
	return r.scanner.Ports[index]
}

func (r *Runner) ConnectVerification() {
	r.scanner.ListenHandler.Phase.Set(scan.Scan)
	var swg sync.WaitGroup
	limiter := ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)
	defer limiter.Stop()

	verifiedResult := result.NewResult()

	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		limiter.Take()

		swg.Add(1)
		go func(hostResult *result.HostResult) {
			defer swg.Done()

			results := r.scanner.ConnectVerify(hostResult.IP, hostResult.Ports)
			verifiedResult.SetPorts(hostResult.IP, results)
		}(hostResult)
	}

	swg.Wait()

	r.scanner.ScanResults = verifiedResult
}

func (r *Runner) BackgroundWorkers(ctx context.Context) {
	r.scanner.StartWorkers(ctx)
}

func (r *Runner) RawSocketEnumeration(ctx context.Context, ip string, p *port.Port) {
	select {
	case <-ctx.Done():
		return
	default:
		if r.scanner.ScanResults.IPHasPort(ip, p) {
			return
		}

		r.limiter.Take()
		switch p.Protocol {
		case protocol.TCP:
			r.scanner.EnqueueTCP(ip, scan.Syn, p)
		case protocol.UDP:
			r.scanner.EnqueueUDP(ip, p)
		}
	}
}

func (r *Runner) handleHostPort(ctx context.Context, host string, p *port.Port) {
	defer r.wgscan.Done()

	select {
	case <-ctx.Done():
		return
	default:
		if r.scanner.ScanResults.IPHasPort(host, p) {
			return
		}

		r.limiter.Take()
		r.takeHostLimitToken(ctx, host)
		defer r.releaseHostLimitToken(host)

		open, err := r.scanner.ConnectPort(host, p, r.options.GetTimeout())
		if open && err == nil {
			r.scanner.ScanResults.AddPort(host, p)
			// ignore OnReceive when verification is enabled
			if r.options.Verify {
				return
			}
			if r.scanner.OnReceive != nil {
				r.scanner.OnReceive(&result.HostResult{IP: host, Ports: []*port.Port{p}})
			}
		}
	}
}

func (r *Runner) SetSourceIP(sourceIP string) error {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return errors.New("invalid source ip")
	}

	switch {
	case iputil.IsIPv4(sourceIP):
		r.scanner.ListenHandler.SourceIp4 = ip
	case iputil.IsIPv6(sourceIP):
		r.scanner.ListenHandler.SourceIP6 = ip
	default:
		return errors.New("invalid ip type")
	}

	return nil
}

func (r *Runner) SetSourcePort(sourcePort string) error {
	isValidPort := iputil.IsPort(sourcePort)
	if !isValidPort {
		return errors.New("invalid source port")
	}

	port, err := strconv.Atoi(sourcePort)
	if err != nil {
		return err
	}

	r.scanner.ListenHandler.Port = port

	return nil
}

func (r *Runner) SetInterface(interfaceName string) error {
	networkInterface, err := net.InterfaceByName(r.options.Interface)
	if err != nil {
		return err
	}

	r.scanner.NetworkInterface = networkInterface
	r.scanner.ListenHandler.SourceHW = networkInterface.HardwareAddr
	return nil
}

func (r *Runner) Stats() clistats.StatisticsClient {
	return r.stats
}

func (r *Runner) handleOutput(scanResults *result.Result) {
	var (
		file   *os.File
		err    error
		output string
	)

	if r.options.Verify {
		for hostResult := range scanResults.GetIPsPorts() {
			r.scanner.OnReceive(hostResult)
		}
	}

	// In case the user has given an output file, write all the found
	// ports to the output file.
	if r.options.Output != "" {
		output = r.options.Output

		// create path if not existing
		outputFolder := filepath.Dir(output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				gologger.Error().Msgf("Could not create output folder %s: %s\n", outputFolder, mkdirErr)
				return
			}
		}

		file, err = os.Create(output)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}
	csvFileHeaderEnabled := true

	if scanResults.HasIPsPorts() {
		for hostResult := range scanResults.GetIPsPorts() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}

			if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
				continue
			}

			// recover hostnames from ip:port combination
			for _, p := range hostResult.Ports {
				ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
				if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
					if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
						// replace bare ip:port with host
						for idx, ipCandidate := range dt {
							if iputil.IsIP(ipCandidate) {
								dt[idx] = otherName
							}
						}
					}
				}
			}

			buffer := bytes.Buffer{}
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostResult.IP
				}

				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), host, hostResult.IP)

				// file output
				if file != nil {
					if r.options.CSV {
						err = WriteCsvOutput(host, hostResult.IP, hostResult.Ports, csvFileHeaderEnabled, file)
					} else {
						err = WriteHostOutput(host, hostResult.Ports, file)
					}

					if err != nil {
						gologger.Error().Msgf("Could not write results to file %s for %s: %s\n", output, host, err)
					}
				}

				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostResult.IP, Ports: hostResult.Ports})
				}
			}
			csvFileHeaderEnabled = false
		}
	}
}

func ipMatchesIpVersions(ip string, ipVersions ...string) bool {
	for _, ipVersion := range ipVersions {
		if ipVersion == scan.IPv4 && iputil.IsIPv4(ip) {
			return true
		}
		if ipVersion == scan.IPv6 && iputil.IsIPv6(ip) {
			return true
		}
	}
	return false
}
