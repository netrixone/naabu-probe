package runner

import (
	"context"
	"net"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr/asn"
	iputil "github.com/projectdiscovery/utils/ip"
	"github.com/remeh/sizedwaitgroup"
	"github.com/stuchl4n3k/naabu-probe/pkg/scan"
	"golang.org/x/sync/semaphore"
)

func (r *Runner) LoadTargets(targets []string) error {
	r.scanner.ListenHandler.Phase.Set(scan.Init)

	// Pre-process all targets (resolves all non fqdn targets to ip address).
	if err := r.preProcessTargets(targets); err != nil {
		gologger.Warning().Msgf("%s\n", err)
	}

	return nil
}

func (r *Runner) preProcessTargets(targets []string) error {
	wg := sizedwaitgroup.New(r.options.Threads)

	for _, target := range targets {
		wg.Add()
		func(target string) {
			defer wg.Done()
			if err := r.AddTarget(target); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		}(target)
	}

	wg.Wait()
	return nil
}

func (r *Runner) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	if asn.IsASN(target) {
		// Get CIDRs for ASN
		cidrs, err := asn.GetCIDRsForASNNum(target)
		if err != nil {
			return err
		}
		for _, cidr := range cidrs {
			if err := r.scanner.IPRanger.AddHostWithMetadata(cidr.String(), "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
				gologger.Warning().Msgf("%s\n", err)
			}
		}
		return nil
	}
	if iputil.IsCIDR(target) {
		if err := r.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
			gologger.Warning().Msgf("%s\n", err)
		}
		return nil
	}
	if iputil.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		ip := net.ParseIP(target)
		// convert ip4 expressed as ip6 back to ip4
		if ip.To4() != nil {
			target = ip.To4().String()
		}

		metadata := "ip"
		if r.options.ReversePTR {
			names, err := iputil.ToFQDN(target)
			if err != nil {
				gologger.Debug().Msgf("reverse ptr failed for %s: %s\n", target, err)
			} else {
				metadata = strings.Trim(names[0], ".")
			}
		}
		err := r.scanner.IPRanger.AddHostWithMetadata(target, metadata)
		if err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
		return nil
	}

	targetToResolve := target
	ips, err := r.resolveFQDN(targetToResolve)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		if err := r.scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}

	return nil
}

func (r *Runner) resolveFQDN(target string) ([]string, error) {
	ipsV4, ipsV6, err := r.host2ips(target)
	if err != nil {
		return nil, err
	}

	var (
		initialHosts   []string
		initialHostsV6 []string
		hostIPS        []string
	)
	for _, ip := range ipsV4 {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			gologger.Warning().Msgf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}
	for _, ip := range ipsV6 {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			gologger.Warning().Msgf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHostsV6 = append(initialHostsV6, ip)
	}
	if len(initialHosts) == 0 && len(initialHostsV6) == 0 {
		return []string{}, nil
	}

	if len(initialHosts) > 0 {
		hostIPS = append(hostIPS, initialHosts[0])
	}
	if len(initialHostsV6) > 0 {
		hostIPS = append(hostIPS, initialHostsV6[0])
	}

	for _, hostIP := range hostIPS {
		if r.scanner.IPRanger.Contains(hostIP) {
			gologger.Debug().Msgf("Using ip %s for host %s enumeration\n", hostIP, target)
		}
	}

	return hostIPS, nil
}

func (r *Runner) takeHostLimitToken(ctx context.Context, host string) {
	s, _ := r.hostSemaphores.LoadOrStore(host, semaphore.NewWeighted(int64(r.options.PerHostConcurrency)))
	sem := s.(*semaphore.Weighted)
	_ = sem.Acquire(ctx, 1)
}

func (r *Runner) releaseHostLimitToken(host string) {
	s, ok := r.hostSemaphores.Load(host)
	if !ok {
		gologger.Warning().Msg("Attempt to release host limit, that was not held.\n")
		return
	}

	sem := s.(*semaphore.Weighted)
	sem.Release(1)
}
