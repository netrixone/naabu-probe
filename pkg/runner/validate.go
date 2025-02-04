package runner

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/stuchl4n3k/naabu-probe/pkg/privileges"
	"github.com/stuchl4n3k/naabu-probe/pkg/scan"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	errNoInputList = errors.New("no input list provided")
	errOutputMode  = errors.New("both verbose and silent mode specified")
	errZeroValue   = errors.New("cannot be zero")
)

// ValidateOptions validates the configuration options passed
func (options *Options) ValidateOptions() error {
	// Check if Host or list of domains was provided.
	// If none was provided, then return.
	if options.Host == nil && len(flag.Args()) == 0 {
		return errNoInputList
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errOutputMode
	}

	if options.Rate == 0 {
		return errors.Wrap(errZeroValue, "rate")
	} else if !privileges.IsPrivileged && options.Rate == DefaultRateSynScan {
		options.Rate = DefaultRateConnectScan
	}

	if !privileges.IsPrivileged && options.Retries == DefaultRetriesSynScan {
		options.Retries = DefaultRetriesConnectScan
	}

	if options.Interface != "" {
		if _, err := net.InterfaceByName(options.Interface); err != nil {
			return fmt.Errorf("interface %s not found", options.Interface)
		}
	}

	if fileutil.FileExists(options.Resolvers) {
		chanResolvers, err := fileutil.ReadFile(options.Resolvers)
		if err != nil {
			return err
		}
		for resolver := range chanResolvers {
			options.baseResolvers = append(options.baseResolvers, resolver)
		}
	} else if options.Resolvers != "" {
		for _, resolver := range strings.Split(options.Resolvers, ",") {
			options.baseResolvers = append(options.baseResolvers, strings.TrimSpace(resolver))
		}
	}

	if len(options.IPVersion) > 0 && !sliceutil.ContainsItems([]string{scan.IPv4, scan.IPv6}, options.IPVersion) {
		return errors.New("IP Version must be 4 and/or 6")
	}

	if options.ScanType == SynScan && scan.PkgRouter == nil {
		gologger.Warning().Msgf("Routing could not be determined (are you using a VPN?).falling back to connect scan")
		options.ScanType = ConnectScan
	}

	return nil
}

// ConfigureOutput configures the output on the screen
func (options *Options) ConfigureOutput() {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
