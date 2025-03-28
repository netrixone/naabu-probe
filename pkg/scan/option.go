package scan

import (
	"time"

	"github.com/netrixone/naabu-probe/pkg/result"
)

// Options of the scan
type Options struct {
	Timeout   time.Duration
	Rate      int
	OnReceive result.ResultCallback
	ScanType  string
	Proxy     string
	ProxyAuth string
}
