package runner

import "time"

const (
	DefaultPortTimeoutSynScan     = time.Second
	DefaultPortTimeoutConnectScan = 3 * time.Second

	DefaultRateSynScan     = 1000
	DefaultRateConnectScan = 1500
	DefaultHostConcurrency = 1500

	DefaultRetriesSynScan     = 1
	DefaultRetriesConnectScan = 1

	SynScan     = "s"
	ConnectScan = "c"
)
