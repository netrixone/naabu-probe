package scan

import (
	"errors"
	"net"

	"github.com/projectdiscovery/gologger"
	"github.com/stuchl4n3k/naabu-probe/pkg/privileges"
	"github.com/stuchl4n3k/naabu-probe/pkg/routing"
)

const (
	IPv4 = "4"
	IPv6 = "6"
)

var (
	ListenHandlers                          []*ListenHandler
	NetworkInterface                        string
	transportPacketSend, ethernetPacketSend chan *PkgSend

	PkgRouter routing.Router

	NumberOfHandlers = 1
	tcpsequencer     = NewTCPSequencer()
)

type ListenHandler struct {
	Busy                                   bool
	Phase                                  *Phase
	SourceHW                               net.HardwareAddr
	SourceIp4                              net.IP
	SourceIP6                              net.IP
	Port                                   int
	TcpConn4, UdpConn4, TcpConn6, UdpConn6 *net.IPConn
	TcpChan, UdpChan                       chan *PkgResult
}

func NewListenHandler() *ListenHandler {
	return &ListenHandler{Phase: &Phase{}}
}

func Acquire(options *Options) (*ListenHandler, error) {
	// always grant to unprivileged scans or connect scan
	if PkgRouter == nil || !privileges.IsPrivileged || options.ScanType == "c" {
		h := NewListenHandler()
		h.Busy = true
		return NewListenHandler(), nil
	}

	for _, listenHandler := range ListenHandlers {
		if !listenHandler.Busy {
			listenHandler.Phase = &Phase{}
			listenHandler.Busy = true
			return listenHandler, nil
		}
	}
	return nil, errors.New("no free handlers")
}

func (l *ListenHandler) Release() {
	l.Busy = false
	l.Phase = nil
}

func init() {
	if r, err := routing.New(); err != nil {
		gologger.Error().Msgf("could not initialize router: %s\n", err)
	} else {
		PkgRouter = r
	}
}

func ToString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}
