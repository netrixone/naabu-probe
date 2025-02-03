package scan

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stuchl4n3k/naabu-probe/pkg/port"
	"github.com/stuchl4n3k/naabu-probe/pkg/protocol"
)

func TestConnectVerify(t *testing.T) {
	go func() {
		// start tcp server
		l, err := net.Listen("tcp", ":17895")
		if err != nil {
			assert.Nil(t, err)
		}
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	s, err := NewScanner(&Options{})
	assert.Nil(t, err)
	wanted := []*port.Port{
		{Port: 17895, Protocol: protocol.TCP},
	}

	targetPorts := []*port.Port{
		{Port: 17895, Protocol: protocol.TCP},
		{Port: 17896, Protocol: protocol.TCP},
	}
	got := s.ConnectVerify("localhost", targetPorts)
	assert.EqualValues(t, wanted, got)
}
