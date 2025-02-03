package port

import (
	"fmt"

	"github.com/stuchl4n3k/naabu-probe/pkg/protocol"
)

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	Label    string            `json:"label"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.Label)
}
