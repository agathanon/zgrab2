package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/irc"
)

func init() {
	zgrab2.RegisterModule(irc.NewModule())
}
