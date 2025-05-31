package conntrack

import (
	"github.com/mdlayher/netlink"
)

func (c *Conn) RunQuery(req netlink.Message) ([]netlink.Message, error) {
	return c.conn.Query(req)
}
