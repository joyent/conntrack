package conntrack

import (
	"github.com/ti-mo/netfilter"
)

type Filter interface {
	Marshal() []netfilter.Attribute
}

// Filter is a structure used in dump operations to filter the response
// based on a given connmark and mask. The mask is applied to the Mark field of
// all flows in the conntrack table, the result is compared to the filter's Mark.
// Each flow that matches will be returned by the kernel.
type FilterMark struct {
	Mark, Mask uint32
}

// marshal marshals a Filter into a list of netfilter.Attributes.
func (f FilterMark) Marshal() []netfilter.Attribute {

	return []netfilter.Attribute{
		{
			Type: uint16(ctaMark),
			Data: netfilter.Uint32Bytes(f.Mark),
		},
		{
			Type: uint16(ctaMarkMask),
			Data: netfilter.Uint32Bytes(f.Mask),
		},
	}
}

type FilterZone struct {
	Zone uint16
}

// marshal marshals a Filter into a list of netfilter.Attributes.
func (f FilterZone) Marshal() []netfilter.Attribute {

	return []netfilter.Attribute{
		{
			Type: uint16(ctaZone),
			Data: netfilter.Uint16Bytes(f.Zone),
		},
	}
}
