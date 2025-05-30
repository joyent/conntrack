package conntrack

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

const (
	BpfFilterInstructionSize = 4 // 4 fileds
)

type BpfFilter struct {
	NumInst      uint16
	Instructions []uint32
}

func (bf BpfFilter) String() string {
	return fmt.Sprintf("%d, %v", bf.NumInst, bf.Instructions)
}

// unmarshal unmarshals netlink attributes into a Tuple.
func (bf BpfFilter) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() < 2 {
		return errNeedChildren
	}

	for ad.Next() {
		tt := bpfFilterType(ad.Type())
		switch tt {
		case ctaBpfFltInstCount:
			bf.NumInst = ad.Uint16()
		case ctaBpfFltInst:
			inst := make([]uint32, bf.NumInst)
			data := ad.Bytes()
			buf := bytes.NewReader(data)
			err := binary.Read(buf, binary.BigEndian, inst)
			if err != nil {
				return fmt.Errorf("failed to read insts: err=%v", err)
			}

		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}

		if err := ad.Err(); err != nil {
			return fmt.Errorf("unmarshal %s: %w", tt, err)
		}
	}

	return ad.Err()
}

func (bf BpfFilter) Marshal() []netfilter.Attribute {
	att, _ := bf.marshal(uint16(ctaDrvCfgBpfFilter))
	return []netfilter.Attribute{
		att,
	}
}

// marshal marshals a Tuple to a netfilter.Attribute.
func (bf BpfFilter) marshal(at uint16) (netfilter.Attribute, error) {
	// an instruction made of 4 Uint32
	l := uint16(len(bf.Instructions) / BpfFilterInstructionSize)
	if l != bf.NumInst {
		return netfilter.Attribute{}, fmt.Errorf("Invalid Instructions")
	}

	nfa := netfilter.Attribute{Type: at, Nested: true, Children: make([]netfilter.Attribute, 2)}

	nfa.Children[0] = netfilter.Attribute{
		Type: uint16(ctaBpfFltInstCount), Data: netfilter.Uint16Bytes(bf.NumInst),
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, bf.Instructions)
	if err != nil {
		return netfilter.Attribute{}, err
	}

	nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaBpfFltInst), Data: buf.Bytes()}

	return nfa, nil
}
