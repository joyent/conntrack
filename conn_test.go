package conntrack_test

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

func TestMain(t *testing.T) {
	//testConnBufferSizes(t)
	//testLabel(t)
	testDump(t)
	//testUpdate(t)
}

func testConnBufferSizes(t *testing.T) {
	c, err := conntrack.Dial(nil)
	require.NoError(t, err, "dialing conn")

	assert.NoError(t, c.SetReadBuffer(256))
	assert.NoError(t, c.SetWriteBuffer(256))

	require.NoError(t, c.Close(), "closing conn")
}

func ExampleConn_createUpdateFlow() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set up a new Flow object using a given set of attributes.
	f := conntrack.NewFlow(
		17, 0,
		netip.MustParseAddr("2a00:1450:400e:804::200e"),
		netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0,
	)

	// Send the Flow to the kernel.
	err = c.Create(f)
	if err != nil {
		log.Fatal(err)
	}

	f.Timeout = 240

	// Update the Flow's timeout to 240 seconds.
	err = c.Update(f)
	if err != nil {
		log.Fatal(err)
	}

	// Query the kernel based on the Flow's source/destination tuples.
	// Returns a new Flow object with its connection ID assigned by the kernel.
	qf, err := c.Get(f)
	if err != nil {
		log.Fatal(err)
	}

	// Print the result. The Flow has a timeout greater than 120 seconds.
	log.Print(qf)
}

func ExampleConn_dumpFilter() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	f1 := conntrack.NewFlow(
		6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0x00ff, // Set a connection mark
	)

	f2 := conntrack.NewFlow(
		17, 0, netip.MustParseAddr("2a00:1450:400e:804::200e"), netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0xff00, // Set a connection mark
	)

	_ = c.Create(f1)
	_ = c.Create(f2)

	// Dump all records in the Conntrack table that match the filter's mark/mask.
	df, err := c.DumpFilter(conntrack.Filter{Mark: 0xff00, Mask: 0xff00}, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Print the result. Only f2 is displayed.
	log.Print(df)
}

func ExampleConn_flush() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Evict all entries from the conntrack table in the current network namespace.
	err = c.Flush()
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleConn_flushFilter() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	f1 := conntrack.NewFlow(
		6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0x00ff, // Set a connection mark
	)

	f2 := conntrack.NewFlow(
		17, 0, netip.MustParseAddr("2a00:1450:400e:804::200e"), netip.MustParseAddr("2a00:1450:400e:804::200f"),
		1234, 80, 120, 0xff00, // Set a connection mark
	)

	_ = c.Create(f1)
	_ = c.Create(f2)

	// Flush only the second flow matching the filter's mark/mask.
	err = c.FlushFilter(conntrack.Filter{Mark: 0xff00, Mask: 0xff00})
	if err != nil {
		log.Fatal(err)
	}

	// Getting f1 succeeds.
	_, err = c.Get(f1)
	if err != nil {
		log.Fatal(err)
	}

	// Getting f2 will fail, since it was flushed.
	_, err = c.Get(f2)
	if err != nil {
		log.Println("Flow f2 missing, as expected", err)
	}
}

func ExampleConn_delete() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	f := conntrack.NewFlow(
		6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
		1234, 80, 120, 0,
	)

	// Create the Flow, will return err if unsuccessful.
	err = c.Create(f)
	if err != nil {
		log.Fatal(err)
	}

	// Delete the Flow based on its IP/port tuple, will return err if unsuccessful.
	err = c.Delete(f)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleConn_listen() {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Make a buffered channel to receive event updates on.
	evCh := make(chan conntrack.Event, 1024)

	// Listen for all Conntrack and Conntrack-Expect events with 4 decoder goroutines.
	// All errors caught in the decoders are passed on channel errCh.
	errCh, err := c.Listen(evCh, 4, append(netfilter.GroupsCT, netfilter.GroupsCTExp...))
	if err != nil {
		log.Fatal(err)
	}

	// Listen to Conntrack events from all network namespaces on the system.
	err = c.SetOption(netlink.ListenAllNSID, true)
	if err != nil {
		log.Fatal(err)
	}

	// Start a goroutine to print all incoming messages on the event channel.
	go func() {
		for {
			fmt.Println(<-evCh)
		}
	}()

	// Stop the program as soon as an error is caught in a decoder goroutine.
	log.Print(<-errCh)
}

func testLabel(t *testing.T) {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatalf("1. %s", err)
	}

	// Dump all records in the Conntrack table that match the filter's mark/mask.
	df, err := c.Dump(nil)
	if err != nil {
		log.Fatalf("2. %s", err)
	}

	var uf conntrack.Flow
	var found bool

	for i, f := range df {
		if f.TupleOrig.Proto.Protocol == 6 &&
			f.TupleOrig.Proto.DestinationPort == 22 {
			uf = f
			fmt.Printf("### 1. %d: flow:%+v \n", i, f)
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("### 2. not selected flow \n")
	}

	fmt.Printf("### 2. selected flow:%+v \n", uf)

	// get a single flow
	// Set up a new Flow object using a given set of attributes.
	src := uf.TupleOrig.IP.SourceAddress.String()
	dst := uf.TupleOrig.IP.DestinationAddress.String()
	mark := uint32(1111)

	saddr, _ := netip.ParseAddr(src)
	daddr, _ := netip.ParseAddr(dst)

	timestamp := uint32(time.Now().Unix())
	fmt.Printf("%d \n", timestamp)

	f := conntrack.NewFlow(
		uf.TupleOrig.Proto.Protocol,
		0,
		saddr,
		daddr,
		uf.TupleOrig.Proto.SourcePort,
		uf.TupleOrig.Proto.DestinationPort,
		0,
		mark)

	f.TupleOrig.Proto.ICMPv4 = uf.TupleOrig.Proto.ICMPv4
	f.TupleOrig.Proto.ICMPID = uf.TupleOrig.Proto.ICMPID
	f.TupleOrig.Proto.ICMPType = uf.TupleOrig.Proto.ICMPType

	//////////////////////
	// update label

	f.Labels = make([]byte, 16)
	f.LabelsMask = make([]byte, 16)

	binary.BigEndian.PutUint32(f.Labels[0:4], timestamp)
	binary.BigEndian.PutUint32(f.LabelsMask[0:4], ^uint32(0))

	if false {
		f.Labels[10] = 99
		f.Labels[11] = 88
		f.LabelsMask[10] = 0xff
		f.LabelsMask[11] = 0xff
	}

	fmt.Printf("### 3. Labels: %+v \n", f.Labels)
	fmt.Printf("### 3.   mask: %+v \n", f.LabelsMask)

	// update
	err = c.Update(f)
	if err != nil {
		log.Fatalf("3. %s", err)
	}

	////////////////////////

	// Query the kernel based on the Flow's source/destination tuples.
	// Returns a new Flow object with its connection ID assigned by the kernel.
	qf, err := c.Get(f)
	if err != nil {
		log.Fatalf("4. %s", err)
	}

	fmt.Printf("### 3. get flow:%+v \n", qf)
}

func testDump(t *testing.T) {
	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatalf("1. %s", err)
	}

	// Dump all records in the Conntrack table that match the filter's mark/mask.
	df, err := c.Dump(nil)
	if err != nil {
		log.Fatalf("2. %s", err)
	}

	var i int
	for _, f := range df {
		fmt.Printf("### %d: flow:%+v \n", i, f)

		/*
			if f.TupleOrig.Proto.Protocol == 1 {
				i++
				fmt.Printf("### %d: flow:%+v \n", i, f)
			}
		*/
	}
}

func testDump1(t *testing.T) {
	// Open a Conntrack connection.
	log.Printf("start dump...\n")
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatalf("1. %s", err)
	}

	dumpCt(c)
}

func dumpCt(c *conntrack.Conn) {

	// Dump all records in the Conntrack table that match the filter's mark/mask.
	df, err := c.Dump(nil)
	if err != nil {
		log.Fatalf("2. %s", err)
	}

	//log.Printf("length=%d \n", len(df))

	for i, f := range df {
		var proto *conntrack.ProtoInfoTCP

		if f.ProtoInfo.TCP != nil &&
			//f.TupleOrig.IP.DestinationAddress == netip.MustParseAddr("37.153.118.121") {
			f.TupleOrig.IP.DestinationAddress == netip.MustParseAddr("1.1.1.100") {
			proto = f.ProtoInfo.TCP
		} else {
			//fmt.Printf("### %d: flow:%+v \n", i, f)
			continue
		}

		fmt.Printf("### %d: before: flow:%+v, tcp=%+v, flag=0x%x \n", i, f, *proto, proto.OriginalFlags)

		proto.State = 2
		proto.OriginalFlags |= 0x800

		fmt.Printf("### %d: after: flow:%+v, tcp=%+v, flag=0x%x \n", i, f, *proto, proto.OriginalFlags)

		// Update the Flow's timeout to 240 seconds.
		err = c.Update(f)
		if err != nil {
			log.Fatal(err)
		}

		// Query the kernel based on the Flow's source/destination tuples.
		// Returns a new Flow object with its connection ID assigned by the kernel.
		qf, err := c.Get(f)
		if err != nil {
			log.Fatal(err)
		}

		proto = qf.ProtoInfo.TCP
		fmt.Printf("### %d: tcp=%+v \n", i, *proto)

	}
}

func updateCt(conn *conntrack.Conn, uf *conntrack.Flow) {
	if uf.Status.Value&conntrack.StatusSeenReply != 0 {
		// already syn_recved
		return
	} else if uf.ProtoInfo.TCP == nil {
		// only tcp
		return
	} else if uf.Zone < uint16(100) || uint16(2100) < uf.Zone {
		// not NLB Traffic
		return
	}

	fmt.Printf("### 1.New event: %+v, Zone=%d, ProtoInfo=%+v \n",
		uf, uf.Zone, uf.ProtoInfo.TCP)

	f := conntrack.NewFlow(
		uf.TupleOrig.Proto.Protocol,
		uf.Status.Value|conntrack.StatusSeenReply|conntrack.StatusAssured,
		uf.TupleOrig.IP.SourceAddress,
		uf.TupleOrig.IP.DestinationAddress,
		uf.TupleOrig.Proto.SourcePort,
		uf.TupleOrig.Proto.DestinationPort,
		0,
		uf.Mark)

	/*
		f.TupleOrig.Proto.ICMPv4 = uf.TupleOrig.Proto.ICMPv4
		f.TupleOrig.Proto.ICMPID = uf.TupleOrig.Proto.ICMPID
		f.TupleOrig.Proto.ICMPType = uf.TupleOrig.Proto.ICMPType
	*/

	// 0x0800
	// value & mask
	var flags uint16 = 0x0808
	f.Zone = uf.Zone
	f.ProtoInfo.TCP = uf.ProtoInfo.TCP
	f.ProtoInfo.TCP.State = 2
	f.ProtoInfo.TCP.OriginalFlags |= flags
	f.ProtoInfo.TCP.ReplyFlags |= flags

	fmt.Printf("### 2.Update conntrack: %s:%d->%s:%d(%d), Zone(OvsPortId)=%d, ProtoInfo=%+v \n",
		uf.TupleOrig.IP.SourceAddress,
		uf.TupleOrig.Proto.SourcePort,
		uf.TupleOrig.IP.DestinationAddress,
		uf.TupleOrig.Proto.DestinationPort,
		uf.TupleOrig.Proto.Protocol,
		uf.Zone,
		f.ProtoInfo.TCP)

	err := conn.Update(f)
	if err != nil {
		fmt.Printf("failed to update: err=%s \n", err)
	}

	// Query the kernel based on the Flow's source/destination tuples.
	// Returns a new Flow object with its connection ID assigned by the kernel.
	qf, err := conn.Get(f)
	if err != nil {
		fmt.Printf("failed to get ct: err=%s \n", err)
	}

	fmt.Printf("### 3.Updated CT: %+v, ### ProtoInfo=%+v \n", qf, qf.ProtoInfo.TCP)
}

func testUpdate(t *testing.T) {
	fmt.Printf("Start TestUpdate\n")

	eventConn, err := conntrack.Dial(nil)
	if err != nil {
		fmt.Printf("unexpected error dialing namespaced connection: %s \n", err)
		return
	}
	defer eventConn.Close()

	// Open a Conntrack connection.
	conn, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatalf("failed to connect netlink: err=%s \n", err)
		return
	}
	defer conn.Close()

	// Subscribe to new/update conntrack events using a single worker.
	ev := make(chan conntrack.Event)
	errChan, err := eventConn.Listen(ev, 1, []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
		//netfilter.GroupCTUpdate,
		//netfilter.GroupCTDestroy,
	})

	for {
		select {
		case <-errChan:
		case e := <-ev:
			if e.Type == conntrack.EventNew && e.Flow != nil {
				fmt.Printf("new event: %+v\n", e.Flow)
				updateCt(conn, e.Flow)
			}
		}
	}
}
