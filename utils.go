package main

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/rancher/rancher-cni-bridge/macfinder"
	"github.com/rancher/rancher-cni-bridge/macfinder/metadata"
	"github.com/vishvananda/netlink"
)

func makeVethPair(name, peer string, mtu int) (netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Flags: net.FlagUp,
			MTU:   mtu,
		},
		PeerName: peer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, err
	}

	return veth, nil
}

func peerExists(name string) bool {
	if _, err := netlink.LinkByName(name); err != nil {
		return false
	}
	return true
}

func makeVeth(name, peerName string, mtu int) (veth netlink.Link, err error) {
	veth, err = makeVethPair(name, peerName, mtu)
	switch {
	case err == nil:
		return

	case os.IsExist(err):
		if peerExists(peerName) {
			err = fmt.Errorf("container veth name provided (%v) already exists", name)
			return
		}
	default:
		err = fmt.Errorf("failed to make veth pair: %v", err)
		return
	}

	// should really never be hit
	err = fmt.Errorf("failed to find a unique veth name")
	return
}

// Only 15 characters are allowed (IFNAMSIZ)
func getHostVethName(containerID string) (string, error) {
	containerIDPrefixLength := 10
	if containerID == "" || len(containerID) < containerIDPrefixLength {
		return "", fmt.Errorf("no or invalid containerID specified")
	}

	return fmt.Sprintf("vethr%v", containerID[:containerIDPrefixLength]), nil
}

// SetupVeth is similar to the one provided by upstream except that
// you can pass your own host side veth's name
func SetupVeth(containerID, contVethName string, mtu int, hostNS ns.NetNS) (hostVeth, contVeth netlink.Link, err error) {
	hostVethName, err := getHostVethName(containerID)
	if err != nil {
		return
	}

	// To make sure there is no dangling veth, lookup the veth
	// on host side and delete if found
	err = hostNS.Do(func(_ ns.NetNS) error {
		hVeth, e := netlink.LinkByName(hostVethName)
		if e != nil {
			logrus.Debugf("rancher-cni-bridge: no dangling veth found on host for %v", hostVethName)
			return nil
		}

		if e = netlink.LinkDel(hVeth); e != nil {
			return fmt.Errorf("failed to delete dangling veth %q on host: %v", hostVethName, e)
		}
		logrus.Infof("rancher-cni-bridge: found and deleted dangling veth on host: %v", hostVethName)
		return nil
	})
	if err != nil {
		return
	}

	contVeth, err = makeVeth(contVethName, hostVethName, mtu)
	if err != nil {
		return
	}

	if err = netlink.LinkSetUp(contVeth); err != nil {
		err = fmt.Errorf("failed to set %q up: %v", contVethName, err)
		return
	}

	hostVeth, err = netlink.LinkByName(hostVethName)
	if err != nil {
		err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
		return
	}

	if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
		err = fmt.Errorf("failed to move veth to host netns: %v", err)
		return
	}

	err = hostNS.Do(func(_ ns.NetNS) error {
		hostVeth, err = netlink.LinkByName(hostVethName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q in %q: %v", hostVethName, hostNS.Path(), err)
		}

		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}
		return nil
	})
	return
}
func getBridgeIP(br *netlink.Bridge) (net.IP, error) {
	addrs, err := netlink.AddrList(br, syscall.AF_INET)
	if err != nil && err != syscall.ENOENT {
		return net.IP{}, fmt.Errorf("could not get list of IP addresses: %v", err)
	}

	for _, addr := range addrs {
		// return first IPv4 address. To4() returns nil if IP is not v4
		if addr.IP.To4() != nil {
			return addr.IP, nil
		}
	}
	return net.IP{}, fmt.Errorf("%q doesn't have an IPv4 address. Needed for gateway", br.Name)
}

func ensureBridgeAddr(br *netlink.Bridge, ipn *net.IPNet) error {
	addrs, err := netlink.AddrList(br, syscall.AF_INET)
	if err != nil && err != syscall.ENOENT {
		return fmt.Errorf("could not get list of IP addresses: %v", err)
	}

	// if there're no addresses on the bridge, it's ok -- we'll add one
	if len(addrs) > 0 {
		ipnStr := ipn.String()
		for _, a := range addrs {
			// string comp is actually easiest for doing IPNet comps
			if a.IPNet.String() == ipnStr {
				return nil
			}
		}
		return fmt.Errorf("%q already has an IP address different from %v", br.Name, ipn.String())
	}

	// no addresses on the bridge, add one
	addr := &netlink.Addr{IPNet: ipn, Label: ""}
	if err := netlink.AddrAdd(br, addr); err != nil {
		return fmt.Errorf("could not add IP address to %q: %v", br.Name, err)
	}
	return nil
}

func bridgeByName(name string) (*netlink.Bridge, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}

func ensureBridge(brName string, mtu int, promiscMode bool) (*netlink.Bridge, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  mtu,
			// Let kernel use default txqueuelen; leaving it unset
			// means 0, and a zero-length TX queue messes up FIFO
			// traffic shapers which use TX queue length as the
			// default packet limit
			TxQLen: -1,
		},
	}

	if err := netlink.LinkAdd(br); err != nil {
		if err != syscall.EEXIST {
			return nil, fmt.Errorf("could not add %q: %v", brName, err)
		}

		// it's ok if the device already exists as long as config is similar
		br, err = bridgeByName(brName)
		if err != nil {
			return nil, err
		}
	}

	if promiscMode {
		logrus.Debugf("rancher-cni-bridge: enabling promiscMode")
		if err := netlink.SetPromiscOn(br); err != nil {
			return nil, fmt.Errorf("could not set promiscuous mode on %q: %v", brName, err)
		}
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}

	return br, nil
}

func setupVeth(netns ns.NetNS, br *netlink.Bridge, containerID, ifName string, mtu int, hairpinMode bool) error {
	var hostVethName string

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, _, err := SetupVeth(containerID, ifName, mtu, hostNS)
		if err != nil {
			return err
		}

		hostVethName = hostVeth.Attrs().Name
		return nil
	})
	if err != nil {
		return err
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
	}

	// connect host veth end to the bridge
	if err = netlink.LinkSetMaster(hostVeth, br); err != nil {
		return fmt.Errorf("failed to connect %q to bridge %v: %v", hostVethName, br.Attrs().Name, err)
	}

	// set hairpin mode
	if err = netlink.LinkSetHairpin(hostVeth, hairpinMode); err != nil {
		return fmt.Errorf("failed to setup hairpin mode for %v: %v", hostVethName, err)
	}

	return nil
}

func calcGatewayIP(ipn *net.IPNet) net.IP {
	nid := ipn.IP.Mask(ipn.Mask)
	return ip.NextIP(nid)
}

func calculateBridgeIP(bridgeIP, bridgeSubnet string) (*net.IPNet, error) {
	var (
		ip          net.IP
		bridgeIPNet *net.IPNet
		err         error
	)

	_, brNetworkIPNet, err := net.ParseCIDR(bridgeSubnet)
	if err != nil {
		return nil, fmt.Errorf("Invalid bridgeSubnet specified got error: %v", err)
	}

	if bridgeIP != "" {
		ip = net.ParseIP(bridgeIP)
		if ip == nil {
			// Check if we can parse as a CIDR
			ip, _, err = net.ParseCIDR(bridgeIP)
			if err != nil {
				return nil, fmt.Errorf("invalid bridgeIP specified in config")
			}
		}

		if !brNetworkIPNet.Contains(ip) {
			return nil, fmt.Errorf("bridgeIP is not in bridgeSubnet")
		}
		bridgeIPNet = &net.IPNet{IP: ip, Mask: brNetworkIPNet.Mask}
	} else {
		// Use the first IP of the subnet for the bridge
		brNetworkIPTo4 := brNetworkIPNet.IP.To4()

		ip = net.IPv4(
			brNetworkIPTo4[0],
			brNetworkIPTo4[1],
			brNetworkIPTo4[2],
			brNetworkIPTo4[3]+1,
		)
		bridgeIPNet = &net.IPNet{IP: ip, Mask: brNetworkIPNet.Mask}
	}

	return bridgeIPNet, nil
}

func setBridgeIP(bridgeName, bridgeIP, bridgeSubnet string) error {
	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", bridgeName, err)
	}

	bridgeIPNet, err := calculateBridgeIP(bridgeIP, bridgeSubnet)
	if err != nil {
		return fmt.Errorf("failed to calculate bridge IP: %v", err)
	}

	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil && err != syscall.ENOENT {
		return fmt.Errorf("could not get list of IP addresses: %v", err)
	}
	if len(addrs) > 0 {
		bridgeIPStr := bridgeIPNet.String()
		for _, a := range addrs {
			if a.IPNet.String() == bridgeIPStr {
				// Bridge IP already set, nothing to do
				return nil
			}
		}
	}

	addr := &netlink.Addr{IPNet: bridgeIPNet, Label: ""}
	if err = netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP addr to %q: %v", bridgeName, err)
	}

	return nil
}

func setupBridge(n *NetConf) (*netlink.Bridge, error) {
	// create bridge if necessary
	br, err := ensureBridge(n.BrName, n.MTU, n.PromiscMode)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge %q: %v", n.BrName, err)
	}

	// Set the bridge IP address
	if n.BrSubnet != "" && !n.SkipBridgeConfigureIP {
		err = setBridgeIP(n.BrName, n.BrIP, n.BrSubnet)
		if err != nil {
			return nil, fmt.Errorf("failed to set bridge IP: %v", err)
		}
	}

	return br, nil
}

// configureInterface takes the result of IPAM plugin and
// applies to the ifName interface
func configureInterface(ifName string, res *types.Result) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	// TODO(eyakubovich): IPv6
	addr := &netlink.Addr{IPNet: &res.IP4.IP, Label: ""}
	if err = netlink.AddrAdd(link, addr); err != nil {
		if err.Error() == "file exists" {
			logrus.Infof("rancher-cni-bridge: Interface %q already has IP address: %v, no worries", ifName, addr)
		} else {
			return fmt.Errorf("failed to add IP addr to %q: %v", ifName, err)
		}
	}

	for _, r := range res.IP4.Routes {
		gw := r.GW
		if gw == nil {
			gw = res.IP4.Gateway
		}
		if err = ip.AddRoute(&r.Dst, gw, link); err != nil {
			// we skip over duplicate routes as we assume the first one wins
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%v via %v dev %v': %v", r.Dst, gw, ifName, err)
			}
		}
	}

	return nil
}

func checkIfContainerInterfaceExists(args *skel.CmdArgs) bool {
	err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		_, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
		}
		return nil
	})

	if err == nil {
		return true
	}
	return false
}

func setInterfaceMacAddress(ifName, mac string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	hwaddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("failed to parse MAC address: %v", err)
	}
	err = netlink.LinkSetHardwareAddr(link, hwaddr)
	if err != nil {
		return fmt.Errorf("failed to set hw address of interface: %v", err)
	}

	return nil
}

func findMACAddressForContainer(containerID, rancherID string) (string, error) {
	var mf macfinder.MACFinder
	metadataAddress := os.Getenv("RANCHER_METADATA_ADDRESS")
	mf, err := metadata.NewMACFinderFromMetadata(metadataAddress)
	if err != nil {
		return "", err
	}
	macString := mf.GetMACAddress(containerID, rancherID)
	if macString == "" {
		return "", fmt.Errorf("No MAC address found")
	}

	return macString, nil
}
