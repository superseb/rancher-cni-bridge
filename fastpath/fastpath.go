package fastpath

import (
	"context"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/docker/engine-api/client"
)

// GetMacAndIPInfo returns MAC address and IPAM Info using
// the information from docker inspect of the given container id
func GetMacAndIPInfo(cid string) (string, *types.Result, error) {
	var (
		err error
		mac string
		r   *types.Result
	)

	dClient, err := client.NewEnvClient()
	if err != nil {
		return mac, r, err
	}

	container, err := dClient.ContainerInspect(context.Background(), cid)
	if err != nil {
		return mac, r, err
	}

	mac = container.Config.Labels["io.rancher.container.mac_address"]
	if mac == "" {
		return mac, r, fmt.Errorf("couldn't find mac address label on container")
	}

	ipStringWithPrefix := container.Config.Labels["annotation.io.rancher.container.ip"]
	if ipStringWithPrefix == "" {
		ipStringWithPrefix = container.Config.Labels["io.rancher.container.ip"]
	}
	if ipStringWithPrefix == "" {
		return mac, r, fmt.Errorf("couldn't find ip address label on container")
	}

	ip, ipnet, err := net.ParseCIDR(ipStringWithPrefix)
	if err != nil {
		return mac, r, err
	}

	r = &types.Result{
		IP4: &types.IPConfig{
			IP: net.IPNet{IP: ip, Mask: ipnet.Mask},
		},
	}

	return mac, r, nil
}
