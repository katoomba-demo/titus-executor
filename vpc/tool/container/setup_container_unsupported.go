// +build !linux

package container

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/vishvananda/netlink"
)

func doSetupContainer(ctx context.Context, netnsfd int, bandwidth, ceil uint64, jumbo bool, allocation types.Allocation) (netlink.Link, error) {
	return nil, types.ErrUnsupported
}

func teardownNetwork(ctx context.Context, allocation types.Allocation, link netlink.Link, netnsfd int) {
}
