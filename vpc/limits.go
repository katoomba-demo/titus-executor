package vpc

import (
	"fmt"
	"strings"
)

type limits struct {
	interfaces              int
	ipAddressesPerInterface int
	// in Mbps
	networkThroughput int
}

var interfaceLimits = map[string]map[string]limits{
	"m4": {
		"large": limits{
			interfaces:              2,
			ipAddressesPerInterface: 10,
			networkThroughput:       100,
		},
		"xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       1000,
		},
		"2xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       1000,
		},
		"4xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       2000,
		},
		"10xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			// Is this number correct?
			networkThroughput: 10000,
		},
		"16xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       23000,
		},
	},
	"m5": {
		"large": limits{
			interfaces:              3,
			ipAddressesPerInterface: 10,
			networkThroughput:       100,
		},
		"xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       1000,
		},
		"2xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       1000,
		},
		"4xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       2000,
		},
		"12xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			// Is this number correct?
			networkThroughput: 10000,
		},
		"24xlarge": limits{
			interfaces:              15,
			ipAddressesPerInterface: 50,
			networkThroughput:       23000,
		},
		"metal": limits{
			interfaces:              15,
			ipAddressesPerInterface: 50,
			networkThroughput:       23000,
		},
	},
	"r4": {
		"large": limits{
			interfaces:              3,
			ipAddressesPerInterface: 10,
			networkThroughput:       1000,
		},
		"xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       1000,
		},
		"2xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       2000,
		},
		"4xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       4000,
		},
		"8xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       9000,
		},
		"16xlarge": limits{
			interfaces:              15,
			ipAddressesPerInterface: 24,
			networkThroughput:       23000,
		},
	},
	"r5": {
		"large": limits{
			interfaces:              3,
			ipAddressesPerInterface: 10,
			networkThroughput:       1000,
		},
		"xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       1000,
		},
		"2xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       2000,
		},
		"4xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       4000,
		},
		"12xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       9000,
		},
		"24xlarge": limits{
			interfaces:              15,
			ipAddressesPerInterface: 50,
			networkThroughput:       23000,
		},
		"metal": limits{
			interfaces:              15,
			ipAddressesPerInterface: 50,
			networkThroughput:       23000,
		},
	},
	"p2": {
		"xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			// Maybe?
			networkThroughput: 2000,
		},
		"8xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       6000,
		},
		"16xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       20000,
		},
	},
	"p3": {
		"2xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       2000,
		},
		"8xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       10000,
		},
		"16xlarge": limits{
			interfaces:              8,
			ipAddressesPerInterface: 30,
			networkThroughput:       25000,
		},
	},
	"c5": {
		"large": limits{
			interfaces:              3,
			ipAddressesPerInterface: 10,
			// Maybe?
			networkThroughput: 1000,
		},
		"xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       2000,
		},
		"2xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 15,
			networkThroughput:       2000,
		},
		"4xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 30,
			networkThroughput:       4000,
		},
		"9xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 30,
			networkThroughput:       10000,
		},
		"18xlarge": limits{
			interfaces:              4,
			ipAddressesPerInterface: 50,
			networkThroughput:       23000,
		},
	},
}

// This function will panic if the instance type is unknown
func getLimits(instanceType string) (limits, error) {
	familyAndSubtype := strings.Split(instanceType, ".")
	family := familyAndSubtype[0]
	subtype := familyAndSubtype[1]
	subtypes, ok := interfaceLimits[family]
	if !ok {
		return limits{}, fmt.Errorf("Unknown family: %q", family)
	}

	l, ok := subtypes[subtype]
	if !ok {
		return limits{}, fmt.Errorf("Unknown subtype %q for family: %q", subtype, family)
	}
	return l, nil
}

func mustGetLimits(instanceType string) limits {
	l, err := getLimits(instanceType)
	if err != nil {
		panic(err.Error())
	}
	return l
}

// GetMaxInterfaces returns the maximum number of interfaces that this instance type can handle
// includes the primary ENI
func GetMaxInterfaces(instanceType string) (int, error) {
	l, err := getLimits(instanceType)

	return l.interfaces, err
}

// GetMaxIPAddresses returns  the maximum number of IPv4 addresses that this instance type can handle
func GetMaxIPAddresses(instanceType string) (int, error) {
	l, err := getLimits(instanceType)

	return l.ipAddressesPerInterface, err
}

// GetMaxNetworkMbps returns the maximum network throughput in Megabits per second that this instance type can handle
func GetMaxNetworkMbps(instanceType string) (int, error) {
	l, err := getLimits(instanceType)

	return l.networkThroughput, err
}

// GetMaxNetworkbps returns the maximum network throughput in bits per second that this instance type can handle
func GetMaxNetworkbps(instanceType string) (uint64, error) {
	maxNetworkMbps, err := GetMaxNetworkMbps(instanceType)

	return uint64(maxNetworkMbps) * 1000 * 1000, err
}

// MustGetMaxInterfaces returns the maximum number of interfaces that this instance type can handle
// includes the primary ENI
func MustGetMaxInterfaces(instanceType string) int {
	return mustGetLimits(instanceType).interfaces
}

// MustGetMaxIPAddresses returns  the maximum number of IPv4 addresses that this instance type can handle
func MustGetMaxIPAddresses(instanceType string) int {
	return mustGetLimits(instanceType).ipAddressesPerInterface
}

// GetMaxNetworkMbps returns the maximum network throughput in Megabits per second that this instance type can handle
func MustGetMaxNetworkMbps(instanceType string) int {
	return mustGetLimits(instanceType).networkThroughput
}

// GetMaxNetworkbps returns the maximum network throughput in bits per second that this instance type can handle
func MustGetMaxNetworkbps(instanceType string) uint64 {
	return uint64(MustGetMaxNetworkMbps(instanceType)) * 1000 * 1000
}
