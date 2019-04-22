package main

import (
	"context"
	"github.com/Netflix/titus-executor/vk"
	"github.com/hashicorp/go-plugin"
	"github.com/virtual-kubelet/virtual-kubelet/providers/plugin/proto"
	"github.com/virtual-kubelet/virtual-kubelet/providers/plugin/shared"
	"google.golang.org/grpc"
)

var (
	_ plugin.GRPCPlugin = (*exampleProviderPlugin)(nil)
)

func main() {
	p, err := vk.NewVk()
	if err != nil {
		panic(err)
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.HandshakeConfig("titus"),
		VersionedPlugins: map[int]plugin.PluginSet{
			shared.VersionWithFeatures(1): map[string]plugin.Plugin{
				shared.ProviderPluginName: &exampleProviderPlugin{vk: p},
			},
		},
		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,

	})
}

type exampleProviderPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	vk *vk.Vk
}

func (p *exampleProviderPlugin) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (interface{}, error) {
	panic("Plugin does not implement client")
}

func (p *exampleProviderPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterProviderServer(s, p.vk)
	return nil
}