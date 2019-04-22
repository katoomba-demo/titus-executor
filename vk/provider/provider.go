package provider

import (
	"context"
	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"io"
	"k8s.io/api/core/v1"
	"time"

)

var (
	_ providers.Provider = (*Provider)(nil)
)

type Provider struct {
	nodename                string
	pods                    map[podKey]v1.Pod
}

func (p *Provider) CreatePod(ctx context.Context, pod *v1.Pod) error {
	pk := podKeyFromPod(pod)
	p.pods[pk] = pod

	return nil
}

func (p *Provider) UpdatePod(ctx context.Context, pod *v1.Pod) error {
	panic("implement me")
}

func (p *Provider) DeletePod(ctx context.Context, pod *v1.Pod) error {
	panic("implement me")
}

func (p *Provider) GetPod(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	panic("implement me")
}

func (p *Provider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, tail int) (string, error) {
	panic("implement me")
}

func (p *Provider) ExecInContainer(name string, uid interface{}, container string, cmd []string, in io.Reader, out, err io.WriteCloser, tty bool, resize <-chan interface{}, timeout time.Duration) error {
	panic("implement me")
}

func (p *Provider) GetPodStatus(ctx context.Context, namespace, name string) (*v1.PodStatus, error) {
	panic("implement me")
}

func (p *Provider) GetPods(context.Context) ([]*v1.Pod, error) {
	panic("implement me")
}

func (p *Provider) Capacity(context.Context) v1.ResourceList {
	panic("implement me")
}

func (p *Provider) NodeConditions(context.Context) []v1.NodeCondition {
	panic("implement me")
}

func (p *Provider) NodeAddresses(context.Context) []v1.NodeAddress {
	panic("implement me")
}

func (p *Provider) NodeDaemonEndpoints(context.Context) *v1.NodeDaemonEndpoints {
	panic("implement me")
}

func (p *Provider) OperatingSystem() string {
	panic("implement me")
}

func NewProvider(nodename string) (*Provider, error) {
	return &Provider{
		pods: make(map[podKey]v1.Pod),
	}, nil
}

func podKeyFromPod(pod *v1.Pod) podKey {
	return podKey{
		namespace: pod.GetNamespace(),
		name: pod.GetName(),
	}
}

type podKey struct {
	namespace string
	name string
}

/*

func (vk *Provider) CreatePod(ctx context.Context, cpr *proto.CreatePodRequest) (*proto.CreatePodResponse, error) {
	pk := podKeyFromPod(cpr.GetPod())
	vk.pods[pk] = cpr.GetPod()

	return &proto.CreatePodResponse{}, nil
}

func (vk *Provider) UpdatePod(ctx context.Context, upr *proto.UpdatePodRequest) (*proto.UpdatePodResponse, error) {
	// TODO: Merge
	pk := podKeyFromPod(upr.GetPod())
	vk.pods[pk] = upr.GetPod()

	return &proto.UpdatePodResponse{}, nil

}

func (vk *Provider) DeletePod(ctx context.Context, dpr *proto.DeletePodRequest) (*proto.DeletePodResponse, error) {
	pk := podKeyFromPod(dpr.GetPod())
	_, ok := vk.pods[pk]
	if !ok {
		return &proto.DeletePodResponse{}, nil
	}

	return nil, errors.New("Cannot delete pod")
}

func (vk *Provider) GetPod(ctx context.Context, gp *proto.GetPodRequest) (*proto.GetPodResponse, error) {
	pk := podKey{name: gp.GetName(), namespace: gp.GetNamespace()}
	pod, ok := vk.pods[pk]
	if !ok {
		return nil, fmt.Errorf("Cannot find pod: %s", gp.GetName())
	}

	return &proto.GetPodResponse{Pod: pod}, nil
}

func (vk *Provider) GetContainerLogs(context.Context, *proto.GetContainerLogsRequest) (*proto.GetContainerLogsResponse, error) {
	panic("implement me")
}

func (vk *Provider) GetPodStatus(ctx context.Context, gpsr *proto.GetPodStatusRequest) (*proto.GetPodStatusResponse, error) {
	pk := podKey{name: gpsr.GetName(), namespace: gpsr.GetNamespace()}
	pod, ok := vk.pods[pk]
	if !ok {
		return nil, fmt.Errorf("Cannot find pod: %s", gpsr.GetName())
	}

	return &proto.GetPodStatusResponse{
		Status: &pod.Status,
	}, nil
}

func (vk *Provider) GetPods(context.Context, *proto.GetPodsRequest) (*proto.GetPodsResponse, error) {
	resp := make([]*v1.Pod, 0, len(vk.pods))
	for podKey := range vk.pods {
		resp = append(resp, vk.pods[podKey])
	}
	return &proto.GetPodsResponse{
		Pods: resp,
	}, nil
}

func (vk *Provider) Capacity(context.Context, *proto.CapacityRequest) (*proto.CapacityResponse, error) {
	resp := &proto.CapacityResponse{}

	cpu := resource.MustParse(strconv.Itoa(runtime.NumCPU()))

	resp.ResourceList = map[string]string{
		string(v1.ResourceCPU): (&cpu).String(),
		string(v1.ResourceMemory): (&memory).String(),
		string(v1.ResourceStorage): (&disk).String(),
	}

	mesosResources := os.Getenv("MESOS_RESOURCES")
	if mesosResources == "" {
		logrus.Warning("Cannot fetch mesos resources")
		return resp, nil
	}

	for _, r := range strings.Split(mesosResources, ";") {
		resourceKV := strings.SplitN(r, ":", 2)
		if len(resourceKV) != 2 {
			panic(fmt.Sprintf("Cannot parse resource: %s", r))
		}
		switch resourceKV[0] {
		case "mem":
			res := resource.MustParse(resourceKV[1])
			resp.ResourceList[string(v1.ResourceMemory)] = (&res).String()
		case "disk":
			res := resource.MustParse(resourceKV[1])
			resp.ResourceList[string(v1.ResourceStorage)] = (&res).String()
		case "network":
			res := resource.MustParse(resourceKV[1])
			resp.ResourceList["network"] = (&res).String()
		}
	}

	return resp, nil
}

func (vk *Provider) nodeCondition(ready bool) *v1.NodeCondition {
	if ready {
		return &v1.NodeCondition{

			Type:               "Ready",
			Status:             v1.ConditionTrue,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: vk.lastStateTransitionTime,
			Reason:             "KubeletReady",
			Message:            "kubelet is ready.",

		}
	}
	return &v1.NodeCondition{

		Type:               "Ready",
		Status:             v1.ConditionFalse,
		LastHeartbeatTime:  metav1.Now(),
		LastTransitionTime: vk.lastStateTransitionTime,
		Reason:             "KubeletReady",
		Message:            "kubelet is waiting to maintain.",
	}
}
func (vk *Provider) NodeConditions(context.Context, *proto.NodeConditionsRequest) (*proto.NodeConditionsResponse, error) {
	return &proto.NodeConditionsResponse{
		// TODO: Fix this
		NodeConditions: []*v1.NodeCondition{vk.nodeCondition(true)},
	}, nil
}

func (vk *Provider) NodeAddresses(context.Context, *proto.NodeAddressesRequest) (*proto.NodeAddressesResponse, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.Errorf("Did not find addresses for node %s", hostname)
	}

	nodeAddresses := []*v1.NodeAddress{
		{
			Type: v1.NodeHostName,
			Address: hostname,
		},
	}

	for _, addr := range addrs {
		nodeAddresses = append(nodeAddresses, &v1.NodeAddress{
			Type: v1.NodeInternalIP,
			Address: addr,
		})
	}

	return &proto.NodeAddressesResponse{
		NodeAddresses: nodeAddresses,
	}, nil
}

func (vk *Provider) NodeDaemonEndspoints(context.Context, *proto.NodeDaemonEndpointsRequest) (*proto.NodeDaemonEndpointsResponse, error) {
	return &proto.NodeDaemonEndpointsResponse{
		NodeDaemonEndpoints:&v1.NodeDaemonEndpoints{
			KubeletEndpoint: v1.DaemonEndpoint{
				Port: vk.daemonEndpointPort,
			},
		},
	}, nil
}

func (vk *Provider) OperatingSystem(context.Context, *proto.OperatingSystemRequest) (*proto.OperatingSystemResponse, error) {
	return &proto.OperatingSystemResponse{
		OperatingSystem: "Linux",
	}, nil
}
*/



