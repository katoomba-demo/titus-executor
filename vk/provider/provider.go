package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/uploader"
	proto "github.com/golang/protobuf/proto"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/pkg/errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"github.com/virtual-kubelet/virtual-kubelet/providers/register"
	"io"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/remotecommand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	_ providers.Provider = (*Provider)(nil)
	cpu = resource.MustParse("10")
	memory = resource.MustParse("1000M")
	disk = resource.MustParse("10G")

)

type runtimePod struct {
	pod *v1.Pod
	runner *runner.Runner
}

func state2phase(state titusdriver.TitusTaskState) v1.PodPhase {
	switch state {
	case titusdriver.Starting:
		return v1.PodPending
	case titusdriver.Running:
		return v1.PodRunning
	case titusdriver.Finished:
		return v1.PodSucceeded
	case titusdriver.Failed:
		return v1.PodFailed
	case titusdriver.Killed:
		return v1.PodSucceeded
	case titusdriver.Lost:
		return v1.PodUnknown
	default:
		panic(state)
	}
}

func (rp *runtimePod) start() {
	for {
		select {
		case update := <-rp.runner.UpdatesChan:
			rp.pod.Status.Message = update.Mesg
			if update.Details != nil {
				rp.pod.Status.PodIP = update.Details.NetworkConfiguration.IPAddress
			}
			rp.pod.Status.Reason = update.State.String()
			rp.pod.Status.Phase = state2phase(update.State)
			logrus.WithField("update", update).WithField("status", rp.pod.Status).Info("Processing update")

		case <-rp.runner.StoppedChan:
			return
		}
	}
}

func (rp *runtimePod) kill() {
	rp.runner.Kill()
}

type Provider struct {
	nodename                string
	pods                    map[string]map[string]*runtimePod
	lastStateTransitionTime metav1.Time
	daemonEndpointPort int32
	config *config.Config
	dockerCfg *docker.Config
}

func (p *Provider) getPod(ctx context.Context, namespace, name string) *runtimePod {
	_, ok := p.pods[namespace]
	if !ok {
		p.pods[namespace] = map[string]*runtimePod{}
	}
	return p.pods[namespace][name]
}

func (p *Provider) deletePod(ctx context.Context, pod *v1.Pod) {
	ns, ok := p.pods[pod.GetNamespace()]
	if !ok {
		return
	}
	delete(ns, pod.GetName())
}

func (p *Provider) CreatePod(ctx context.Context, pod *v1.Pod) error {
	_, ok := p.pods[pod.GetNamespace()]
	if !ok {
		p.pods[pod.GetNamespace()] = map[string]*runtimePod{}
	}

	rp := &runtimePod{
		pod: pod,
	}
	containerInfoStr, ok := pod.GetAnnotations()["containerInfo"]
	if !ok {
		return errors.New("Cannot find container info")
	}
	data, err := base64.StdEncoding.DecodeString(containerInfoStr)
	if err != nil {
		return errors.Wrap(err, "Could not decode containerInfo from base64")
	}
	var containerInfo titus.ContainerInfo

	err = proto.Unmarshal(data, &containerInfo)
	if err != nil {
		return errors.Wrap(err, "Could not deserialize protobuf")
	}

	runtimeCtx := context.Background()
	runtimeCtx = log.WithLogger(ctx, log.G(ctx))

//	runtime := func(ctx context.Context, cfg config.Config) (runtimeTypes.Runtime, error) {
//		return &runtimeMock{
//			ctx: runtimeCtx,
//		}, nil
//	}
//	rp.runner, err = runner.WithRuntime(runtimeCtx, metrics.Discard, runtime, &uploader.Uploaders{}, *cfg)
	rp.runner, err = runner.New(runtimeCtx, metrics.Discard, &uploader.Uploaders{}, *p.config, *p.dockerCfg)
	if err != nil {
		return errors.Wrap(err, "Could not initialize runtime")
	}

	requests := pod.Spec.Containers[0].Resources.Requests
	disk := requests["titus/disk"]
	cpu := requests["cpu"]
	memory := requests["memory"]

	go rp.start()
	err = rp.runner.StartTask(pod.GetName(), &containerInfo, memory.Value(), cpu.Value(), uint64(disk.Value()))
	if err != nil {
		return errors.Wrap(err, "Could not start task")
	}

	p.pods[pod.GetNamespace()][pod.GetName()] = rp

	return nil
}

func (p *Provider) UpdatePod(ctx context.Context, pod *v1.Pod) error {
	// TODO: Merge
	log.G(ctx).Info("Got asked to make pod update?")
	return errors.New("Backend does not support pod updates")
}

func (p *Provider) DeletePod(ctx context.Context, pod *v1.Pod) error {
	if rp := p.getPod(ctx, pod.GetNamespace(), pod.GetName()); rp == nil {
		return fmt.Errorf("Pod %s/%s not found", pod.Namespace, pod.Name)
	} else {
		rp.runner.Kill()
	}

	return nil
}

func (p *Provider) GetPod(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	pod := p.getPod(ctx, namespace, name)
	if pod == nil {
		return nil, fmt.Errorf("Pod %s/%s not found", namespace, name)
	}
	return pod.pod, nil
}

func (p *Provider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, tail int) (string, error) {
	panic("implement me")
}

func (p *Provider) ExecInContainer(string, types.UID, string, []string, io.Reader, io.WriteCloser, io.WriteCloser, bool, <-chan remotecommand.TerminalSize, time.Duration) error {
	panic("implement me")
}

func (p *Provider) GetPodStatus(ctx context.Context, namespace, name string) (*v1.PodStatus, error) {
	pod := p.getPod(ctx, namespace, name)
	if pod == nil {
		return nil, fmt.Errorf("Pod %s/%s not found", namespace, name)
	}
	return &pod.pod.Status, nil
}

func (p *Provider) GetPods(context.Context) ([]*v1.Pod, error) {
	resp := make([]*v1.Pod, 0, len(p.pods))
	for _, ns := range p.pods {
		for _, p := range ns {
			resp = append(resp, p.pod)
		}
	}
	return resp, nil
}

func (p *Provider) Capacity(ctx context.Context) v1.ResourceList {
	resourceList := v1.ResourceList{
		v1.ResourceCPU:     (cpu),
		v1.ResourceMemory:  (memory),
		v1.ResourceStorage: (disk),
	}

	mesosResources := os.Getenv("MESOS_RESOURCES")
	if mesosResources == "" {
		log.G(ctx).Warn("Cannot fetch mesos resources")
		return resourceList
	}

	for _, r := range strings.Split(mesosResources, ";") {
		resourceKV := strings.SplitN(r, ":", 2)
		if len(resourceKV) != 2 {
			panic(fmt.Sprintf("Cannot parse resource: %s", r))
		}
		switch resourceKV[0] {
		case "mem":
			resourceList[v1.ResourceMemory] = resource.MustParse(resourceKV[1])
		case "disk":
			resourceList[v1.ResourceStorage] = resource.MustParse(resourceKV[1])
		case "network":
			resourceList["network"] = resource.MustParse(resourceKV[1])
		}
	}

	return resourceList
}

func (p *Provider) NodeConditions(context.Context) []v1.NodeCondition {
	return []v1.NodeCondition{
		{
			Type:               "Ready",
			Status:             v1.ConditionTrue,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: p.lastStateTransitionTime,
			Reason:             "KubeletReady",
			Message:            "kubelet is ready.",
		},
	}
}

func (p *Provider) NodeAddresses(ctx context.Context) []v1.NodeAddress {
	nodeAddresses := []v1.NodeAddress{}

	hostname, err := os.Hostname()
	if err != nil {
		log.G(ctx).WithError(err).Warn("Cannot get hostname")
		return nodeAddresses
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		log.G(ctx).WithError(err).Warn("Cannot resolve hostname")
		return nodeAddresses
	}
	if len(addrs) == 0 {
		log.G(ctx).Warn("Zero node addresses found")
		return nodeAddresses
	}

	for _, addr := range addrs {
		nodeAddresses = append(nodeAddresses, v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: addr,
		})
	}

	return nodeAddresses
}

func (p *Provider) NodeDaemonEndpoints(context.Context) *v1.NodeDaemonEndpoints {
	return &v1.NodeDaemonEndpoints{
		KubeletEndpoint: v1.DaemonEndpoint{
			Port: p.daemonEndpointPort,
		},
	}
}

func (p *Provider) OperatingSystem() string {
	return "Linux"
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(p.pods)
}

func NewProvider(config register.InitConfig, cfg *config.Config, dockerCfg *docker.Config) (*Provider, error) {
	p := &Provider{
		pods: make(map[string]map[string]*runtimePod),
		lastStateTransitionTime: metav1.Now(),
		daemonEndpointPort: config.DaemonPort,
		config: cfg,
		dockerCfg: dockerCfg,
	}

	srv := http.Server{
		Addr: "0.0.0.0:5656",
		Handler: p,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logrus.WithError(err).Fatal("Backend server failed")
		}
	}()
	return p, nil
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



