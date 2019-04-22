package vk

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/providers/plugin/proto"
	"k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	cpu = resource.MustParse("10")
 memory = resource.MustParse("1000M")
 disk = resource.MustParse("10G")
 errPodNotFound = errors.New("Pod not found")
)
type Vk struct {
	lastStateTransitionTime metav1.Time
	nodename                string
	pods                    map[podKey]*v1.Pod
	daemonEndpointPort      int32
	clientset               *kubernetes.Clientset
	ready bool
}

func addMesosAttributesAsAnnotations(annotations map[string]string) {
	mesosAttributes := os.Getenv("MESOS_ATTRIBUTES")
	if mesosAttributes == "" {
		logrus.Warn("Cannot fetch mesos attributes")
		return
	}
	for _, attribute := range strings.Split(mesosAttributes, ";")	 {
		attributeKV := strings.SplitN(attribute, ":", 2)
		if len(attributeKV) != 2 {
			panic(fmt.Sprintf("Attribute %s did not split into two parts", attribute))
		}
		annotationKey := fmt.Sprintf("com.netflix.titus.agent.attribute/%s", attributeKV[0])
		annotations[annotationKey] = attributeKV[1]
	}
}

func (vk *Vk) maintain(ctx context.Context) {
	nodesClient := vk.clientset.CoreV1().Nodes() // TODO: Maybe use a different namespace?
	nodename := vk.nodename
	for {
		_, err := nodesClient.Get(nodename, metav1.GetOptions{})
		if kerrors.IsNotFound(err) {
			logrus.WithError(err).Info("Kubelet not found")
			time.Sleep(2 * time.Second)
		} else if err != nil {
			logrus.WithError(err).Fatal("Could not fetch kubelet :(")
		} else {
			break
		}
	}

	for {
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			node, err := nodesClient.Get(nodename, metav1.GetOptions{})
			if err != nil {
				return errors.Wrap(err, "Unable to get node")
			}

			addMesosAttributesAsAnnotations(node.Annotations)
			condition := vk.nodeCondition(true)
			node.Status.Conditions = []v1.NodeCondition{*condition}
			newNode, err := nodesClient.Update(node)
			if err == nil {
				logrus.WithField("node", newNode).Info("Updated node")
			}
			return err
		})
		if retryErr != nil {
			logrus.WithError(retryErr).Fatal("Could not update node")
		} else {
			vk.ready = true
			vk.lastStateTransitionTime = metav1.Now()
			return
		}

		time.Sleep(5 * time.Second)
	}
}

func NewVk() (*Vk, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	vk :=  &Vk{
		lastStateTransitionTime: metav1.Now(),
		pods: make(map[podKey]*v1.Pod),
		clientset: clientset,
	}
	return vk, nil
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


func (vk *Vk) Register(ctx context.Context, rr *proto.ProviderRegisterRequest) (*proto.ProviderRegisterResponse, error) {
	vk.nodename = rr.GetInitConfig().NodeName
	vk.daemonEndpointPort = rr.GetInitConfig().GetDaemonPort()
	go vk.maintain(context.TODO())
	return &proto.ProviderRegisterResponse{}, nil
}

func (vk *Vk) CreatePod(ctx context.Context, cpr *proto.CreatePodRequest) (*proto.CreatePodResponse, error) {
	pk := podKeyFromPod(cpr.GetPod())

	vk.pods[pk] = cpr.GetPod()

	return &proto.CreatePodResponse{}, nil
}

func (vk *Vk) UpdatePod(ctx context.Context, upr *proto.UpdatePodRequest) (*proto.UpdatePodResponse, error) {
	// TODO: Merge
	pk := podKeyFromPod(upr.GetPod())
	vk.pods[pk] = upr.GetPod()

	return &proto.UpdatePodResponse{}, nil

}

func (vk *Vk) DeletePod(ctx context.Context, dpr *proto.DeletePodRequest) (*proto.DeletePodResponse, error) {
	pk := podKeyFromPod(dpr.GetPod())
	_, ok := vk.pods[pk]
	if !ok {
		return &proto.DeletePodResponse{}, nil
	}

	return nil, errors.New("Cannot delete pod")
}

func (vk *Vk) GetPod(ctx context.Context, gp *proto.GetPodRequest) (*proto.GetPodResponse, error) {
	pk := podKey{name: gp.GetName(), namespace: gp.GetNamespace()}
	pod, ok := vk.pods[pk]
	if !ok {
		return nil, fmt.Errorf("Cannot find pod: %s", gp.GetName())
	}

	return &proto.GetPodResponse{Pod: pod}, nil
}

func (vk *Vk) GetContainerLogs(context.Context, *proto.GetContainerLogsRequest) (*proto.GetContainerLogsResponse, error) {
	panic("implement me")
}

func (vk *Vk) GetPodStatus(ctx context.Context, gpsr *proto.GetPodStatusRequest) (*proto.GetPodStatusResponse, error) {
	pk := podKey{name: gpsr.GetName(), namespace: gpsr.GetNamespace()}
	pod, ok := vk.pods[pk]
	if !ok {
		return nil, fmt.Errorf("Cannot find pod: %s", gpsr.GetName())
	}

	return &proto.GetPodStatusResponse{
		Status: &pod.Status,
	}, nil
}

func (vk *Vk) GetPods(context.Context, *proto.GetPodsRequest) (*proto.GetPodsResponse, error) {
	resp := make([]*v1.Pod, 0, len(vk.pods))
	for podKey := range vk.pods {
		resp = append(resp, vk.pods[podKey])
	}
	return &proto.GetPodsResponse{
		Pods: resp,
	}, nil
}

func (vk *Vk) Capacity(context.Context, *proto.CapacityRequest) (*proto.CapacityResponse, error) {
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

func (vk *Vk) nodeCondition(ready bool) *v1.NodeCondition {
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
func (vk *Vk) NodeConditions(context.Context, *proto.NodeConditionsRequest) (*proto.NodeConditionsResponse, error) {
	return &proto.NodeConditionsResponse{
		// TODO: Fix this
		NodeConditions: []*v1.NodeCondition{vk.nodeCondition(true)},
	}, nil
}

func (vk *Vk) NodeAddresses(context.Context, *proto.NodeAddressesRequest) (*proto.NodeAddressesResponse, error) {
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

func (vk *Vk) NodeDaemonEndspoints(context.Context, *proto.NodeDaemonEndpointsRequest) (*proto.NodeDaemonEndpointsResponse, error) {
	return &proto.NodeDaemonEndpointsResponse{
		NodeDaemonEndpoints:&v1.NodeDaemonEndpoints{
			KubeletEndpoint: v1.DaemonEndpoint{
				Port: vk.daemonEndpointPort,
			},
		},
	}, nil
}

func (vk *Vk) OperatingSystem(context.Context, *proto.OperatingSystemRequest) (*proto.OperatingSystemResponse, error) {
	return &proto.OperatingSystemResponse{
		OperatingSystem: "Linux",
	}, nil
}


