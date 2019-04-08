package vk

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"net/http"
	"os"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
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
	router *mux.Router
	lastStateTransitionTime metav1.Time
	hostname string
	pods map[podKey]pod
}

func (vk *Vk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vk.router.ServeHTTP(w, r)
}

func (vk *Vk) Maintain(ctx context.Context) error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	go vk.maintain(ctx, clientset)

	return nil
}

func (vk *Vk) maintain(ctx context.Context, clientset *kubernetes.Clientset) {
	nodesClient := clientset.CoreV1().Nodes() // TODO: Maybe use a different namespace?
	nodename := strings.ToLower(vk.hostname)
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
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := nodesClient.Get(nodename, metav1.GetOptions{})
		if err != nil {
			return errors.Wrap(err, "Unable to get node")
		}

		node.Annotations["com.netflix.titus/proveThatICanSetAnnotations"] = "yep"
		_, err = nodesClient.Update(node)
		return err
	})
	if retryErr != nil {
		logrus.WithError(retryErr).Fatal("Could not update node")
	}
	logrus.Info("Updated node")
}

func NewVk() (*Vk, error) {
	vk :=  &Vk{
		lastStateTransitionTime: metav1.Now(),
		router:  mux.NewRouter(),
		pods: make(map[podKey]pod),
	}
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	vk.router.NotFoundHandler = simpleMw(notFoundHandler)
	vk.router.Use(simpleMw)

	vk.router.HandleFunc("/createPod", vk.createPod).Methods("POST")
	vk.router.HandleFunc("/updatePod", vk.updatePod).Methods("PUT")
	vk.router.HandleFunc("/deletePod", vk.deletePod)
	vk.router.Path("/getPod").
		Queries("namespace", "{namespace}").
		Queries("name", "{name}").HandlerFunc(vk.getPod)
	vk.router.Path("/getPodStatus").
		Queries("namespace", "{namespace}").
		Queries("name", "{name}").HandlerFunc(vk.getPodStatus)
	vk.router.HandleFunc("/getPods", vk.getPods)
	vk.router.HandleFunc("/capacity", vk.capacity)
	vk.router.HandleFunc("/nodeConditions", vk.nodeConditions)
	vk.router.HandleFunc("/nodeAddresses", vk.nodeAddresses)

	if hostname, err := os.Hostname(); err != nil {
		return nil, err
	} else {
		vk.hostname = hostname
	}
	return vk, nil
}

type responseWriter struct {
	statusCode int
	w http.ResponseWriter
}

type podKey struct {
	namespace string
	name string
}

type pod struct {
	pod v1.Pod
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.w.Write(data)
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.w.WriteHeader(statusCode)
}
func (rw *responseWriter) Header() http.Header {
	return rw.w.Header()
}

func simpleMw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		entry := logrus.WithFields(map[string]interface{}{
			"method":     r.Method,
			"url":        r.URL.String(),
			"requestURI": r.RequestURI,
			"remoteAddr": r.RemoteAddr,
		})
		rw := &responseWriter{
				w: w,
		}
		next.ServeHTTP(rw, r)
		entry.WithField("statusCode", rw.statusCode).Info()
	})
}

func (vk *Vk) createPod(w http.ResponseWriter, r *http.Request) {
	var newPod v1.Pod
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&newPod)
	if err != nil {
		logrus.WithError(err).Error("Failed to deserialize pod")
		w.WriteHeader(503)
		w.Write([]byte(fmt.Sprintf("Cannot deserialize pod: %s", err.Error())))
		return
	}

	vk.pods[podKey{newPod.Namespace, newPod.Name}] = pod{pod:newPod}
}



func (vk *Vk) doCreatePod(namespace, name string) (*v1.Pod, error) {
	pk := podKey{namespace:namespace, name: name}
	_, ok := vk.pods[pk]
	if !ok {
		return nil, nil
	}

	return nil, errors.New("Cannot delete pod")
}

func (vk *Vk) deletePod(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var err error
	pod, err := vk.doDeletePod(vars["namespace"], vars["name"])
	if err != nil {
		goto fail
	}
	if pod == nil {
		w.WriteHeader(404)
		w.Write([]byte("Pod not found"))
		return
	}
	err = json.NewEncoder(w).Encode(pod)
	if err != nil {
		goto fail
	}
	return
fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}


func (vk *Vk) doDeletePod(namespace, name string) (*v1.Pod, error) {
	pk := podKey{namespace:namespace, name: name}
	p, ok := vk.pods[pk]
	if !ok {
		return nil, nil
	}

	delete(vk.pods, pk)

	return &p.pod, nil
}

func (vk *Vk) updatePod(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logrus.Info(vars)
	w.WriteHeader(503)
	w.Write([]byte("Not implemented"))
}

func (vk *Vk) getPod(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var err error
	pod, err := vk.doGetPod(vars["namespaces"], vars["name"])
	if err != nil {
		goto fail
	}
	if pod == nil {
		w.WriteHeader(404)
		w.Write([]byte("Pod not found"))
		return
	}
	err = json.NewEncoder(w).Encode(pod)
	if err != nil {
		goto fail
	}
	return
fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}

func (vk *Vk) doGetPod(namespace, name string) (*v1.Pod, error) {
	pk := podKey{namespace:namespace, name: name}
	p, ok := vk.pods[pk]
	if !ok {
		return nil, nil
	}

	return &p.pod, nil
}

func (vk *Vk) getPodStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var err error
	podStatus, err := vk.doGetPodStatus(vars["namespace"], vars["name"])
	if err != nil {
		goto fail
	}
	if podStatus == nil {
		w.WriteHeader(404)
		w.Write([]byte("Pod not found"))
		return
	}
	err = json.NewEncoder(w).Encode(podStatus)
	if err != nil {
		goto fail
	}
	return
fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}

func (vk *Vk) doGetPodStatus(namespace, name string) (*v1.PodStatus, error) {
	pk := podKey{namespace:namespace, name: name}
	_, ok := vk.pods[pk]
	if !ok {
		logrus.WithField("namespace", namespace).WithField("name", name).Info("Cannot find pod")
		return nil, nil
	}

	ps := &v1.PodStatus{
		Phase: v1.PodPending,
		// How does this differ from Phase?
		Conditions: []v1.PodCondition{},
		Message: "Because sargun hasn't wired up the requisite logic to handle this yet",
		Reason: "NotYetImplemented",
	}
	return ps, nil
}

func (vk *Vk) getPods(w http.ResponseWriter, r *http.Request) {
	var err error
	pods, err := vk.doGetPods()
	if err != nil {
		goto fail
	}
	err = json.NewEncoder(w).Encode(pods)
	if err != nil {
		goto fail
	}
	return
	fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}

func (vk *Vk) doGetPods() ([]v1.Pod, error) {
	logrus.Info(vk.pods)
	ret := []v1.Pod{}
	for _, pod := range vk.pods {
		ret = append(ret, pod.pod)
	}
	return ret, nil
}

func (vk *Vk) capacity(w http.ResponseWriter, r *http.Request) {
	var err error
	pods, err := vk.doCapacity()
	if err != nil {
		goto fail
	}
	err = json.NewEncoder(w).Encode(pods)
	if err != nil {
		goto fail
	}
	return
fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}


func (vk *Vk) doCapacity() (v1.ResourceList, error) {
	return map[v1.ResourceName]resource.Quantity{
		v1.ResourceCPU: cpu,
		v1.ResourceMemory: memory,
		v1.ResourceStorage: disk,

	}, nil
}

func (vk *Vk) nodeConditions(w http.ResponseWriter, r *http.Request) {
	var err error
	nodeConditions, err := vk.doNodeConditions()
	if err != nil {
		goto fail
	}
	err = json.NewEncoder(w).Encode(nodeConditions)
	if err != nil {
		goto fail
	}
	return
fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}

func (vk *Vk) doNodeConditions() ([]v1.NodeCondition, error) {
	return []v1.NodeCondition{
		{
			Type:               "Ready",
			Status:             v1.ConditionTrue,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: vk.lastStateTransitionTime,
			Reason:             "KubeletReady",
			Message:            "kubelet is ready.",
		},
	}, nil
}

func (vk *Vk) nodeAddresses(w http.ResponseWriter, r *http.Request) {
	var err error
	nodeAddresses, err := vk.doNodeAddresses()
	if err != nil {
		goto fail
	}
	err = json.NewEncoder(w).Encode(nodeAddresses)
	if err != nil {
		goto fail
	}
	return
fail:
	w.WriteHeader(503)
	w.Write([]byte(err.Error()))
}


func (vk *Vk) doNodeAddresses() ([]v1.NodeAddress, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
     }
	return []v1.NodeAddress{
		{
			Type: v1.NodeHostName,
			Address: hostname,
		},
	}, nil
}