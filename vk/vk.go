package vk

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
)

var (
	cpu = resource.MustParse("10")
 memory = resource.MustParse("1000M")
 disk = resource.MustParse("10G")
)
type Vk struct {
	router *mux.Router
	lastStateTransitionTime metav1.Time
}

func (vk *Vk) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vk.router.ServeHTTP(w, r)
}

func NewVk() *Vk {
	vk :=  &Vk{
		lastStateTransitionTime: metav1.Now(),
		router:  mux.NewRouter(),
	}
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	vk.router.NotFoundHandler = simpleMw(notFoundHandler)
	vk.router.Use(simpleMw)

	vk.router.HandleFunc("/createPod", vk.createPod)
	vk.router.HandleFunc("/updatePod", vk.updatePod)
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

	return vk
}

type responseWriter struct {
	statusCode int
	w http.ResponseWriter
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
	w.WriteHeader(503)
	w.Write([]byte("Not implemented"))
}

func (vk *Vk) deletePod(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(503)
	w.Write([]byte("Not implemented"))
}

func (vk *Vk) updatePod(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(503)
	w.Write([]byte("Not implemented"))
}

func (vk *Vk) getPod(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(503)
	w.Write([]byte("Not implemented"))
}

func (vk *Vk) getPodStatus(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(503)
	w.Write([]byte("Not implemented"))
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
	return []v1.Pod{}, nil
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