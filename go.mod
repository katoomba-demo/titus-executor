module github.com/Netflix/titus-executor

go 1.12

replace github.com/docker/docker => github.com/docker/engine v0.0.0-20190408150954-50ebe4562dfc

require (
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/DataDog/datadog-go v2.2.0+incompatible // indirect
	github.com/Datadog/opencensus-go-exporter-datadog v0.0.0-20190503082300-0f32ad59ab08
	github.com/Microsoft/go-winio v0.4.11 // indirect
	github.com/Netflix/metrics-client-go v0.0.0-20171019173821-bb173f41fc07
	github.com/Netflix/titus-api-definitions v0.0.1-rc46.0.20190821104755-2eaaac3afbd0
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v0.0.0-20190409004728-b115ca0f9053 // indirect
	github.com/apparentlymart/go-cidr v1.0.0
	github.com/aws/aws-sdk-go v1.20.21
	github.com/coreos/go-systemd v0.0.0-20170731111925-d21964639418
	github.com/cyphar/filepath-securejoin v0.0.0-20190205144030-7efe413b52e1
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/distribution v2.7.0+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190108045446-77df18c24acf
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.3.3
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff
	github.com/go-critic/go-critic v0.0.0-20181204210945-ee9bf5809ead // indirect
	github.com/go-sql-driver/mysql v1.4.1 // indirect
	github.com/godbus/dbus v4.1.0+incompatible // indirect
	github.com/gogo/protobuf v1.2.1
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/golang/mock v1.3.1 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/golangci/golangci-lint v1.17.1
	github.com/gorilla/mux v1.7.1
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/golang-lru v0.5.1
	github.com/jteeuwen/go-bindata v3.0.7+incompatible
	github.com/leanovate/gopter v0.0.0-20170420174722-9e6101e5a875
	github.com/lib/pq v1.2.0
	github.com/mesos/mesos-go v0.0.0-20161004192122-7228b13084ce
	github.com/myitcv/gobin v0.0.9
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v0.0.0-20180125150909-c4e4bb0df2fc
	github.com/opencontainers/runtime-spec v1.0.1 // indirect
	github.com/openzipkin/zipkin-go v0.1.6
	github.com/pborman/uuid v0.0.0-20150824212802-cccd189d45f7
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/rogpeppe/go-internal v1.3.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/soheilhy/cmux v0.1.4
	github.com/spf13/cobra v0.0.2
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.0.2
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/virtual-kubelet/virtual-kubelet v1.0.0
	github.com/vishvananda/netlink v1.0.1-0.20190618143317-99a56c251ae6
	github.com/vishvananda/netns v0.0.0-20160430053723-8ba1072b58e0
	github.com/wercker/journalhook v0.0.0-20180428041537-5d0a5ae867b3
	go.opencensus.io v0.22.0
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980 // indirect
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	golang.org/x/sys v0.0.0-20190616124812-15dcb6c0061f
	golang.org/x/tools v0.0.0-20190610231749-f8d1dee965f7
	google.golang.org/appengine v1.5.0 // indirect
	google.golang.org/genproto v0.0.0-20190605220351-eb0b1bdb6ae6 // indirect
	google.golang.org/grpc v1.21.1
	gopkg.in/DataDog/dd-trace-go.v1 v1.14.0 // indirect
	gopkg.in/alessio/shellescape.v1 v1.0.0-20170105083845-52074bc9df61
	gopkg.in/urfave/cli.v1 v1.20.0
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.0.0-20190222213804-5cb15d344471
)
