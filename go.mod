module github.com/Netflix/titus-executor

go 1.12

replace github.com/docker/docker => github.com/docker/engine v0.0.0-20190408150954-50ebe4562dfc

replace github.com/virtual-kubelet/virtual-kubelet => github.com/sargun/virtual-kubelet v0.9.1-0.20190422220937-dcfeb5700728

require (
	contrib.go.opencensus.io/exporter/ocagent v0.4.12 // indirect
	github.com/Microsoft/go-winio v0.3.8 // indirect
	github.com/Netflix/metrics-client-go v0.0.0-20171019173821-bb173f41fc07
	github.com/Netflix/titus-api-definitions v0.0.0-20190122230735-8229582b5675
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v0.0.0-20190409004728-b115ca0f9053 // indirect
	github.com/apparentlymart/go-cidr v0.0.0-20170616213631-2bd8b58cf427
	github.com/aws/aws-sdk-go v1.19.15
	github.com/coreos/go-systemd v0.0.0-20180511133405-39ca1b05acc7
	github.com/cpuguy83/strongerrors v0.2.1
	github.com/cyphar/filepath-securejoin v0.0.0-20190205144030-7efe413b52e1
	github.com/deckarep/golang-set v0.0.0-20180603214616-504e848d77ea
	github.com/docker/distribution v0.0.0-20170303212246-08b06dc02367 // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.3.0
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff
	github.com/godbus/dbus v4.1.0+incompatible // indirect
	github.com/gogo/protobuf v1.2.1
	github.com/golang/glog v0.0.0-20170312005925-543a34c32e4d // indirect
	github.com/golang/protobuf v1.3.1
	github.com/gorilla/mux v1.6.2
	github.com/gregjones/httpcache v0.0.0-20190212212710-3befbb6ad0cc // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v0.0.0-20171204182908-b7773ae21874
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/leanovate/gopter v0.0.0-20170420174722-9e6101e5a875
	github.com/mesos/mesos-go v0.0.0-20161004192122-7228b13084ce
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc0 // indirect
	github.com/opencontainers/image-spec v0.0.0-20190321123305-da296dcb1e47 // indirect
	github.com/opencontainers/runc v0.0.0-20180125150909-c4e4bb0df2fc
	github.com/opencontainers/runtime-spec v1.0.1 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.8.0
	github.com/sirupsen/logrus v1.2.0
	github.com/spf13/cobra v0.0.3 // indirect
	github.com/spf13/pflag v1.0.3 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/virtual-kubelet/virtual-kubelet v0.0.0-00010101000000-000000000000
	github.com/vishvananda/netlink v0.0.0-20180205182215-a2af46a09c21
	github.com/vishvananda/netns v0.0.0-20160430053723-8ba1072b58e0
	github.com/wercker/journalhook v0.0.0-20180428041537-5d0a5ae867b3
	golang.org/x/sync v0.0.0-20190227155943-e225da77a7e6
	golang.org/x/sys v0.0.0-20190312061237-fead79001313
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	google.golang.org/grpc v1.20.1 // indirect
	gopkg.in/alessio/shellescape.v1 v1.0.0-20170105083845-52074bc9df61
	gopkg.in/urfave/cli.v1 v1.20.0
	k8s.io/api v0.0.0-20190418212532-b8e4ab4b136a
	k8s.io/apimachinery v0.0.0-20190418212431-b3683fe6b520
	k8s.io/apiserver v0.0.0-20190418213308-0a718f081a3a // indirect
	k8s.io/client-go v0.0.0-20190418212717-1d2e9628a1ee
	k8s.io/kubernetes v1.14.1 // indirect
	k8s.io/utils v0.0.0-20190308190857-21c4ce38f2a7 // indirect
)
