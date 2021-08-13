package cmd

import (
	flag "github.com/spf13/pflag"

	"github.com/liqotech/liqo/pkg/liqoctl/install/aks"
	"github.com/liqotech/liqo/pkg/liqoctl/install/eks"
	"github.com/liqotech/liqo/pkg/liqoctl/install/kubeadm"
)

var providers = []string{"kubeadm", "eks", "aks"}

var providerInitFunc = map[string]func(*flag.FlagSet){
	"kubeadm": kubeadm.GenerateFlags,
	"eks":     eks.GenerateFlags,
	"aks":     aks.GenerateFlags,
}
