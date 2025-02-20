package loader

var Hooks = map[string]bool{
	"to_container_pre_ct_v4":   true,
	"from_container_pre_ct_v4": true,
	"from_netdev_ipv4":         true,
}
