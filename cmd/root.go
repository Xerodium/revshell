/*
Copyright © 2026 hi@maxfrancis.me
*/
package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"strconv"

	"math/rand/v2"
	"charm.land/huh/v2"
	"github.com/spf13/cobra"
)

type tunnelAddress struct {
	label string
	ip    string
}

func selectTunnelAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list network interfaces: %w", err)
	}

	var addresses []tunnelAddress

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		ifaceAddresses, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf(
				"get addresses for interface %s: %w",
				iface.Name,
				err,
			)
		}

		for _, address := range ifaceAddresses {
			ip := addressIP(address)
			if ip == nil || ip.IsLoopback() {
				continue
			}

			if ip.To4() == nil {
				continue
			}

			addresses = append(addresses, tunnelAddress{
				label: fmt.Sprintf("%s (%s)", iface.Name, ip.String()),
				ip:    ip.String(),
			})
		}
	}

	if len(addresses) == 0 {
		return "", fmt.Errorf("no active tunnel interfaces with IPv4 addresses found")
	}

	sort.Slice(addresses, func(i, j int) bool {
		return addresses[i].label < addresses[j].label
	})

	options := make([]huh.Option[string], 0, len(addresses))
	for _, address := range addresses {
		options = append(
			options,
			huh.NewOption(address.label, address.ip),
		)
	}

	var selectedIP string

	err = huh.NewSelect[string]().
		Title("Select a tunnel interface").
		Options(options...).
		Value(&selectedIP).
		Run()
	if err != nil {
		return "", fmt.Errorf("select tunnel interface: %w", err)
	}

	return selectedIP, nil
} 

func selectTunnelPort() (string, error) {
	selectedPort := rand.IntN(999) + 9000
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(selectedPort))
	if err != nil {
		return "", fmt.Errorf("Port unavailable:", err)
	}
	defer listener.Close()

	return strconv.Itoa(selectedPort), nil
}

func addressIP(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func isTunnelInterface(name string) bool {
	name = strings.ToLower(name)

	prefixes := []string{
		"tun",
		"tap",
		"wg",
		"utun",
		"ppp",
		"ipsec",
		"tailscale",
		"zt",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "revshell",
	Short: "Stupidly easy reverse shell generator and listener setup",
	Args:  cobra.NoArgs,

	RunE: func(cmd *cobra.Command, args []string) error {
		selectedIP, err := selectTunnelAddress()
		if err != nil {
			return fmt.Errorf("select tunnel address: %w", err)
		}

		fmt.Fprintf(
			cmd.OutOrStdout(),
			"Selected tunnel address: %s\n",
			selectedIP,
		)

		selectedPort, err := selectTunnelPort()
		fmt.Fprintf(
			cmd.OutOrStdout(),
			"Selected port: %s\n",
			selectedPort,
		)

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.revshell.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
