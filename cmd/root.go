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

type WebShellType string

const (
	TargetShellTypeLinux    WebShellType = "linux"
	TargetShellTypeWindows  WebShellType = "windows"
	TargetShellTypeWebShell WebShellType = "webshell"
)

var targetShellTypeValues = []WebShellType{
	TargetShellTypeLinux,
	TargetShellTypeWindows,
	TargetShellTypeWebShell,
}

func targetShellTypeLabel(targetShellType WebShellType) string {
	switch targetShellType {
	case TargetShellTypeLinux:
		return "Linux / Unix"
	case TargetShellTypeWindows:
		return "Windows"
	case TargetShellTypeWebShell:
		return "Web Shell"
	default:
		return string(targetShellType)
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
	EncodingNone,
	EncodingBase64,
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
	Name       string
	Type       WebShellType
	Encoding   Encoding
	Template   string
	PowerShell bool
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

func selectTunnelListener() (net.Listener, string, error) {
	const attempts = 100
	for range attempts {
		port := strconv.Itoa(rand.IntN(1000) + 9000)
		listener, err := net.Listen("tcp", net.JoinHostPort("", port))
		if err == nil {
			return listener, port, nil
		}
	}

	return nil, "", fmt.Errorf("find an available listener port between 9000 and 9999")
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

func queryReverseShellCommandsToOffer(payloadsPath string) (ShellCandidate, error) {
	catalog, err := loadPayloads(payloadsPath)
	if err != nil {
		return ShellCandidate{}, err
	}
	var selectedType WebShellType
	var typeOptions []huh.Option[WebShellType]
	for _, kind := range targetShellTypeValues {
		if len(catalog[kind]) > 0 {
			typeOptions = append(typeOptions, huh.NewOption(targetShellTypeLabel(kind), kind))
		}
	}
	if len(typeOptions) == 0 {
		return ShellCandidate{}, fmt.Errorf("payload catalog is empty")
	}
	if err := huh.NewSelect[WebShellType]().Title("Select the target platform").Options(typeOptions...).Value(&selectedType).Run(); err != nil {
		return ShellCandidate{}, fmt.Errorf("select shell type: %w", err)
	}
	var index int
	var payloadOptions []huh.Option[int]
	for i, payload := range catalog[selectedType] {
		payloadOptions = append(payloadOptions, huh.NewOption(payload.Name+" — "+payload.Description, i))
	}
	if err := huh.NewSelect[int]().Title("Select a payload").Options(payloadOptions...).Value(&index).Run(); err != nil {
		return ShellCandidate{}, fmt.Errorf("select payload: %w", err)
	}
	selected := catalog[selectedType][index]
	encoding := EncodingNone
	var encodingOptions []huh.Option[Encoding]
	for _, value := range encodingValues {
		if value == EncodingPowerShellBase64 && !selected.PowerShell {
			continue
		}
		encodingOptions = append(encodingOptions, huh.NewOption(targetEncodingLabels(value), value))
	}
	if err := huh.NewSelect[Encoding]().Title("What encoding do you require?").Options(encodingOptions...).Value(&encoding).Run(); err != nil {
		return ShellCandidate{}, fmt.Errorf("select encoding: %w", err)
	}
	return ShellCandidate{
		Name:       selected.Name,
		Type:       selectedType,
		Encoding:   encoding,
		Template:   selected.Template,
		PowerShell: selected.PowerShell,
	}, nil
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

		listener, selectedPort, err := selectTunnelListener()
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintf(
			cmd.OutOrStdout(),
			"Selected port: %s\n",
			selectedPort,
		)

		payloadsPath, err := cmd.Flags().GetString("payloads")
		if err != nil {
			return err
		}
		shellCandidate, err := queryReverseShellCommandsToOffer(payloadsPath)
		if err != nil {
			return err
		}
		payload, err := renderPayload(shellCandidate, selectedIP, selectedPort)
		if err != nil {
			return err
		}
		fmt.Fprintf(
			cmd.OutOrStdout(),
			"\nGenerated %s payload for %s (%s):\n%s\n\n",
			shellCandidate.Name,
			targetShellTypeLabel(shellCandidate.Type),
			targetEncodingLabels(shellCandidate.Encoding),
			payload,
		)
		return establishReverseShellListener(listener, selectedPort)
	},
}

func establishReverseShellListener(listener net.Listener, port string) error {
	fmt.Printf("\nSetting up port listener on %s...\n", port)

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
	rootCmd.Flags().String("payloads", "payloadsList.json", "Path to the payload JSON catalog")
}
