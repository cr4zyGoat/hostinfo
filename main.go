package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

type IPInfoResponse struct {
	Hostname string `json:"hostname,omitempty"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

type ShodanResponse struct {
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

type CombinedResponse struct {
	Target string `json:"target,omitempty"`
	IP     string `json:"ip"`
	IPInfoResponse
	ShodanResponse
}

var argResolver string
var cachedResponses map[string]CombinedResponse

func init() {
	flag.StringVar(&argResolver, "r", "", "Resolver to use for domain resolution (e.g., 8.8.8.8)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "[!] Usage: %s [file|target]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "If no arguments are provided, targets will be read from stdin.")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}
}

func fetchShodanData(ip string) (ShodanResponse, error) {
	resp, err := http.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", ip))
	if err != nil {
		return ShodanResponse{}, err
	}
	defer resp.Body.Close()

	var shodanData ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&shodanData); err != nil {
		return ShodanResponse{}, err
	}

	return shodanData, nil
}

func fetchIPInfoData(ip string) (IPInfoResponse, error) {
	resp, err := http.Get(fmt.Sprintf("https://ipinfo.io/%s/json", ip))
	if err != nil {
		return IPInfoResponse{}, err
	}
	defer resp.Body.Close()

	var ipInfoData IPInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&ipInfoData); err != nil {
		return IPInfoResponse{}, err
	}

	return ipInfoData, nil
}

func resolveHostname(hostname string) (string, error) {
	var resolver net.Resolver
	if argResolver != "" {
		dialer := &net.Dialer{}
		resolver = net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, argResolver+":53")
			},
		}
	}

	ips, err := resolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname %s", hostname)
	}
	return ips[0].String(), nil
}

func processTarget(target string) (CombinedResponse, error) {
	ip := target
	var combined CombinedResponse
	var err error

	if net.ParseIP(target) == nil {
		ip, err = resolveHostname(target)
		if err != nil {
			return combined, err
		}
	}

	combined, cached := cachedResponses[ip]
	if cached {
		combined.Target = target
		return combined, nil
	}

	shodanData, _ := fetchShodanData(ip)
	ipInfoData, err := fetchIPInfoData(ip)
	if err != nil {
		return combined, err
	}

	combined.ShodanResponse = shodanData
	combined.IPInfoResponse = ipInfoData
	combined.Target = target
	combined.IP = ip

	cachedResponses[ip] = combined
	return combined, nil
}

func processTargets(targets []string, singleTarget bool) {
	cachedResponses = map[string]CombinedResponse{}

	for _, target := range targets {
		combinedData, err := processTarget(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing target %s: %v\n", target, err)
			continue
		}

		jsonData, err := json.MarshalIndent(combinedData, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling data for target %s: %v\n", target, err)
			continue
		}

		if singleTarget {
			fmt.Println(string(jsonData))
		} else {
			jsonData, err := json.Marshal(combinedData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshalling data for target %s: %v\n", target, err)
				continue
			}
			fmt.Println(string(jsonData))
		}
	}
}

func main() {
	flag.Parse()

	var targets []string
	var singleTarget bool

	if flag.NArg() > 0 {
		firstArg := flag.Arg(0)
		if _, err := os.Stat(firstArg); err == nil {
			file, err := os.Open(firstArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				targets = append(targets, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				return
			}
		} else {
			targets = append(targets, firstArg)
			singleTarget = true
		}
	} else {
		info, err := os.Stdin.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error stating stdin: %v\n", err)
			return
		}

		if info.Mode()&os.ModeCharDevice != 0 {
			flag.Usage()
			return
		}

		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				return
			}
			targets = append(targets, strings.TrimSpace(line))
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] Hostinfo: No targets provided")
		return
	}

	processTargets(targets, singleTarget)
}
