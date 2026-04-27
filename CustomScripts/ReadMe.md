CustomScripts/ contains a few scripts built and used for various purposes while conducting this research. These scripts came in handy in different stages of discovering this vulnerability (plus going beyond CWE-295, and leveraging it to discover other vulnerabilities), and I hope these tools also come in handy for anyone interested in recreating this PoC or analyzing similar IoT hardware traffic.


## mitmToJson.py
Converts `.mitm` capture files into a readable JSON format.

#### Info/Flow:
    Opens a `.mitm` file and uses `mitmproxy.io` to read the captured flows (requests/responses).
    Iterates through the stream, extracting the raw state data (`flow.get_state()`) from each intercepted flow.
    Passes the data through a custom `MitmJSONEncoder`. It attempts to decode bytes to UTF-8 readable strings; if a `UnicodeDecodeError` occurs, it safely falls back to base64 encoding.
    Writes the completely parsed dictionary to a formatted JSON file.

#### Usage:
`python mitmToJson.py <input.mitm> <output.json>`


## AccessPoint.sh
Configures a wireless interface (`wlan0`) to act as a routed access point for traffic interception. 

#### Info/Flow:
    Manually assigns a static IP (`192.168.100.1/24`) to `wlan0` and brings the interface up. This manual assignment is particularly useful for ensuring the static IP is enforced without allowing background services (like NetworkManager) to interfere with `hostapd`.
    Enables IPv4 forwarding in the kernel and configures `iptables` to masquerade outbound traffic from the AP through the host's primary connection.
    Restarts `hostapd` (for the access point daemon) and `dnsmasq` (for DHCP/DNS).
    Contains commented-out `iptables` rules that can be uncommented to establish a transparent proxy, redirecting all port 80/443 traffic to `mitmproxy` running on port 8081.

#### Usage:
`chmod +x AccessPoint.sh`
`sudo ./AccessPoint.sh`


## pcapParser.py
Parses `.pcapng` network captures, extracting a specific set of protocol fields into CSV formats for easier bulk analysis.

#### Info/Flow:
    Searches the current working directory for all `.pcapng` files.
    Uses a predefined list of Wireshark/tshark display filters to target specific data points across L2/L3/L4, DNS, HTTP, TLS (including leaf certificates and ciphersuites), STUN/WebRTC, and MQTT payloads.
    Constructs and executes a `tshark` subprocess for each capture file, forcing the output format to a comma-separated, quote-enclosed CSV with headers.
    Generates a corresponding `_extract.csv` file for every parsed capture, calculating and printing the final file size upon completion.

#### Usage:
*(Ensure `tshark` is installed before running)*
`python pcapParser.py`
