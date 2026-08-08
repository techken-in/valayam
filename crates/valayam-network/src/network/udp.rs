#![allow(
    clippy::field_reassign_with_default,
    clippy::same_item_push,
    clippy::redundant_field_names
)]
use futures::future::join_all;
use std::collections::HashSet;
use tokio::net::UdpSocket;
// Reuse service info from TCP module

/// Result of a UDP port scan, including optional response data.
#[derive(Debug, Clone)]
pub struct UdpPortResult {
    pub port: u16,
    pub response: Option<Vec<u8>>,
    /// Additional metadata about the service
    pub service_info: service_info::ServiceInfo,
}

/// Additional service information for UDP services
pub mod service_info {

    #[derive(Debug, Clone, Default)]
    pub struct ServiceInfo {
        /// Detected service name (DNS, SNMP, DHCP, etc.)
        pub service_name: Option<String>,
        /// Detected service version if available
        pub version: Option<String>,
        /// Raw response data for further analysis
        pub raw_response: Option<Vec<u8>>,
        /// Whether this appears to be a DNS service
        pub is_dns: bool,
        /// Whether this appears to be an SNMP service
        pub is_snmp: bool,
        /// Whether this appears to be a DHCP service
        pub is_dhcp: bool,
        /// Whether this appears to be an NTP service
        pub is_ntp: bool,
        /// Whether this appears to be a TFTP service
        pub is_tftp: bool,
        /// Whether this appears to be an SSDP service
        pub is_ssdp: bool,
    }
}

use valayam_models::error::ScannerError;

/// Parses a list of port strings, expanding ranges into individual port numbers.
/// E.g., ["53", "161", "8000-8005"] -> {53, 161, 8000, 8001, ..., 8005}
fn parse_ports(ports: &[String]) -> Result<HashSet<u16>, ScannerError> {
    let mut parsed_ports = HashSet::new();
    for port_str in ports {
        if let Some((start, end)) = port_str.split_once('-') {
            let start_port: u16 = start.trim().parse().map_err(|_| {
                ScannerError::ConfigurationError(format!("Invalid port range start: {}", start))
            })?;
            let end_port: u16 = end.trim().parse().map_err(|_| {
                ScannerError::ConfigurationError(format!("Invalid port range end: {}", end))
            })?;
            if start_port > end_port {
                return Err(ScannerError::ConfigurationError(format!(
                    "Invalid port range: start > end ({} > {})",
                    start_port, end_port
                )));
            }
            for port in start_port..=end_port {
                parsed_ports.insert(port);
            }
        } else {
            let port: u16 = port_str.trim().parse().map_err(|_| {
                ScannerError::ConfigurationError(format!("Invalid port: {}", port_str))
            })?;
            parsed_ports.insert(port);
        }
    }
    Ok(parsed_ports)
}

/// Perform protocol-specific probes to elicit responses from UDP services
async fn probe_udp_service(_socket: &UdpSocket, port: u16) -> Option<Vec<u8>> {
    match port {
        // DNS - send a simple query
        53 => {
            // Standard DNS query for "example.com" (type A)
            let mut query = Vec::with_capacity(64);
            // Transaction ID
            query.push(0x12);
            query.push(0x34);
            // Flags: standard query
            query.push(0x01);
            query.push(0x00);
            // Questions: 1
            query.push(0x00);
            query.push(0x01);
            // Answer RRs: 0
            query.push(0x00);
            query.push(0x00);
            // Authority RRs: 0
            query.push(0x00);
            query.push(0x00);
            // Additional RRs: 0
            query.push(0x00);
            query.push(0x00);
            // Question: example.com
            query.extend_from_slice(b"\x07example\x03com\x00"); // length-prefixed labels
                                                                // QTYPE: A (1)
            query.push(0x00);
            query.push(0x01);
            // QCLASS: IN (1)
            query.push(0x00);
            query.push(0x01);
            Some(query)
        }
        // SNMP - send a simple GET request
        161 => {
            // SNMPv1 GetRequest for sysDescr.0
            // This is a simplified version - real implementation would use proper BER encoding
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[
                0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0,
                0x19, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x12, 0x06, 0x08, 0x2b, 0x06, 0x01,
                0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
            ]);
            Some(pkt)
        }
        // DHCP - client discover message
        67 | 68 => {
            // Simplified DHCP Discover
            let mut pkt = Vec::with_capacity(300);
            // OP: 1 (Client to Server)
            pkt.push(0x01);
            // HTYPE: Ethernet
            pkt.push(0x01);
            // HLEN: 6
            pkt.push(0x06);
            // HOPS: 0
            pkt.push(0x00);
            // XID: random transaction ID
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let xid: u32 = rng.gen();
            pkt.extend_from_slice(&xid.to_be_bytes());
            // SECS: 0
            pkt.push(0x00);
            pkt.push(0x00);
            // FLAGS: 0x8000 (Broadcast)
            pkt.push(0x80);
            pkt.push(0x00);
            // CIADDR: 0.0.0.0
            pkt.extend_from_slice(&[0, 0, 0, 0]);
            // YIADDR: 0.0.0.0
            // SIADDR: 0.0.0.0
            // GIADDR: 0.0.0.0
            for _ in 0..9 {
                pkt.push(0x00);
            }
            // CHAD: client hardware address (MAC)
            // Using a placeholder MAC
            pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            // SNAME: 64 bytes zero
            for _ in 0..64 {
                pkt.push(0x00);
            }
            // FILE: 128 bytes zero
            for _ in 0..128 {
                pkt.push(0x00);
            }
            // OPTIONS: magic cookie + options
            pkt.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // Magic cookie
                                                              // DHCP Message Type: Discover (1)
            pkt.extend_from_slice(&[0x35, 0x01, 0x01]);
            // END
            pkt.push(0xff);
            Some(pkt)
        }
        // NTP - NTPv4 client request
        123 => {
            let mut pkt = vec![0u8; 48];
            // LI=0 (0), VN=4 (4), Mode=3 (Client) -> 0x23
            pkt[0] = 0x23;
            Some(pkt)
        }
        // TFTP - Read Request (RRQ)
        69 => {
            // Build dynamic RRQ for a common probe file to elicit an error or data response
            let filename = "valayam_probe.txt";
            let mode = "octet";
            let mut pkt = Vec::new();
            pkt.push(0x00);
            pkt.push(0x01); // Opcode 1: RRQ
            pkt.extend_from_slice(filename.as_bytes());
            pkt.push(0x00);
            pkt.extend_from_slice(mode.as_bytes());
            pkt.push(0x00);
            Some(pkt)
        }
        // SSDP (UPnP) - M-SEARCH
        1900 => {
            let payload = "M-SEARCH * HTTP/1.1\r\n\
                           Host: 239.255.255.250:1900\r\n\
                           Man: \"ssdp:discover\"\r\n\
                           MX: 1\r\n\
                           ST: ssdp:all\r\n\r\n";
            Some(payload.as_bytes().to_vec())
        }
        _ => None, // No specific probe for other ports
    }
}

/// Extract DNS information from response
fn parse_dns_response(response: &[u8]) -> service_info::ServiceInfo {
    let mut info = service_info::ServiceInfo::default();
    info.is_dns = true;
    info.service_name = Some("DNS".to_string());

    if response.len() >= 12 {
        // Parse header
        let _id = u16::from_be_bytes([response[0], response[1]]);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let _qdcount = u16::from_be_bytes([response[4], response[5]]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);

        // Check if it's a response (QR bit set)
        if (flags & 0x8000) != 0 {
            // It's a response
            if ancount > 0 {
                // Has answers - likely a valid DNS server
                info.version = Some("DNS Server".to_string());
            }
        }
    }

    info
}

/// Extract SNMP information from response
fn parse_snmp_response(response: &[u8]) -> service_info::ServiceInfo {
    let mut info = service_info::ServiceInfo::default();
    info.is_snmp = true;
    info.service_name = Some("SNMP".to_string());

    // SNMP responses start with SEQUENCE tag (0x30)
    if !response.is_empty() && response[0] == 0x30 {
        // Very basic check - real implementation would parse BER
        info.version = Some("SNMP Agent".to_string());
        // Try to extract community string (simplified)
        if response.len() > 10 {
            // Look for public/private strings
            if response.windows(6).any(|window| window == b"public") {
                info.version = Some("SNMP v1/v2c (public community)".to_string());
            } else if response.windows(7).any(|window| window == b"private") {
                info.version = Some("SNMP v1/v2c (private community)".to_string());
            }
        }
    }

    info
}

/// Extract DHCP information from response
fn parse_dhcp_response(response: &[u8]) -> service_info::ServiceInfo {
    let mut info = service_info::ServiceInfo::default();
    info.is_dhcp = true;
    info.service_name = Some("DHCP".to_string());

    // DHCP message format: op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, options
    if response.len() >= 240 {
        // Check OP field: 2 = Server to Client
        if response[0] == 2 {
            // Check for magic cookie in options (starts at byte 236)
            if response.len() >= 248 && &response[236..240] == b"\x63\x82\x53\x63" {
                info.version = Some("DHCP Server".to_string());
                // Could parse options further for more info
            }
        }
    }

    info
}

/// Extract NTP information from response
fn parse_ntp_response(response: &[u8]) -> service_info::ServiceInfo {
    let mut info = service_info::ServiceInfo::default();
    info.is_ntp = true;
    info.service_name = Some("NTP".to_string());

    // NTP response is at least 48 bytes
    if response.len() >= 48 {
        // LI, VN, Mode are in the first byte
        let mode = response[0] & 0x07;
        // Mode 4 is Server
        if mode == 4 {
            let vn = (response[0] & 0x38) >> 3;
            info.version = Some(format!("NTPv{}", vn));
        }
    }
    info
}

fn parse_tftp_response(response: &[u8]) -> service_info::ServiceInfo {
    let mut info = service_info::ServiceInfo::default();
    info.is_tftp = true;
    info.service_name = Some("TFTP".to_string());

    if response.len() >= 4 {
        let opcode = u16::from_be_bytes([response[0], response[1]]);
        match opcode {
            3 => {
                // Opcode 3: DATA
                let block = u16::from_be_bytes([response[2], response[3]]);
                info.version = Some(format!("TFTP Server (Data Block {})", block));
            }
            5 => {
                // Opcode 5: ERROR
                let err_code = u16::from_be_bytes([response[2], response[3]]);
                // Extract error message
                let err_msg = if response.len() > 4 {
                    let msg_bytes = &response[4..response.len().saturating_sub(1)];
                    String::from_utf8_lossy(msg_bytes).to_string()
                } else {
                    "Unknown Error".to_string()
                };
                info.version = Some(format!("TFTP Server (Error {}: {})", err_code, err_msg));
            }
            _ => {
                info.version = Some(format!("TFTP Server (Opcode {})", opcode));
            }
        }
    }
    info
}

/// Extract SSDP information from response
fn parse_ssdp_response(response: &[u8]) -> service_info::ServiceInfo {
    let mut info = service_info::ServiceInfo::default();
    info.is_ssdp = true;
    info.service_name = Some("SSDP".to_string());

    let resp_str = String::from_utf8_lossy(response);
    if resp_str.contains("HTTP/1.1 200 OK") || resp_str.contains("UPnP") {
        info.version = Some("UPnP Device".to_string());
        // Try to extract Server header
        if let Some(server_line) = resp_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
        {
            info.version = Some(server_line["server:".len()..].trim().to_string());
        }
    }
    info
}

/// Performs a concurrent UDP probe on a list of ports for a given host.
/// UDP is stateless, so we send a protocol-specific probe and wait for a response.
pub async fn scan_ports(
    host: &str,
    ports: &[String],
    banner_timeout_ms: Option<u64>,
    enable_service_detection: bool,
) -> Result<Vec<UdpPortResult>, ScannerError> {
    let parsed_ports = parse_ports(ports)?;

    let scan_futures = parsed_ports.into_iter().map(|port| {
        let host = host.to_string();
        let timeout_ms = banner_timeout_ms.unwrap_or(2000); // Default 2 second wait for UDP
        let detect_service = enable_service_detection;
        tokio::spawn(async move {
            let address = format!("{}:{}", host, port);

            // Bind to a local ephemeral port
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return None,
            };

            // Timeout is handled via tokio::time::timeout on the recv call

            // Connect to target (for UDP, this just sets the default address)
            if socket.connect(&address).await.is_err() {
                return None;
            }

            // Send protocol-specific probe if enabled
            let mut response = None;
            if detect_service {
                if let Some(probe) = probe_udp_service(&socket, port).await {
                    if socket.send(&probe).await.is_ok() {
                        // Wait for response
                        let mut buf = vec![0u8; 65535]; // Max UDP packet size
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(timeout_ms),
                            socket.recv(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                response = Some(buf[..n].to_vec());
                            }
                            _ => {} // Timeout or error - no response
                        }
                    }
                }
            } else {
                // Just send a basic probe (empty packet)
                if socket.send(&[]).await.is_ok() {
                    let mut buf = vec![0u8; 65535];
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(timeout_ms),
                        socket.recv(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            response = Some(buf[..n].to_vec());
                        }
                        _ => {}
                    }
                }
            }

            // Process response if we got one
            let mut service_info = service_info::ServiceInfo::default();
            if let Some(ref resp) = response {
                if detect_service {
                    // Try to identify the service based on port and response
                    service_info = match port {
                        53 => {
                            let mut info = parse_dns_response(resp);
                            info.raw_response = Some(resp.clone());
                            info
                        }
                        161 => {
                            let mut info = parse_snmp_response(resp);
                            info.raw_response = Some(resp.clone());
                            info
                        }
                        67 | 68 => {
                            let mut info = parse_dhcp_response(resp);
                            info.raw_response = Some(resp.clone());
                            info
                        }
                        123 => {
                            let mut info = parse_ntp_response(resp);
                            info.raw_response = Some(resp.clone());
                            info
                        }
                        69 => {
                            let mut info = parse_tftp_response(resp);
                            info.raw_response = Some(resp.clone());
                            info
                        }
                        1900 => {
                            let mut info = parse_ssdp_response(resp);
                            info.raw_response = Some(resp.clone());
                            info
                        }
                        _ => {
                            // Generic handling - just check if we got any response
                            if !resp.is_empty() {
                                service_info.service_name = Some("Unknown".to_string());
                                service_info.raw_response = Some(resp.clone());
                            }
                            service_info
                        }
                    };
                }
            }

            Some(UdpPortResult {
                port,
                response,
                service_info,
            })
        })
    });

    let results = join_all(scan_futures).await;

    Ok(results
        .into_iter()
        .filter_map(|res| res.unwrap_or(None))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_ports() {
        let ports = vec!["53".to_string(), "161".to_string(), "8000-8005".to_string()];
        let result = parse_ports(&ports).expect("Should parse ports");
        assert!(result.contains(&53));
        assert!(result.contains(&161));
        assert!(result.contains(&8000));
        assert!(result.contains(&8002));
        assert!(result.contains(&8005));
        assert!(!result.contains(&8006)); // Out of range
    }

    #[tokio::test]
    async fn test_parse_dns_response() {
        // Minimal valid DNS response (header only, no questions/answers)
        // ID: 0x1234, Flags: 0x8180 (standard response), QDCOUNT: 1, ANCOUNT: 2, etc.
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, // Header
                 // Question section would follow...
        ];
        let info = parse_dns_response(&response);
        assert!(info.is_dns);
        assert_eq!(info.service_name.as_deref(), Some("DNS"));
    }

    #[tokio::test]
    async fn test_parse_snmp_response() {
        // Minimal SNMP response (simplified)
        let response = [
            0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2,
            0x00,
        ];
        let info = parse_snmp_response(&response);
        assert!(info.is_snmp);
        assert_eq!(info.service_name.as_deref(), Some("SNMP"));
    }
    #[tokio::test]
    async fn test_parse_ntp_response() {
        // NTPv4 Server response (LI=0, VN=4, Mode=4 -> 0x24)
        let mut response = vec![0u8; 48];
        response[0] = 0x24;
        let info = parse_ntp_response(&response);
        assert!(info.is_ntp);
        assert_eq!(info.service_name.as_deref(), Some("NTP"));
        assert_eq!(info.version.as_deref(), Some("NTPv4"));
    }

    #[tokio::test]
    async fn test_parse_tftp_response() {
        // TFTP Error response (Opcode 5)
        let response = [0x00, 0x05, 0x00, 0x01, b'e', b'r', b'r', 0x00];
        let info = parse_tftp_response(&response);
        assert!(info.is_tftp);
        assert_eq!(info.service_name.as_deref(), Some("TFTP"));
        assert_eq!(info.version.as_deref(), Some("TFTP Server (Error 1: err)"));
    }
}
