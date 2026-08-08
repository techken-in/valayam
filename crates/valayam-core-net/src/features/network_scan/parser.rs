use std::collections::HashSet;

/// Parses a port string which can contain comma-separated values and ranges (e.g. "80,443,1000-1005").
/// Returns a sorted deduplicated list of u16 ports.
pub fn parse_port_ranges(ports_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = HashSet::new();

    for part in ports_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range format: {}", part));
            }

            let start = bounds[0]
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid start port in range: {}", bounds[0]))?;
            let end = bounds[1]
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid end port in range: {}", bounds[1]))?;

            if start > end {
                return Err(format!(
                    "Start port {} is greater than end port {}",
                    start, end
                ));
            }

            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let port = part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.insert(port);
        }
    }

    let mut sorted_ports: Vec<u16> = ports.into_iter().collect();
    sorted_ports.sort_unstable();

    Ok(sorted_ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        assert_eq!(parse_port_ranges("80").unwrap(), vec![80]);
    }

    #[test]
    fn test_parse_multiple_ports() {
        assert_eq!(
            parse_port_ranges("80,443, 8080").unwrap(),
            vec![80, 443, 8080]
        );
    }

    #[test]
    fn test_parse_port_ranges() {
        assert_eq!(
            parse_port_ranges("100-103").unwrap(),
            vec![100, 101, 102, 103]
        );
    }

    #[test]
    fn test_parse_mixed_ports_and_ranges() {
        assert_eq!(
            parse_port_ranges("22, 80, 100-102").unwrap(),
            vec![22, 80, 100, 101, 102]
        );
    }

    #[test]
    fn test_parse_overlapping_and_dedup() {
        assert_eq!(parse_port_ranges("80,80-82,82").unwrap(), vec![80, 81, 82]);
    }

    #[test]
    fn test_invalid_port() {
        assert!(parse_port_ranges("80,abc").is_err());
    }

    #[test]
    fn test_invalid_range() {
        assert!(parse_port_ranges("100-200-300").is_err());
        assert!(parse_port_ranges("200-100").is_err());
    }
}
