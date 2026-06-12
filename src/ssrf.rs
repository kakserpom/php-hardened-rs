use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use ipnet::IpNet;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::LazyLock;
use thiserror::Error;
use url::{Host, Url};

// Error codes for SSRF guard errors: 2200-2299
pub mod error_codes {
    pub const INVALID_URL: i32 = 2200;
    pub const FORBIDDEN_SCHEME: i32 = 2201;
    pub const FORBIDDEN_PORT: i32 = 2202;
    pub const NO_HOST: i32 = 2203;
    pub const FORBIDDEN_USERINFO: i32 = 2204;
    pub const RESOLUTION_FAILED: i32 = 2205;
    pub const FORBIDDEN_IP: i32 = 2206;
    pub const INVALID_IP: i32 = 2207;
    pub const INVALID_CIDR: i32 = 2208;
}

/// Errors that can occur during SSRF validation.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Scheme {0:?} is not allowed")]
    ForbiddenScheme(String),

    #[error("Port {0} is not allowed")]
    ForbiddenPort(u16),

    #[error("URL has no host")]
    NoHost,

    #[error("URL must not contain userinfo")]
    ForbiddenUserinfo,

    #[error("Failed to resolve host {0:?}: {1}")]
    ResolutionFailed(String, String),

    #[error("Address {0} is in a forbidden range")]
    ForbiddenIp(IpAddr),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Invalid CIDR {0:?}: {1}")]
    InvalidCidr(String, String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidUrl(_) => error_codes::INVALID_URL,
            Error::ForbiddenScheme(_) => error_codes::FORBIDDEN_SCHEME,
            Error::ForbiddenPort(_) => error_codes::FORBIDDEN_PORT,
            Error::NoHost => error_codes::NO_HOST,
            Error::ForbiddenUserinfo => error_codes::FORBIDDEN_USERINFO,
            Error::ResolutionFailed(_, _) => error_codes::RESOLUTION_FAILED,
            Error::ForbiddenIp(_) => error_codes::FORBIDDEN_IP,
            Error::InvalidIp(_) => error_codes::INVALID_IP,
            Error::InvalidCidr(_, _) => error_codes::INVALID_CIDR,
        }
    }
}

impl From<Error> for PhpException {
    fn from(err: Error) -> Self {
        let code = err.code();
        let message = err.to_string();
        PhpException::new(message, code, ce::exception())
    }
}

/// Result type alias for SSRF guard operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Reserved / special-purpose ranges that must never be reachable from an
/// outbound request triggered by untrusted input: loopback, RFC 1918 private,
/// link-local (incl. cloud metadata 169.254.169.254), CGNAT, unique-local
/// (incl. fd00:ec2::254), benchmarking, documentation, multicast, broadcast,
/// NAT64/6to4/Teredo embedded-IPv4 ranges.
static RESERVED_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        // IPv4
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        // IPv6
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .map(|s| s.parse().expect("built-in CIDR is valid"))
    .collect()
});

/// Maps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4 so the
/// IPv4 policy cannot be bypassed via the mapped form.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn parse_cidr(cidr: &str) -> Result<IpNet> {
    if cidr.contains('/') {
        cidr.parse()
            .map_err(|e: ipnet::AddrParseError| Error::InvalidCidr(cidr.to_string(), e.to_string()))
    } else {
        let ip: IpAddr = cidr.parse().map_err(|e: std::net::AddrParseError| {
            Error::InvalidCidr(cidr.to_string(), e.to_string())
        })?;
        Ok(IpNet::from(ip))
    }
}

/// SSRF guard: outbound network policy for URLs built from untrusted input.
///
/// Implements resolve-then-validate: the hostname is resolved once, every
/// resolved address is checked against the policy, and the validated
/// addresses are returned so the caller can *pin* the connection to them
/// (e.g. via curl's `CURLOPT_RESOLVE`). Re-resolving at connect time would
/// allow a DNS-rebinding TOCTOU; pinning closes it.
///
/// By default only `http`/`https` on ports 80/443 are allowed, and loopback,
/// private (RFC 1918), link-local (incl. the 169.254.169.254 cloud metadata
/// endpoint), CGNAT, unique-local, multicast, broadcast and other reserved
/// ranges are denied — for both address families, including IPv4-mapped IPv6.
///
/// When following redirects, disable automatic following and validate every
/// hop with this guard.
#[php_class]
#[php(name = "Hardened\\SsrfGuard")]
pub struct SsrfGuard {
    allowed_schemes: Vec<String>,
    allowed_ports: Vec<u16>,
    allow_cidrs: Vec<IpNet>,
    deny_cidrs: Vec<IpNet>,
    block_reserved: bool,
}

impl SsrfGuard {
    fn _is_ip_allowed(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        if self.deny_cidrs.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if self.allow_cidrs.iter().any(|net| net.contains(&ip)) {
            return true;
        }
        if self.block_reserved && RESERVED_RANGES.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        true
    }

    /// Parses and policy-checks `url`, resolves its host, and validates
    /// every resolved address. Returns `(host, port, validated_ips)`.
    fn _validate_url(&self, url: &str) -> Result<(String, u16, Vec<IpAddr>)> {
        let parsed = Url::parse(url).map_err(|e| Error::InvalidUrl(e.to_string()))?;

        let scheme = parsed.scheme().to_ascii_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(Error::ForbiddenScheme(scheme));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(Error::ForbiddenUserinfo);
        }
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| Error::InvalidUrl("URL has no port".to_string()))?;
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port) {
            return Err(Error::ForbiddenPort(port));
        }

        let (host_str, ips) = match parsed.host().ok_or(Error::NoHost)? {
            Host::Ipv4(ip) => (ip.to_string(), vec![IpAddr::V4(ip)]),
            Host::Ipv6(ip) => (ip.to_string(), vec![IpAddr::V6(ip)]),
            Host::Domain(domain) => {
                let ips: Vec<IpAddr> = (domain, port)
                    .to_socket_addrs()
                    .map_err(|e| Error::ResolutionFailed(domain.to_string(), e.to_string()))?
                    .map(|addr| addr.ip())
                    .collect();
                if ips.is_empty() {
                    return Err(Error::ResolutionFailed(
                        domain.to_string(),
                        "no addresses returned".to_string(),
                    ));
                }
                (domain.to_string(), ips)
            }
        };

        // Strict: if *any* resolved address is forbidden, reject the URL.
        // A round-robin answer mixing public and private addresses is how
        // DNS-rebinding setups smuggle the private one in.
        if let Some(&bad) = ips.iter().find(|&&ip| !self._is_ip_allowed(ip)) {
            return Err(Error::ForbiddenIp(bad));
        }

        Ok((host_str, port, ips))
    }
}

#[php_impl]
impl SsrfGuard {
    /// Constructs an SSRF guard with secure defaults: schemes `http`/`https`,
    /// ports 80/443, and all reserved/private/metadata ranges denied.
    fn __construct() -> Self {
        Self {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allowed_ports: vec![80, 443],
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            block_reserved: true,
        }
    }

    /// Replaces the set of allowed URL schemes.
    ///
    /// # Parameters
    /// - `schemes`: Allowed schemes, e.g. `["https"]`.
    fn set_allowed_schemes(&mut self, schemes: Vec<String>) {
        self.allowed_schemes = schemes
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
    }

    /// Replaces the set of allowed ports.
    ///
    /// # Parameters
    /// - `ports`: Allowed ports, e.g. `[80, 443, 8443]`. An empty array
    ///   allows any port.
    fn set_allowed_ports(&mut self, ports: Vec<u16>) {
        self.allowed_ports = ports;
    }

    /// Adds an allowed CIDR range (or single IP), overriding the built-in
    /// reserved-range denylist — but not explicit `denyCidr()` entries.
    ///
    /// Use this to deliberately permit, say, one internal service:
    /// `$guard->allowCidr("10.0.5.20")`.
    ///
    /// # Parameters
    /// - `cidr`: A CIDR like `"10.0.5.0/24"` or a bare IP.
    ///
    /// # Exceptions
    /// - Throws an exception if the CIDR fails to parse.
    fn allow_cidr(&mut self, cidr: &str) -> Result<()> {
        self.allow_cidrs.push(parse_cidr(cidr)?);
        Ok(())
    }

    /// Adds a denied CIDR range (or single IP). Deny entries take precedence
    /// over everything else.
    ///
    /// # Parameters
    /// - `cidr`: A CIDR like `"203.0.113.0/24"` or a bare IP.
    ///
    /// # Exceptions
    /// - Throws an exception if the CIDR fails to parse.
    fn deny_cidr(&mut self, cidr: &str) -> Result<()> {
        self.deny_cidrs.push(parse_cidr(cidr)?);
        Ok(())
    }

    /// Enables or disables the built-in reserved-range denylist (loopback,
    /// private, link-local/metadata, CGNAT, unique-local, multicast, …).
    /// Enabled by default; disable only if you fully manage policy via
    /// `allowCidr()`/`denyCidr()`.
    ///
    /// # Parameters
    /// - `block`: Whether to deny reserved ranges.
    fn set_block_reserved_ranges(&mut self, block: bool) {
        self.block_reserved = block;
    }

    /// Checks a single IP address against the policy.
    ///
    /// # Parameters
    /// - `ip`: IPv4 or IPv6 address literal.
    ///
    /// # Returns
    /// - `bool`: `true` if the address is allowed.
    ///
    /// # Exceptions
    /// - Throws an exception if the address fails to parse.
    fn is_ip_allowed(&self, ip: &str) -> Result<bool> {
        Ok(self._is_ip_allowed(
            ip.parse()
                .map_err(|e: std::net::AddrParseError| Error::InvalidIp(e.to_string()))?,
        ))
    }

    /// Validates a URL against the policy: scheme, port, no userinfo, and
    /// every address the host resolves to. Resolution happens exactly once.
    ///
    /// Connect to one of the returned addresses (e.g. via `curlResolve()`)
    /// instead of re-resolving the hostname, otherwise a DNS-rebinding
    /// attacker can serve a public address during validation and a private
    /// one at connect time.
    ///
    /// # Parameters
    /// - `url`: The untrusted URL.
    ///
    /// # Returns
    /// - `string[]`: The validated resolved IP addresses.
    ///
    /// # Exceptions
    /// - Throws an exception if the URL is invalid, the scheme/port/userinfo
    ///   violates policy, resolution fails, or any resolved address is in a
    ///   forbidden range.
    fn validate_url(&self, url: &str) -> Result<Vec<String>> {
        let (_, _, ips) = self._validate_url(url)?;
        Ok(ips.iter().map(ToString::to_string).collect())
    }

    /// Validates a URL and returns a ready-made `CURLOPT_RESOLVE` entry
    /// (`"host:port:ip1,ip2"`) pinning curl to the validated addresses.
    ///
    /// ```php
    /// $entry = $guard->curlResolve($url);
    /// curl_setopt($ch, CURLOPT_RESOLVE, [$entry]);
    /// curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // validate each hop!
    /// ```
    ///
    /// # Parameters
    /// - `url`: The untrusted URL.
    ///
    /// # Returns
    /// - `string`: A `CURLOPT_RESOLVE` entry for the validated addresses.
    ///
    /// # Exceptions
    /// - Throws an exception if validation fails (see `validateUrl()`).
    fn curl_resolve(&self, url: &str) -> Result<String> {
        let (host, port, ips) = self._validate_url(url)?;
        Ok(format!(
            "{host}:{port}:{}",
            ips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::SsrfGuard;
    use crate::run_php_example;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_reserved_ranges_denied() {
        let guard = SsrfGuard::__construct();
        for addr in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(!guard._is_ip_allowed(ip(addr)), "{addr} should be denied");
        }
    }

    #[test]
    fn test_public_addresses_allowed() {
        let guard = SsrfGuard::__construct();
        for addr in ["93.184.216.34", "8.8.8.8", "2606:4700::6810:84e5"] {
            assert!(guard._is_ip_allowed(ip(addr)), "{addr} should be allowed");
        }
    }

    #[test]
    fn test_ipv4_mapped_ipv6_not_a_bypass() {
        let guard = SsrfGuard::__construct();
        assert!(!guard._is_ip_allowed(ip("::ffff:127.0.0.1")));
        assert!(!guard._is_ip_allowed(ip("::ffff:169.254.169.254")));
        assert!(!guard._is_ip_allowed(ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn test_allow_and_deny_cidrs() {
        let mut guard = SsrfGuard::__construct();
        guard.allow_cidr("10.0.5.0/24").unwrap();
        assert!(guard._is_ip_allowed(ip("10.0.5.20")));
        assert!(!guard._is_ip_allowed(ip("10.0.6.1")));

        guard.deny_cidr("93.184.216.34").unwrap();
        assert!(!guard._is_ip_allowed(ip("93.184.216.34")));

        // Deny wins over allow
        guard.allow_cidr("93.184.216.0/24").unwrap();
        assert!(!guard._is_ip_allowed(ip("93.184.216.34")));
        assert!(guard._is_ip_allowed(ip("93.184.216.35")));

        assert!(guard.allow_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn test_validate_url_policy() {
        let guard = SsrfGuard::__construct();
        // Scheme
        assert!(guard._validate_url("ftp://example.com/").is_err());
        assert!(guard._validate_url("gopher://example.com/").is_err());
        // Port
        assert!(guard._validate_url("http://1.1.1.1:8080/").is_err());
        // Userinfo
        assert!(guard._validate_url("http://user:pass@1.1.1.1/").is_err());
        // IP literals (no DNS needed)
        assert!(guard._validate_url("http://127.0.0.1/").is_err());
        assert!(
            guard
                ._validate_url("http://169.254.169.254/latest/meta-data/")
                .is_err()
        );
        assert!(guard._validate_url("http://[::1]/").is_err());
        assert!(guard._validate_url("http://[::ffff:127.0.0.1]/").is_err());
        let ips = guard._validate_url("http://1.1.1.1/").unwrap().2;
        assert_eq!(ips, vec![ip("1.1.1.1")]);
    }

    #[test]
    fn test_decimal_and_hex_ip_forms_normalized() {
        // The WHATWG URL parser normalizes exotic IPv4 notations; ensure they
        // cannot dodge the policy.
        let guard = SsrfGuard::__construct();
        // 2130706433 == 127.0.0.1, 0x7f.1 == 127.0.0.1, 017700000001 octal
        assert!(guard._validate_url("http://2130706433/").is_err());
        assert!(guard._validate_url("http://0x7f.1/").is_err());
        assert!(guard._validate_url("http://017700000001/").is_err());
    }

    #[test]
    fn test_localhost_resolution_denied() {
        let guard = SsrfGuard::__construct();
        assert!(guard._validate_url("http://localhost/").is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("ssrf-guard")?;
        Ok(())
    }
}
