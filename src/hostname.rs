use crate::to_str;
use anyhow::{Result, anyhow};
use ext_php_rs::exception::PhpResult;
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use url::quirks::hostname;
use url::{Host, Url};

/// A secured wrapper around `url::Host` for use in PHP extensions.
/// Provides hostname parsing and normalization to prevent security issues.
#[php_class]
#[php(name = "Hardened\\Hostname")]
#[derive(Debug)]
pub struct Hostname {
    inner: Host,
}

impl Hostname {
    /// Internal constructor from a raw hostname string.
    pub fn _from_str(s: &str) -> Result<Self> {
        // Try IPv6 (with or without brackets)
        let s = s.trim_end_matches('.');
        let host = if s.starts_with('[') && s.ends_with(']') {
            // strip brackets
            let inner = &s[1..s.len() - 1];
            Host::Ipv6(inner.parse().map_err(|e| anyhow!("Invalid IPv6: {}", e))?)
        } else if let Ok(v4) = s.parse() {
            Host::Ipv4(v4)
        } else {
            // domain (to lowercase)
            Host::Domain(s.to_lowercase())
        };
        Ok(Self { inner: host })
    }

    /// Internal constructor from a URL string.
    pub fn _from_url(url: &str) -> Result<Self> {
        let parsed = Url::parse(url).map_err(|e| anyhow!("URL parse error: {}", e))?;
        let host_ref = parsed.host().ok_or_else(|| anyhow!("URL has no host"))?;
        let host = match host_ref {
            Host::Domain(d) => Host::Domain(d.trim_end_matches('.').to_lowercase()),
            Host::Ipv4(a) => Host::Ipv4(a),
            Host::Ipv6(a) => Host::Ipv6(a),
        };
        Ok(Self { inner: host })
    }

    /// Compare against a raw hostname string.
    pub fn _equals_str(&self, other: &str) -> Result<bool> {
        let other = Hostname::_from_str(other)?;
        println!("other: {other:?}");
        Ok(self.inner.eq(&other.inner))
    }

    /// True if equals any of the provided host strings.
    pub fn _equals_any_str(&self, list: &[&str]) -> Result<bool> {
        for &h in list {
            if self._equals_str(h)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Compare against the host of a URL string.
    pub fn _equals_url(&self, url: &str) -> Result<bool> {
        let parsed = Url::parse(url).map_err(|e| anyhow!(e.to_string()))?;
        let host_str = hostname(&parsed);
        self._equals_str(host_str)
    }

    /// True if equals any host of the provided URLs.
    pub fn _equals_any_url(&self, urls: &[&str]) -> Result<bool> {
        for &u in urls {
            if self._equals_url(u)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check if this is a subdomain of the raw hostname.
    pub fn _subdomain_of(&self, hostname: &str) -> Result<bool> {
        let this = &self.inner;
        let mut that = Host::parse(&hostname).map_err(|err| anyhow!("{err}"))?;
        if let Host::Domain(s) = &mut that {
            *s = s.trim_end_matches('.').to_lowercase();
        }
        Ok(match (this, that) {
            (Host::Domain(this), Host::Domain(that)) => {
                if this.eq(&that) {
                    true
                } else {
                    this.ends_with(&format!(".{that}"))
                }
            }
            (Host::Ipv4(this), Host::Ipv4(that)) => this.eq(&that),
            (Host::Ipv6(this), Host::Ipv6(that)) => this.eq(&that),
            _ => false,
        })
    }

    /// True if subdomain of any provided host strings.
    pub fn _subdomain_of_any(&self, list: &[&str]) -> Result<bool> {
        for &h in list {
            if self._subdomain_of(h)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check if subdomain of host of a URL string.
    pub fn _subdomain_of_url(&self, url: &str) -> Result<bool> {
        let parsed = Url::parse(url).map_err(|e| anyhow!(e.to_string()))?;
        let host_str = hostname(&parsed);
        self._subdomain_of(host_str)
    }

    /// True if subdomain of any hosts from provided URLs.
    pub fn _subdomain_of_any_url(&self, urls: &[&str]) -> Result<bool> {
        for &u in urls {
            if self._subdomain_of_url(u)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[php_impl]
impl Hostname {
    /// Parses and normalizes a hostname string.
    ///
    /// # Parameters
    /// - `hostname`: The hostname to parse and normalize.
    ///
    /// # Errors
    /// Throws an exception if parsing the hostname fails.
    #[inline]
    pub fn from(hostname: &Zval) -> PhpResult<Self> {
        Self::from_str(&to_str(hostname)?)
    }

    #[inline]
    fn from_str(hostname: &str) -> PhpResult<Self> {
        let mut host = Host::parse(hostname).map_err(|err| anyhow!("{err}"))?;
        if let Host::Domain(s) = &mut host {
            *s = s.trim_end_matches('.').to_lowercase();
        }
        Ok(Self { inner: host })
    }

    /// Constructs a new Hostname instance (alias for `from`).
    ///
    /// # Parameters
    /// - `hostname`: The hostname to initialize.
    ///
    /// # Errors
    /// Throws an exception if parsing the hostname fails.
    pub fn __construct(hostname: &Zval) -> PhpResult<Self> {
        Self::from(hostname)
    }

    /// Parses a URL and extracts its hostname.
    ///
    /// # Parameters
    /// - `url`: The URL to parse.
    ///
    /// # Errors
    /// Throws an exception if parsing the URL or hostname fails.
    pub fn from_url(url: &Zval) -> PhpResult<Self> {
        Self::from_str(hostname(
            &Url::parse(&to_str(url)?).map_err(|err| anyhow!("{err}"))?,
        ))
    }

    /// Compares this hostname with another string.
    ///
    /// # Parameters
    /// - `hostname`: The hostname to compare against.
    ///
    /// # Errors
    /// Throws an exception if parsing the provided hostname fails.
    pub fn equals(&self, hostname: &Zval) -> PhpResult<bool> {
        self.equals_str(&to_str(hostname)?)
    }

    pub fn equals_str(&self, hostname: &str) -> PhpResult<bool> {
        let this = &self.inner;
        let mut that = Host::parse(hostname).map_err(|err| anyhow!("{err}"))?;
        if let Host::Domain(s) = &mut that {
            *s = s.trim_end_matches('.').to_lowercase();
        }
        Ok(match (this, that) {
            (Host::Domain(this), Host::Domain(that)) => this.eq(&that),
            (Host::Ipv4(this), Host::Ipv4(that)) => this.eq(&that),
            (Host::Ipv6(this), Host::Ipv6(that)) => this.eq(&that),
            _ => false,
        })
    }

    /// Returns true if this hostname equals any in the given list.
    ///
    /// # Parameters
    /// - `hostnames`: List of hostname strings to compare.
    ///
    /// # Errors
    /// Throws an exception if parsing any provided hostname fails.
    pub fn equals_any(&self, hostnames: &[&Zval]) -> PhpResult<bool> {
        for host in hostnames {
            if self.equals(host)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Compares this hostname with the hostname extracted from a URL.
    ///
    /// # Parameters
    /// - `url`: The URL to extract hostname from.
    ///
    /// # Errors
    /// Throws an exception if parsing the URL or hostname fails.
    pub fn equals_url(&self, url: &Zval) -> PhpResult<bool> {
        self.equals_str(hostname(
            &Url::parse(&to_str(url)?).map_err(|err| anyhow!("{err}"))?,
        ))
    }

    /// Returns true if this hostname equals any hostname extracted from the given URLs.
    ///
    /// # Parameters
    /// - `urls`: List of URL strings to compare.
    ///
    /// # Errors
    /// Throws an exception if parsing any URL or hostname fails.
    pub fn equals_any_url(&self, urls: &[&Zval]) -> PhpResult<bool> {
        for url in urls {
            if self.equals_url(url)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Checks if this hostname is a subdomain of the given hostname.
    ///
    /// # Parameters
    /// - `hostname`: The parent hostname to check against.
    ///
    /// # Errors
    /// Throws an exception if parsing the provided hostname fails.
    pub fn subdomain_of(&self, hostname: &Zval) -> Result<bool> {
        self._subdomain_of(&to_str(hostname)?)
    }

    /// Returns true if this hostname is a subdomain of any in the given list.
    ///
    /// # Parameters
    /// - `hosts`: List of parent hostname strings to check.
    ///
    /// # Errors
    /// Throws an exception if parsing any provided hostname fails.
    pub fn subdomain_of_any(&self, hosts: &[&Zval]) -> PhpResult<bool> {
        for host in hosts {
            if self.subdomain_of(host)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Checks if this hostname is a subdomain of the hostname extracted from a URL.
    ///
    /// # Parameters
    /// - `url`: The URL to extract hostname from.
    ///
    /// # Errors
    /// Throws an exception if parsing the URL or hostname fails.
    pub fn subdomain_of_url(&self, url: &str) -> Result<bool> {
        self._subdomain_of(hostname(&Url::parse(url).map_err(|err| anyhow!("{err}"))?))
    }

    /// Returns true if this hostname is a subdomain of any hostname extracted from the given URLs.
    ///
    /// # Parameters
    /// - `urls`: List of URL strings to check.
    ///
    /// # Errors
    /// Throws an exception if parsing any URL or hostname fails.
    pub fn subdomain_of_any_url(&self, urls: Vec<&str>) -> PhpResult<bool> {
        for url in urls {
            if self.subdomain_of_url(url)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::Hostname;

    #[test]
    fn test_from_str_and_equals() {
        let h = Hostname::_from_str("Example.COM.").unwrap();
        assert!(h._equals_str("example.com").unwrap());
        assert!(h._equals_str("EXAMPLE.com.").unwrap());
        assert!(!h._equals_str("example.org").unwrap());
    }

    #[test]
    fn test_from_url_and_subdomain() {
        let h = Hostname::_from_url("https://sub.Example.com/path").unwrap();
        assert!(h._subdomain_of("example.com").unwrap());
        assert!(h._subdomain_of("sub.example.com").unwrap());
        assert!(!h._subdomain_of("other.com").unwrap());
    }

    #[test]
    fn test_equals_any_and_subdomain_any() {
        let h = Hostname::_from_str("a.b.example.com").unwrap();
        assert!(
            h._equals_any_str(&["foo", "a.b.example.com", "bar"])
                .unwrap()
        );
        assert!(
            h._subdomain_of_any(&["example.org", "example.com"])
                .unwrap()
        );
        assert!(!h._equals_any_str(&["x", "y"]).unwrap());
        assert!(!h._subdomain_of_any(&["x", "y"]).unwrap());
    }

    #[test]
    fn test_ipv4_and_ipv6() {
        let v4 = Hostname::_from_url("http://127.0.0.1/").unwrap();
        assert!(v4._equals_str("127.0.0.1").unwrap());
        let v6 = Hostname::_from_url("https://[::1]/").unwrap();
        assert!(v6._equals_str("[::1]").unwrap());
    }

    #[test]
    fn test_equals_url_and_any_url() {
        let h = Hostname::_from_str("example.com").unwrap();
        assert!(h._equals_url("https://example.com/path").unwrap());
        assert!(
            h._equals_any_url(&["https://foo.com", "https://example.com"])
                .unwrap()
        );
    }

    #[test]
    fn test_subdomain_url_and_any_url() {
        let h = Hostname::_from_str("deep.sub.example.com").unwrap();
        assert!(h._subdomain_of_url("https://example.com/").unwrap());
        assert!(
            h._subdomain_of_any_url(&["https://foo.com", "https://sub.example.com"])
                .unwrap()
        );
    }
}
