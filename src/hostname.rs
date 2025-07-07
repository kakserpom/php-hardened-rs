use crate::to_str;
use anyhow::anyhow;
use ext_php_rs::exception::PhpResult;
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use url::quirks::hostname;
use url::{Host, Url};

/// A secured wrapper around `url::Host` for use in PHP extensions.
/// Provides hostname parsing and normalization to prevent security issues.
#[php_class]
#[php(name = "Hardened\\Hostname")]
pub struct Hostname {
    inner: Host,
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
        let mut host = Host::parse_opaque(hostname).map_err(|err| anyhow!("{err}"))?;
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
        let mut that = Host::parse_opaque(hostname).map_err(|err| anyhow!("{err}"))?;
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
    pub fn subdomain_of(&self, hostname: &Zval) -> PhpResult<bool> {
        self.subdomain_of_str(&to_str(hostname)?)
    }

    pub fn subdomain_of_str(&self, hostname: &str) -> PhpResult<bool> {
        let this = &self.inner;
        let mut that = Host::parse_opaque(&hostname).map_err(|err| anyhow!("{err}"))?;
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
    pub fn subdomain_of_url(&self, url: &str) -> PhpResult<bool> {
        self.subdomain_of_str(hostname(&Url::parse(url).map_err(|err| anyhow!("{err}"))?))
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
    #[test]
    fn it_works() {
        //use crate::Hostname;
        //let hostname = Hostname::from_url("https://example.com").unwrap();
        //assert!(hostname.equals("eXaMple.com.").unwrap());
    }
}
