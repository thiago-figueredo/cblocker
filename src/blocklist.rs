use std::{collections::HashSet, net::IpAddr};

const DOMAINS: &[&str] = &[
    "fatalmodel.com",
    "vivalocal.com",
    "photoacompanhantes.com",
    "erosguia.com.br",
    "fikante.com",
    "ocabare.com",
    "garotacomlocal.com",
    "lindas.com.br",
    "confrariars.com.br",
    "coelhinhadobrasil.com.br",
    "soacompanhantes.com.br",
    "br.skokka.com",
    "hotters.com.br",
    "br.simpleescort.com",
    "classiaqui.com.br",
    "hotms.com.br",
    // realprazer.com.br
    "realprazer.com.br",
    // br.santtas.com
    "br.santtas.com",
    // xvideosbr.blog
    "xvideosbr.blog",
    // br.xhamster.com
    "br.xhamster.com",
];

// IPs to block via SO_ORIGINAL_DST (catches ECH connections where the SNI is encrypted)
const IPS: &[&str] = &[
    // realprazer.com.br
    "104.21.30.239",
    "172.67.174.48",
    "2606:4700:3036::6815:1eef",
    "2606:4700:3036::ac43:ae30",
    // br.santtas.com
    "104.21.29.235",
    "172.67.171.227",
    "2606:4700:3035::6815:1deb",
    "2606:4700:3036::ac43:abe3",
    // xvideosbr.blog
    "104.21.27.215",
    "172.67.169.195",
    "2606:4700:3037::6815:1bd7",
    "2606:4700:3031::ac43:a9c3",
    // br.xhamster.com
    "104.16.3.81",
    "104.16.4.81",
    "2606:4700::6810:351",
    "2606:4700::6810:451",
];

// Wildcard patterns (* matches any sequence of characters)
const WILDCARDS: &[&str] = &[
    "*xvideos*",
    "*porn*",
    "*redtube*",
    "*erome*",
    "*spankbang*",
    "*xhamster*",
];

pub struct Blocklist {
    pub domains: HashSet<String>,
    pub ips: HashSet<IpAddr>,
    pub wildcards: Vec<String>,
}

impl Blocklist {
    pub fn load() -> Self {
        Self {
            domains: DOMAINS.iter().map(|s| s.to_string()).collect(),
            ips: IPS.iter().map(|s| s.parse().expect("invalid IP in blocklist")).collect(),
            wildcards: WILDCARDS.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn is_domain_blocked(&self, host: &str) -> bool {
        if self.domains.contains(host) {
            return true;
        }

        // Subdomain matching
        for domain in &self.domains {
            if host.ends_with(domain) {
                return true;
            }
        }

        // Wildcard matching (e.g. *xvideos*)
        for pattern in &self.wildcards {
            if glob_match(pattern, host) {
                return true;
            }
        }

        false
    }

    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip)
    }
}


pub fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        return pattern == text;
    }

    let mut remaining = text;

    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            // Must match at start if non-empty (pattern doesn't start with *)
            if !part.is_empty() {
                if !remaining.starts_with(part) {
                    return false;
                }
                remaining = &remaining[part.len()..];
            }
        } else if i == parts.len() - 1 {
            // Must match at end if non-empty (pattern doesn't end with *)
            return part.is_empty() || remaining.ends_with(part);
        } else {
            // Middle segment: find it anywhere in what's left
            if part.is_empty() {
                continue;
            }
            match remaining.find(part) {
                Some(pos) => remaining = &remaining[pos + part.len()..],
                None => return false,
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*xvideos*", "xvideosbr.blog"));
        assert!(glob_match("*xvideos*", "www.xvideos.com"));
        assert!(glob_match("*xvideos*", "xvideos.es"));
        assert!(!glob_match("*xvideos*", "youtube.com"));
        assert!(glob_match("*xhamster*", "br.xhamster.com"));
        assert!(glob_match("*porn*", "pornhub.com"));
    }
}
