use ipnet::Ipv4Net;
use std::{collections::HashSet, net::Ipv4Addr};
use tracing::warn;

/// Manages the alloction of a pool of IPs
pub struct IpPool {
    /// IP pool
    ip_pool: Ipv4Net,
    /// Reserved IPs, must never be allocated to a client.
    reserved_ips: HashSet<Ipv4Addr>,
    /// Hashset to store IPs which are currently unused
    available_ips: HashSet<Ipv4Addr>,
}

impl IpPool {
    pub fn new(ip_pool: Ipv4Net, reserved_ips: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        let reserved_ips = HashSet::from_iter(reserved_ips);

        let available_ips = ip_pool
            .hosts()
            .filter(|ip| !reserved_ips.contains(ip))
            .collect();

        Self {
            ip_pool,
            reserved_ips,
            available_ips,
        }
    }

    pub fn allocate_ip(&mut self) -> Option<Ipv4Addr> {
        if let Some(ip) = self.available_ips.iter().next().cloned() {
            self.available_ips.remove(&ip);
            return Some(ip);
        }

        // we've run out of hosts.
        None
    }

    pub fn free_ip(&mut self, ip: Ipv4Addr) {
        if !self.ip_pool.contains(&ip) {
            warn!(ip = ?ip, "Attempt to free IP address from outside pool");
            return;
        }
        if self.reserved_ips.contains(&ip) {
            warn!(ip = ?ip, "Attempt to free reserved IP address");
            return;
        }

        self.available_ips.insert(ip);
    }
}

// Tests START -> panic, unwrap, expect allowed
#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn get_ip_pool() -> IpPool {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        IpPool::new(ip_pool, [local_ip, dns_ip])
    }

    #[test_case("10.125.0.1", "10.125.0.1", 1; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.2", 2; "Different Local and DNS IP")]
    fn used_ips_check(local_ip: &str, dns_ip: &str, expected_len: usize) {
        let ip_range: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip = local_ip.parse().unwrap();
        let dns_ip = dns_ip.parse().unwrap();
        let pool = IpPool::new(ip_range, [local_ip, dns_ip]);

        assert_eq!(
            pool.available_ips.len(),
            ip_range.hosts().count() - expected_len
        );
        assert!(pool.reserved_ips.contains(&local_ip));
        assert!(pool.reserved_ips.contains(&dns_ip));
    }

    #[test_case("10.125.0.1", "10.125.0.1"; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.3"; "Different Local and DNS IP")]
    fn alloc_ip(local_ip: &str, dns_ip: &str) {
        let ip_range: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip = local_ip.parse().unwrap();
        let dns_ip = dns_ip.parse().unwrap();
        let mut pool = IpPool::new(ip_range, [local_ip, dns_ip]);

        // Allocate IP
        let new_ip = pool.allocate_ip().unwrap();
        assert!(ip_range.contains(&new_ip));
        assert_ne!(new_ip, local_ip);
        assert_ne!(new_ip, dns_ip);
    }

    #[test_case("10.125.0.1", "10.125.0.1", 253; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.3", 252; "Different Local and DNS IP")]
    #[test_case("10.125.0.1", "8.8.8.8", 253; "Different Local and DNS IP. DNS ip in different subnet")]
    fn alloc_ip_exhaust(local_ip: &str, dns_ip: &str, available_ips: usize) {
        let ip_range: Ipv4Net = "10.125.0.0/24".parse().unwrap();
        let local_ip: Ipv4Addr = local_ip.parse().unwrap();
        let dns_ip: Ipv4Addr = dns_ip.parse().unwrap();
        let mut pool = IpPool::new(ip_range, [local_ip, dns_ip]);

        for _ in 1..=available_ips {
            let _ = pool.allocate_ip().unwrap();
        }

        assert_eq!(pool.allocate_ip(), None);
    }

    #[test_case(2, 2; "Free all allocated")]
    #[test_case(3, 2; "Free fewer than allocated")]
    fn free_ip(alloc_times: usize, free_times: usize) {
        let mut pool = get_ip_pool();
        let pool_size = 65536 - 2; // A /16 less network and broadcast addresses
        let reserved_ip_count: usize = 2;

        let mut alloced_ips = Vec::new();
        // Allocate IP
        for _ in 1..=alloc_times {
            let new_ip = pool.allocate_ip().unwrap();
            alloced_ips.push(new_ip);
        }

        assert_eq!(
            pool.available_ips.len(),
            pool_size - alloc_times - reserved_ip_count
        );

        // Free IP
        for _ in 1..=free_times {
            let remove_ip = alloced_ips.pop().unwrap();
            pool.free_ip(remove_ip);
        }

        assert_eq!(
            pool.available_ips.len(),
            pool_size - reserved_ip_count - alloc_times + free_times
        );
    }

    #[test_case("10.125.0.1"; "Free local ip")]
    #[test_case("10.125.0.2"; "Free dns ip")]
    #[test_case("10.125.0.9"; "Free unallocated ip")]
    #[test_case("192.168.1.1"; "Free unrelated ip")]
    fn free_reserved_or_unallocated_ip(ip: &str) {
        let mut pool = get_ip_pool();
        let pool_size = 65536 - 2 - 2; // A /16 less network and broadcast addresses and two reserved addresses

        assert_eq!(pool.available_ips.len(), pool_size);
        pool.free_ip(ip.parse().unwrap());
        assert_eq!(pool.available_ips.len(), pool_size);
    }
}
// Tests END -> panic, unwrap, expect allowed
