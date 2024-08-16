use ipnet::{Ipv4AddrRange, Ipv4Net};
use lightway_core::{InsideIpConfig, ServerIpPool};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::{
    connection::{Connection, ConnectionState},
    metrics,
};

/// IpManager - Manages IP pool to assign to clients
/// Similar to DHCP server
///
/// Generic over T to make it testable
pub(crate) struct IpManager<T = Arc<Connection>> {
    inner: RwLock<IpManagerInner<T>>,
}

/// Inner struct to use for managing IP pool
struct IpManagerInner<T> {
    /// Client IP to lightway::Connection hashmap
    ip_to_conn_map: HashMap<Ipv4Addr, T>,
    /// Reserved IPs, must never be allocated to a client.
    reserved_ips: HashSet<Ipv4Addr>,
    /// Hashset of IPs allocated to client (also contains local_ip and dns_ip)
    used_ips: HashSet<Ipv4Addr>,
    /// Hashset to store IPs which are freed after the client has been disconnected
    freed_ips: HashSet<Ipv4Addr>,
    /// A cursor to find the next IP to allocate.
    unused_ips: Ipv4AddrRange,
    /// Static inside ip config which should be sent to clients in case of IP translation
    static_ip_config: InsideIpConfig,
}

impl ServerIpPool<ConnectionState> for IpManager {
    fn alloc(&self, state: &mut ConnectionState) -> Option<InsideIpConfig> {
        // Recover weak handle to connection which we always set
        let conn = state.conn.get().unwrap();
        // Try to recover a strong handle, the connection may have gone away.
        let conn = conn.upgrade()?;

        // If this connection has already been allocated an IP then
        // return the corresponding config -- otherwise allocate a new
        // IP.
        match state.internal_ip {
            Some(ip) => Some(self.inside_ip_config(ip)),
            None => {
                let (allocation, config) = self.alloc(conn)?;

                state.internal_ip = Some(allocation);

                Some(config)
            }
        }
    }

    fn free(&self, state: &mut ConnectionState) {
        if let Some(ip) = state.internal_ip.take() {
            self.free(ip);
        }
    }
}

impl<T> IpManager<T> {
    pub(crate) fn new(
        ip_pool: Ipv4Net,
        reserved_ips: impl IntoIterator<Item = Ipv4Addr>,
        static_ip_config: InsideIpConfig,
    ) -> Self {
        let reserved_ips = HashSet::from_iter(reserved_ips);

        // Initialize used IPs with reserved IPs so that they will
        // never be assigned to clients.
        let used_ips = reserved_ips.clone();

        let unused_ips = ip_pool.hosts();

        let freed_ips = HashSet::new();
        IpManager {
            inner: RwLock::new(IpManagerInner {
                ip_to_conn_map: HashMap::new(),
                reserved_ips,
                used_ips,
                freed_ips,
                static_ip_config,
                unused_ips,
            }),
        }
    }

    pub(crate) fn allocated_ips_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.ip_to_conn_map.len()
    }

    fn inside_ip_config(&self, ip: Ipv4Addr) -> InsideIpConfig {
        let inner = self.inner.read().unwrap();
        inner.config_for_ip(ip)
    }

    fn alloc(&self, conn: T) -> Option<(Ipv4Addr, InsideIpConfig)> {
        let mut inner = self.inner.write().unwrap();

        let Some(ip) = inner.allocate_ip() else {
            metrics::connection_rejected_no_free_ip();
            return None;
        };

        info!(ip = ?ip, "Alloc");

        inner.ip_to_conn_map.insert(ip, conn);

        let config = inner.config_for_ip(ip);

        Some((ip, config))
    }

    fn free(&self, ip: Ipv4Addr) {
        let mut inner = self.inner.write().unwrap();
        info!(ip = ?ip, "Free");
        inner.free_ip(ip);
        inner.ip_to_conn_map.remove(&ip);
    }
}

impl<T: Clone> IpManager<T> {
    pub(crate) fn find_connection(&self, ip: Ipv4Addr) -> Option<T> {
        let inner = self.inner.read().unwrap();
        inner.ip_to_conn_map.get(&ip).cloned()
    }
}

impl<T> IpManagerInner<T> {
    fn config_for_ip(&self, _ip: Ipv4Addr) -> InsideIpConfig {
        self.static_ip_config
    }

    fn allocate_ip(&mut self) -> Option<Ipv4Addr> {
        // Check in freed_ips first
        if let Some(ip) = self.freed_ips.iter().next().cloned() {
            self.freed_ips.remove(&ip);
            self.used_ips.insert(ip);
            return Some(ip);
        }

        loop {
            let Some(ip) = self.unused_ips.next() else {
                // we've run out of hosts.
                return None;
            };

            // Already present in used_ips. Maybe a reserved IP.
            if self.used_ips.contains(&ip) {
                continue;
            }

            // This IP is a good one to use.
            self.used_ips.insert(ip);

            return Some(ip);
        }
    }

    fn free_ip(&mut self, ip: Ipv4Addr) {
        if self.reserved_ips.contains(&ip) {
            warn!(ip = ?ip, "Attempt to free reserved IP address");
            return;
        }

        let freed_ip = self.used_ips.take(&ip);
        if let Some(ip) = freed_ip {
            self.freed_ips.insert(ip);
        }
    }
}

// Tests START -> panic, unwrap, expect allowed
#[cfg(test)]
mod tests {
    use ipnet::{IpAdd, Ipv4Net};
    use std::sync::Arc;
    use test_case::test_case;

    use super::*;

    #[derive(PartialEq, Debug, Clone)]
    struct DummyConnection;

    fn get_static_ip_config() -> InsideIpConfig {
        InsideIpConfig {
            client_ip: "10.125.0.5".parse().unwrap(),
            server_ip: "10.125.0.6".parse().unwrap(),
            dns_ip: "10.125.0.1".parse().unwrap(),
        }
    }
    fn get_ip_manager_with_dummy_connection() -> IpManager<DummyConnection> {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        IpManager::new(ip_pool, [local_ip, dns_ip], get_static_ip_config())
    }

    #[test_case("10.125.0.1", "10.125.0.1", 1; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.2", 2; "Different Local and DNS IP")]
    fn ip_manager_inner_used_ips_check(local_ip: &str, dns_ip: &str, expected_len: usize) {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip = local_ip.parse().unwrap();
        let dns_ip = dns_ip.parse().unwrap();
        let ip_manager: IpManager<DummyConnection> =
            IpManager::new(ip_pool, [local_ip, dns_ip], get_static_ip_config());
        let inner = ip_manager.inner.read().unwrap();

        assert!(inner.used_ips.contains(&local_ip));
        assert!(inner.used_ips.contains(&dns_ip));
        assert_eq!(inner.used_ips.len(), expected_len);
        assert_eq!(inner.freed_ips.len(), 0);
        assert_eq!(
            inner.unused_ips,
            Ipv4AddrRange::new(
                "10.125.0.1".parse().unwrap(),
                "10.125.255.254".parse().unwrap(),
            )
        );
        assert_eq!(inner.ip_to_conn_map.len(), 0);
        assert!(inner.reserved_ips.contains(&local_ip));
        assert!(inner.reserved_ips.contains(&dns_ip));
    }

    #[test_case("10.125.0.1", "10.125.0.1", "10.125.0.2", 2; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.2", "10.125.0.3", 3; "Consecutive Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.3", "10.125.0.2", 3; "Different Local and DNS IP")]
    fn ip_manager_inner_alloc_ip(
        local_ip: &str,
        dns_ip: &str,
        exp_new_ip: &str,
        used_ips_len: usize,
    ) {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip = local_ip.parse().unwrap();
        let dns_ip = dns_ip.parse().unwrap();
        let ip_manager: IpManager<DummyConnection> =
            IpManager::new(ip_pool, [local_ip, dns_ip], get_static_ip_config());
        let mut inner = ip_manager.inner.write().unwrap();

        // Allocate IP
        let new_ip = inner.allocate_ip();
        assert_eq!(new_ip, Some(exp_new_ip.parse().unwrap()));
        assert_eq!(inner.used_ips.len(), used_ips_len);
    }

    #[test_case("10.125.0.1", "10.125.0.1", 253; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.2", 252; "Consecutive Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.3", 252; "Different Local and DNS IP")]
    #[test_case("10.125.0.1", "8.8.8.8", 253; "Different Local and DNS IP. DNS ip in different subnet")]
    fn ip_manager_inner_alloc_ip_exhaust(local_ip: &str, dns_ip: &str, available_ips: usize) {
        let ip_pool: Ipv4Net = "10.125.0.0/24".parse().unwrap();
        let local_ip: Ipv4Addr = local_ip.parse().unwrap();
        let dns_ip: Ipv4Addr = dns_ip.parse().unwrap();
        let ip_manager: IpManager<DummyConnection> =
            IpManager::new(ip_pool, [local_ip, dns_ip], get_static_ip_config());
        let mut inner = ip_manager.inner.write().unwrap();

        for _ in 1..=available_ips {
            let _ = inner.allocate_ip().unwrap();
        }

        assert_eq!(inner.allocate_ip(), None);
    }

    #[test_case(2, 2; "Alloc and free all")]
    #[test_case(3, 2; "Alloc and free less")]
    fn ip_manager_inner_free_ip(alloc_times: usize, free_times: usize) {
        let ip_manager = get_ip_manager_with_dummy_connection();
        let mut inner = ip_manager.inner.write().unwrap();
        let reserved_ip_count: usize = 2;

        let mut alloced_ips = Vec::new();
        // Allocate IP
        for _ in 1..=alloc_times {
            let new_ip = inner.allocate_ip().unwrap();
            alloced_ips.push(new_ip);
        }

        assert_eq!(inner.used_ips.len(), alloc_times + reserved_ip_count);
        assert_eq!(inner.freed_ips.len(), 0);

        // Free IP
        for _ in 1..=free_times {
            let remove_ip = alloced_ips.pop().unwrap();
            inner.free_ip(remove_ip);
        }

        assert_eq!(
            inner.used_ips.len(),
            alloc_times - free_times + reserved_ip_count
        );
        assert_eq!(inner.freed_ips.len(), free_times);
    }

    #[test]
    fn ip_manager_inner_allocate_after_free_ip() {
        let ip_manager = get_ip_manager_with_dummy_connection();
        let mut inner = ip_manager.inner.write().unwrap();
        let reserved_ip_count: usize = 2;

        // Allocate two ips and then free one
        let new_ip1 = inner.allocate_ip().unwrap();
        assert_eq!(inner.used_ips.len(), reserved_ip_count + 1);
        let new_ip2 = inner.allocate_ip().unwrap();
        assert_eq!(inner.used_ips.len(), reserved_ip_count + 2);
        inner.free_ip(new_ip1);
        assert_eq!(inner.used_ips.len(), reserved_ip_count + 1);

        // Now allocate to get already freed IP
        let new_ip_after_free = inner.allocate_ip().unwrap();
        assert_eq!(new_ip_after_free, new_ip1);

        // Allocate again to get new IP
        let new_ip = inner.allocate_ip().unwrap();
        assert_eq!(new_ip, new_ip2.saturating_add(1));
    }

    #[test_case("10.125.0.1"; "Free local ip")]
    #[test_case("10.125.0.2"; "Free dns ip")]
    #[test_case("10.125.0.9"; "Free unallocated ip")]
    fn ip_manager_inner_free_reserved_or_unallocated_ip(ip: &str) {
        let ip_manager = get_ip_manager_with_dummy_connection();
        let mut inner = ip_manager.inner.write().unwrap();

        assert_eq!(inner.used_ips.len(), 2);
        // Now allocate to get already freed IP
        inner.free_ip(ip.parse().unwrap());
        assert_eq!(inner.used_ips.len(), 2);
    }

    #[derive(PartialEq, Debug, Clone)]
    struct TestConnection(Arc<usize>);

    impl TestConnection {
        fn new(n: usize) -> Self {
            Self(Arc::new(n))
        }
    }

    fn get_ip_manager_with_test_connection() -> IpManager<TestConnection> {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        IpManager::new(ip_pool, [local_ip, dns_ip], get_static_ip_config())
    }

    #[test]
    fn ip_manager_alloc_ip() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);

        let (local_ip1, ip_config) = ip_manager.alloc(conn1).unwrap();
        assert_eq!(
            ip_config,
            get_static_ip_config(),
            "IP config should match static config"
        );

        let (local_ip2, ip_config) = ip_manager.alloc(conn2).unwrap();
        assert_eq!(
            ip_config,
            get_static_ip_config(),
            "IP config should match static config"
        );

        let inner = ip_manager.inner.read().unwrap();

        assert!(inner.ip_to_conn_map.contains_key(&local_ip1));
        assert!(inner.ip_to_conn_map.contains_key(&local_ip2));
        assert_eq!(inner.ip_to_conn_map.len(), 2);
    }

    #[test]
    fn ip_manager_free_ip() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);

        let (alloc1, _) = ip_manager.alloc(conn1.clone()).unwrap();
        let (alloc2, _) = ip_manager.alloc(conn2.clone()).unwrap();

        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 2);
        }

        ip_manager.free(alloc1);
        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 1);
        }

        ip_manager.free(alloc2);
        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 0);
        }
    }

    #[test]
    fn ip_manager_find_ip() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);

        let (ip1, _) = ip_manager.alloc(conn1.clone()).unwrap();
        let (ip2, _) = ip_manager.alloc(conn2.clone()).unwrap();

        // Getting ip1 and verify
        let conn = ip_manager.find_connection(ip1).unwrap();
        assert_eq!(*conn.0, 1);
        assert!(Arc::ptr_eq(&conn.0, &conn1.0));
        assert!(!Arc::ptr_eq(&conn.0, &conn2.0));

        // Getting ip2 and verify
        let conn = ip_manager.find_connection(ip2).unwrap();
        assert_eq!(*conn.0, 2);
        assert!(Arc::ptr_eq(&conn.0, &conn2.0));
        assert!(!Arc::ptr_eq(&conn.0, &conn1.0));
    }

    #[test]
    fn reserved_ips_never_allocated() {
        let ip_pool: Ipv4Net = "10.125.0.0/24".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        let reserved_ip1: Ipv4Addr = "10.125.0.34".parse().unwrap();
        let reserved_ip2: Ipv4Addr = "10.125.0.220".parse().unwrap();

        let ip_manager = IpManager::new(
            ip_pool,
            [local_ip, dns_ip, reserved_ip1, reserved_ip2],
            get_static_ip_config(),
        );
        // Allocate every possible IP and check we never get a reserved one
        let mut count = 0;
        while let Some((ip, _)) = ip_manager.alloc(DummyConnection) {
            count += 1;
            assert_ne!(ip, local_ip);
            assert_ne!(ip, dns_ip);
            assert_ne!(ip, reserved_ip1);
            assert_ne!(ip, reserved_ip2);
        }

        let total_hosts = ip_pool.hosts().count();
        assert_eq!(count, total_hosts - 4); // 4 == local + dns + 2x reserved
    }
}

// Tests END -> panic, unwrap, expect allowed
