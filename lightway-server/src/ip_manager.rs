mod ip_pool;

use ipnet::Ipv4Net;
use lightway_core::{InsideIpConfig, ServerIpPool};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::{
    connection::{Connection, ConnectionState},
    metrics,
};

use ip_pool::IpPool;

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
    /// IP pool
    ip_pool: IpPool,
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
        let ip_pool = IpPool::new(ip_pool, reserved_ips);

        IpManager {
            inner: RwLock::new(IpManagerInner {
                ip_to_conn_map: HashMap::new(),
                ip_pool,
                static_ip_config,
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

        let Some(ip) = inner.ip_pool.allocate_ip() else {
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
        inner.ip_pool.free_ip(ip);
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
}

// Tests START -> panic, unwrap, expect allowed
#[cfg(test)]
mod tests {
    use ipnet::Ipv4Net;
    use std::sync::Arc;

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
    fn alloc_ip() {
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
    fn free_ip() {
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
    fn find_ip() {
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
