use anyhow::{Context, Result};
use route_manager::{AsyncRouteManager, Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

// LAN networks for RouteMode::Lan
const LAN_NETWORKS: [(IpAddr, u8); 5] = [
    (
        // RFC 1918 Class C private
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        16,
    ),
    (
        // RFC 1918 Class B private
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        12,
    ),
    (
        // RFC 1918 Class A private,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        8,
    ),
    (
        // RFC 3927 link-local
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        16,
    ),
    (
        // RFC 5771 multicast
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        24,
    ),
];

// Tunnel routes for high priority default routing
const TUNNEL_ROUTES: [(IpAddr, u8); 2] = [
    (
        // First half default route (0.0.0.0/1)
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        1,
    ),
    (
        // Second half default route (128.0.0.0/1)
        IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        1,
    ),
];

#[derive(Debug, PartialEq, Copy, Clone, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    Default,
    Lan,
    NoExec,
}

#[derive(Error, Debug)]
pub enum RoutingTableError {
    #[error("AsyncRoutingManager error {0}")]
    AsyncRoutingManagerError(std::io::Error),
    #[error("Failed to Add Route {0}")]
    AddRouteError(std::io::Error),
    #[error(
        "Insufficient permissions to modify routing table. Run with administrator/root privileges."
    )]
    InsufficientPermissions,
    #[error("RoutingManager error {0}")]
    RoutingManagerError(std::io::Error),
    #[error("Server route already exists, try modifying it instead")]
    ServerRouteAlreadyExists,
}

pub struct RoutingTable {
    routing_mode: RouteMode,
    route_manager: RouteManager,
    route_manager_async: AsyncRouteManager,
    vpn_routes: Vec<Route>,
    lan_routes: Vec<Route>,
    server_route: Option<Route>,
}

impl RoutingTable {
    pub fn new(routing_mode: RouteMode) -> Result<Self, RoutingTableError> {
        let route_manager = RouteManager::new().map_err(RoutingTableError::RoutingManagerError)?;
        let route_manager_async =
            AsyncRouteManager::new().map_err(RoutingTableError::AsyncRoutingManagerError)?;
        Ok(Self {
            routing_mode,
            route_manager,
            route_manager_async,
            vpn_routes: Vec::with_capacity(TUNNEL_ROUTES.len() + 1),
            lan_routes: Vec::with_capacity(LAN_NETWORKS.len()),
            server_route: None,
        })
    }

    pub async fn cleanup(&mut self) {
        self.cleanup_normal_routes().await;
        self.cleanup_lan_routes().await;
        self.cleanup_server_routes().await;
    }

    /// Adds Route
    async fn add_route(&mut self, route: &Route) -> Result<(), RoutingTableError> {
        self.route_manager_async.add(route).await.map_err(|e| {
            // Check if the error is related to permissions
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                RoutingTableError::InsufficientPermissions
            } else {
                RoutingTableError::AddRouteError(e)
            }
        })
    }

    /// Adds Routes and stores it
    pub async fn add_route_vpn(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.vpn_routes.push(route);
        Ok(())
    }

    /// Adds Server Route and stores it
    pub async fn add_route_server(&mut self, route: Route) -> Result<(), RoutingTableError> {
        if self.server_route.is_some() {
            return Err(RoutingTableError::ServerRouteAlreadyExists);
        }
        self.add_route(&route).await?;
        self.server_route = Some(route);
        Ok(())
    }

    /// Adds LAN Route and stores it
    pub async fn add_route_lan(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.lan_routes.push(route);
        Ok(())
    }

    /// Cleans up LAN routes
    pub async fn cleanup_lan_routes(&mut self) {
        for r in self.lan_routes.drain(..) {
            self.route_manager_async
                .delete(&r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete LAN route: {r}, error: {e}");
                })
        }
    }

    /// Cleans up server routes
    pub async fn cleanup_server_routes(&mut self) {
        if let Some(r) = &self.server_route {
            self.route_manager_async
                .delete(r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete server route: {r}, error: {e}");
                })
        }
        self.server_route = None;
    }

    /// Cleans up normal routes
    pub async fn cleanup_normal_routes(&mut self) {
        for r in self.vpn_routes.drain(..) {
            self.route_manager_async
                .delete(&r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete route: {r}, error: {e}");
                })
        }
    }

    /// Clean up for program unwind
    pub fn cleanup_sync(&mut self) {
        for route in &self.vpn_routes {
            if let Err(e) = self.route_manager.delete(route) {
                warn!(
                    "Failed to delete VPN route during drop: {}, error: {}",
                    route, e
                );
            }
        }

        for route in &self.lan_routes {
            if let Err(e) = self.route_manager.delete(route) {
                warn!(
                    "Failed to delete LAN route during drop: {}, error: {}",
                    route, e
                );
            }
        }

        if let Some(route) = &self.server_route {
            if let Err(e) = self.route_manager.delete(route) {
                warn!(
                    "Failed to delete server route during drop: {}, error: {}",
                    route, e
                );
            }
        }
    }
}

impl Drop for RoutingTable {
    fn drop(&mut self) {
        self.cleanup_sync();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use test_case::test_case;
    use tokio;
    use tun::AbstractDevice;

    const SERVER_ROUTES_COUNT: usize = 1;
    const DNS_ROUTES_COUNT: usize = 1;

    const EXTERNAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    const TEST_TARGET_IP1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
    const TEST_TARGET_IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2));
    const TEST_TARGET_IP3: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 3));

    /// Helper to create test routes with gateway lookup
    fn create_test_routes_with_gateway(
        routing_table: &mut RoutingTable,
    ) -> (Route, Route, Route, IpAddr) {
        let default_route = routing_table.find_route(&EXTERNAL_IP).unwrap();
        let gateway_ip = default_route.gateway().unwrap();

        let route1 = Route::new(TEST_TARGET_IP1, 32).with_gateway(gateway_ip);
        let route2 = Route::new(TEST_TARGET_IP2, 32).with_gateway(gateway_ip);
        let route3 = Route::new(TEST_TARGET_IP3, 32).with_gateway(gateway_ip);

        (route1, route2, route3, gateway_ip)
    }

    /// Compares two routes for equality based on destination, prefix, gateway, and interface
    fn routes_equal(route1: &Route, route2: &Route) -> bool {
        route1.destination() == route2.destination()
            && route1.prefix() == route2.prefix()
            && route1.gateway() == route2.gateway()
            && route1.if_index() == route2.if_index()
    }

    /// Creates a test setup with RouteRestorer and RoutingTable
    /// Returns tuple where RouteRestorer is dropped last for proper cleanup
    fn create_test_setup(route_mode: RouteMode) -> (RouteRestorer, RoutingTable) {
        // Capture initial state FIRST
        let restorer = RouteRestorer::new();

        // Then create RoutingTable
        let routing_table = RoutingTable::new(route_mode).unwrap();

        // Return tuple - RoutingTable will be dropped first, RouteRestorer last
        (restorer, routing_table)
    }

    /// Test wrapper around RouteManager for cleanup purposes
    struct RouteRestorer {
        initial_routes: Vec<Route>,
    }

    impl RouteRestorer {
        fn new() -> Self {
            let mut route_manager = RouteManager::new().unwrap();
            let initial_routes = route_manager.list().unwrap();
            Self { initial_routes }
        }
    }

    impl Drop for RouteRestorer {
        /// Restores the system routing table to match the target routes
        /// Removes routes that shouldn't be there and adds routes that should be there
        fn drop(&mut self) {
            let mut route_manager = RouteManager::new().unwrap();
            let current_routes = route_manager.list().unwrap_or_default();

            // Remove routes that are in current but not in target
            for current_route in &current_routes {
                let should_keep = self
                    .initial_routes
                    .iter()
                    .any(|target_route| routes_equal(current_route, target_route));

                if !should_keep {
                    let _ = route_manager.delete(current_route);
                }
            }

            // Add routes that are in target but not in current
            for target_route in self.initial_routes.iter() {
                let already_exists = current_routes
                    .iter()
                    .any(|current_route| routes_equal(current_route, target_route));

                if !already_exists {
                    let _ = route_manager.add(target_route);
                }
            }
        }
    }

    async fn create_test_tun(
        local_ip: IpAddr,
    ) -> Result<(tun::Device, u32), Box<dyn std::error::Error>> {
        let mut config = tun::Configuration::default();
        config
            .address(local_ip.to_string())
            .netmask("255.255.255.0")
            .up();

        let tun_device = tun::create(&config)?;

        // Add 50ms sleep to allow TUN device to be fully initialized
        // NOTE: This sometimes adds an additional route after the tests have stored the initial route
        //       which may lead to inaccurate tests. 50ms is eternity and enough to stabilise this.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let if_index = tun_device.tun_index().unwrap() as u32;

        Ok((tun_device, if_index))
    }

    #[derive(Debug)]
    enum RouteAddMethod {
        Standard,
        Server,
        Lan,
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    fn test_new_routing_table(route_mode: RouteMode) {
        let (_restorer, routing_table) = create_test_setup(route_mode);
        assert_eq!(routing_table.routing_mode, route_mode);
        assert_eq!(routing_table.vpn_routes.len(), 0);
        assert_eq!(routing_table.lan_routes.len(), 0);
        assert!(routing_table.server_route.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_cleanup_empty_routes() {
        let (_restorer, mut routing_table) = create_test_setup(RouteMode::Default);

        // Get initial route count from the system
        let initial_count = routing_table.route_manager.list().unwrap().len();

        // Cleanup should not change system routes since vpn_routes is empty
        routing_table.cleanup().await;

        // Check that vpn_routes remains empty
        assert_eq!(routing_table.vpn_routes.len(), 0);
        assert_eq!(routing_table.lan_routes.len(), 0);

        // Check that system routes are unchanged
        let final_count = routing_table.route_manager.list().unwrap().len();
        assert_eq!(initial_count, final_count);
        assert!(routing_table.server_route.is_none());
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[serial_test::serial(routing_table)]
    fn test_cleanup_sync(route_mode: RouteMode) {
        let (_restorer, mut routing_table) = create_test_setup(route_mode);

        // Get initial route count from the system
        let initial_count = routing_table.route_manager.list().unwrap().len();

        // Create test routes using shared fixtures
        let (vpn_route, lan_route, server_route, _gateway_ip) =
            create_test_routes_with_gateway(&mut routing_table);

        // Add routes directly to the sync route manager and store them
        routing_table.route_manager.add(&vpn_route).unwrap();
        routing_table.vpn_routes.push(vpn_route.clone());

        routing_table.route_manager.add(&lan_route).unwrap();
        routing_table.lan_routes.push(lan_route.clone());

        routing_table.route_manager.add(&server_route).unwrap();
        routing_table.server_route = Some(server_route.clone());

        // Verify routes were added to the system
        let routes_after_add = routing_table.route_manager.list().unwrap();
        let routes_added = routes_after_add.len() - initial_count;
        assert_eq!(routes_added, 3);

        // Verify internal state
        assert_eq!(routing_table.vpn_routes.len(), 1);
        assert_eq!(routing_table.lan_routes.len(), 1);
        assert!(routing_table.server_route.is_some());

        // Test cleanup_sync
        routing_table.cleanup_sync();

        // Verify routes were removed from the system
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let final_count = routes_after_cleanup.len();
        assert_eq!(final_count, initial_count);

        // Verify internal state is unchanged (cleanup_sync doesn't modify internal vectors)
        assert_eq!(routing_table.vpn_routes.len(), 1);
        assert_eq!(routing_table.lan_routes.len(), 1);
        assert!(routing_table.server_route.is_some());
    }

    #[test_case(RouteAddMethod::Standard, 1, 0, 0)]
    #[test_case(RouteAddMethod::Server, 0, 1, 0)]
    #[test_case(RouteAddMethod::Lan, 0, 0, 1)]
    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_add_single_route(
        add_method: RouteAddMethod,
        expected_vpn: usize,
        expected_server: usize,
        expected_lan: usize,
    ) {
        let (_restorer, mut routing_table) = create_test_setup(RouteMode::Default);

        // Get initial route count from the system
        let initial_count = routing_table.route_manager.list().unwrap().len();

        // Create test route using shared fixtures
        let (route1, _route2, _route3, _gateway_ip) =
            create_test_routes_with_gateway(&mut routing_table);

        // Test adding route using the specified method
        match add_method {
            RouteAddMethod::Standard => routing_table.add_route_vpn(route1.clone()).await.unwrap(),
            RouteAddMethod::Server => routing_table
                .add_route_server(route1.clone())
                .await
                .unwrap(),
            RouteAddMethod::Lan => routing_table.add_route_lan(route1.clone()).await.unwrap(),
        };
        let routes_after_add1 = routing_table.route_manager.list().unwrap();
        assert_eq!(routes_after_add1.len(), initial_count + 1);

        // Verify route counts using test case parameters
        assert_eq!(routing_table.vpn_routes.len(), expected_vpn);
        assert_eq!(
            routing_table.server_route.is_some() as usize,
            expected_server
        );
        assert_eq!(routing_table.lan_routes.len(), expected_lan);

        // Verify the correct route is stored in the right collection
        match add_method {
            RouteAddMethod::Standard => {
                assert_eq!(routing_table.vpn_routes[0], route1);
            }
            RouteAddMethod::Server => {
                assert_eq!(routing_table.server_route, Some(route1.clone()));
            }
            RouteAddMethod::Lan => {
                assert_eq!(routing_table.lan_routes[0], route1);
            }
        }

        // Verify the route was actually added to the system
        let route_found = routes_after_add1
            .iter()
            .any(|r| r.destination() == route1.destination() && r.gateway() == route1.gateway());

        assert!(route_found);
    }
}
