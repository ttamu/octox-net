use crate::error::{Error, Result};
use crate::net::ip::IpAddr;
use crate::spinlock::Mutex;

#[derive(Clone, Copy)]
pub struct Route {
    pub dest: IpAddr,
    pub mask: IpAddr,
    pub gateway: Option<IpAddr>,
    pub dev: &'static str,
}

struct RouteTable {
    routes: Mutex<[Option<Route>; 8]>,
}

impl RouteTable {
    const fn new() -> Self {
        Self {
            routes: Mutex::new([None, None, None, None, None, None, None, None], "routes"),
        }
    }

    fn add_route(&self, route: Route) -> Result<()> {
        let mut routes = self.routes.lock();
        for slot in routes.iter_mut() {
            if slot.is_none() {
                *slot = Some(route);
                return Ok(());
            }
        }
        Err(Error::StorageFull)
    }

    fn lookup(&self, dst: IpAddr) -> Option<Route> {
        let routes = self.routes.lock();
        let mut best: Option<Route> = None;
        for r in routes.iter().flatten() {
            if (dst.0 & r.mask.0) == (r.dest.0 & r.mask.0)
                && best
                    .map(|b| mask_len(r.mask) > mask_len(b.mask))
                    .unwrap_or(true)
            {
                best = Some(*r);
            }
        }
        best
    }
}

static ROUTES: RouteTable = RouteTable::new();

pub fn add_route(route: Route) -> Result<()> {
    ROUTES.add_route(route)
}

pub fn lookup(dst: IpAddr) -> Option<Route> {
    ROUTES.lookup(dst)
}

fn mask_len(mask: IpAddr) -> u32 {
    mask.0.count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test_case]
    fn mask_len_counts_ones() {
        let mask = IpAddr::new(255, 255, 255, 0);
        assert_eq!(mask_len(mask), 24);
    }

    #[test_case]
    fn lookup_chooses_longest_prefix() {
        let table = RouteTable::new();
        table
            .add_route(Route {
                dest: IpAddr::new(10, 0, 0, 0),
                mask: IpAddr::new(255, 0, 0, 0),
                gateway: None,
                dev: "eth0",
            })
            .unwrap();
        table
            .add_route(Route {
                dest: IpAddr::new(10, 1, 0, 0),
                mask: IpAddr::new(255, 255, 0, 0),
                gateway: None,
                dev: "eth1",
            })
            .unwrap();

        let hit = table.lookup(IpAddr::new(10, 1, 2, 3)).unwrap();
        assert_eq!(hit.dev, "eth1");

        let fallback = table.lookup(IpAddr::new(10, 2, 3, 4)).unwrap();
        assert_eq!(fallback.dev, "eth0");
    }

    #[test_case]
    fn add_route_fails_when_full() {
        let table = RouteTable::new();
        for idx in 0..8 {
            table
                .add_route(Route {
                    dest: IpAddr::new(10, 0, 0, idx as u8),
                    mask: IpAddr::new(255, 255, 255, 0),
                    gateway: None,
                    dev: "eth0",
                })
                .unwrap();
        }

        let err = table
            .add_route(Route {
                dest: IpAddr::new(192, 168, 0, 0),
                mask: IpAddr::new(255, 255, 0, 0),
                gateway: None,
                dev: "eth1",
            })
            .unwrap_err();
        assert_eq!(err, Error::StorageFull);
    }
}
