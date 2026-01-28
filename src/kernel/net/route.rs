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
