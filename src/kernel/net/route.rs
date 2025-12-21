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

static ROUTES: Mutex<[Option<Route>; 8]> =
    Mutex::new([None, None, None, None, None, None, None, None], "routes");

pub fn add_route(route: Route) -> Result<()> {
    let mut routes = ROUTES.lock();
    for slot in routes.iter_mut() {
        if slot.is_none() {
            *slot = Some(route);
            return Ok(());
        }
    }
    Err(Error::StorageFull)
}

pub fn lookup(dst: IpAddr) -> Option<Route> {
    let routes = ROUTES.lock();
    let mut best: Option<Route> = None;
    for r in routes.iter().flatten() {
        if (dst.0 & r.mask.0) == (r.dest.0 & r.mask.0) {
            if best
                .map(|b| mask_len(r.mask) > mask_len(b.mask))
                .unwrap_or(true)
            {
                best = Some(*r);
            }
        }
    }
    best
}

fn mask_len(mask: IpAddr) -> u32 {
    mask.0.count_ones()
}
