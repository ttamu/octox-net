pub(crate) fn get_time_ms() -> u64 {
    let ticks = crate::trap::TICKS.lock();
    (*ticks as u64) * (crate::param::TICK_MS as u64)
}
