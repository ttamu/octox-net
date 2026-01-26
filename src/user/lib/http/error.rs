#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidHttpRequest,
    UnsupportedMethod,
    UnsupportedVersion,
}
