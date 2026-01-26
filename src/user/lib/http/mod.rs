extern crate alloc;

mod error;
mod header;
mod method;
mod mime;
mod request;
mod response;
mod status;
mod version;

pub use error::Error;
pub use header::HttpHeader;
pub use method::HttpMethod;
pub use mime::mime_type_from_path;
pub use request::HttpRequest;
pub use response::HttpResponse;
pub use status::HttpStatus;
pub use version::HttpVersion;

pub type Result<T> = core::result::Result<T, Error>;
