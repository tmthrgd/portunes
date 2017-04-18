use std::fmt;

use hyper;
use hyper::header::{Header, HeaderFormat};

const SERVER_NAME: &'static str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

header! { (XAssociatedData, "X-Associated-Data") => [String] }
header! { (XKey, "X-Key") => [String] }

#[derive(Debug, Clone, Copy)]
pub struct XRehash(pub bool);

impl Header for XRehash {
	fn header_name() -> &'static str {
		"X-Rehash"
	}

	fn parse_header(_raw: &[Vec<u8>]) -> hyper::Result<XRehash> {
		unimplemented!()
	}
}

impl HeaderFormat for XRehash {
	fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(if self.0 { "1" } else { "0" })
	}
}

#[derive(Debug, Clone, Copy)]
pub struct ServerHeader {}

impl Header for ServerHeader {
	fn header_name() -> &'static str {
		"Server"
	}

	fn parse_header(_raw: &[Vec<u8>]) -> hyper::Result<ServerHeader> {
		unimplemented!()
	}
}

impl HeaderFormat for ServerHeader {
	fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(SERVER_NAME)
	}
}
