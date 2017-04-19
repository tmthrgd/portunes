#[macro_use]
extern crate hyper;
extern crate argon2rs;
extern crate rand;
extern crate byteorder;
extern crate num_cpus;

mod headers;
mod params;
mod hasher;
mod memset;

use std::time::Duration;

use hyper::server::Server;

use hasher::Hasher;

fn main() {
	let mut srv = Server::http("0.0.0.0:8080").unwrap();
	srv.keep_alive(Some(Duration::from_secs(120)));
	srv.handle_threads(Hasher::new(), num_cpus::get()).unwrap();
}
