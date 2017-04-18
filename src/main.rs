#[macro_use]
extern crate hyper;
extern crate argon2rs;
extern crate rand;
extern crate byteorder;
extern crate num_cpus;

mod headers;
mod params;
mod hasher;

use hyper::server::Server;

use hasher::Hasher;

fn main() {
	Server::http("0.0.0.0:8080")
		.unwrap()
		.handle_threads(Hasher::new(), num_cpus::get())
		.unwrap();
}
