use headers::*;

use params;

use std::io::{Read, Write};

use rand::{Rng, OsRng};

use hyper::server::{Request, Response, Handler};
use hyper::header;
use hyper::uri::RequestUri;
use hyper::status::StatusCode;
use hyper::method::Method;
#[allow(unused_imports)]
use hyper::mime::*;

use argon2rs::Argon2;
use argon2rs::verifier::constant_eq;

use byteorder::{BigEndian, ReadBytesExt};

use memset::memzero;

pub struct Hasher {
	argon_v0: Argon2,
	argon_cur: Argon2,
}

impl Hasher {
	pub fn new() -> Hasher {
		Hasher {
			argon_v0: Argon2::new(params::v0::PASSES,
			                      params::v0::LANES,
			                      params::v0::MEMORY,
			                      params::v0::VARIANT)
					.unwrap(),
			argon_cur: Argon2::new(params::cur::PASSES,
			                       params::cur::LANES,
			                       params::cur::MEMORY,
			                       params::cur::VARIANT)
					.unwrap(),
		}
	}

	fn hash(&self, mut req: Request, mut res: Response) {
		if req.method != Method::Post {
			res.headers_mut().set(header::Allow(vec![Method::Post]));
			return Hasher::error(res, StatusCode::MethodNotAllowed);
		};

		let data_len = req.headers
			.get::<header::ContentLength>()
			.unwrap_or(&header::ContentLength(0))
			.0 as usize;

		let mut salt = [0 as u8; params::cur::SALT_LEN];
		match OsRng::new() {
			Ok(mut rng) => rng.fill_bytes(salt.as_mut()),
			Err(err) => {
				return Hasher::error_msg(res, StatusCode::InternalServerError, err)
			}
		};

		let mut hash = [0 as u8; params::cur::HASH_LEN];
		{
			let ad = if let Some(hdr) = req.headers.get::<XAssociatedData>() {
				hdr.to_owned()
			} else {
				XAssociatedData(String::new())
			};

			let key = if let Some(hdr) = req.headers.get::<XKey>() {
				hdr.to_owned()
			} else {
				XKey(String::new())
			};

			if key.as_bytes().len() > 32 {
				return Hasher::error_msg(res,
				                         StatusCode::BadRequest,
				                         "X-Key header value too long");
			};

			let mut data = Vec::with_capacity(data_len);
			if let Err(err) = req.read_to_end(&mut data) {
				return Hasher::error_msg(res, StatusCode::InternalServerError, err);
			};

			self.argon_cur.hash(&mut hash, &data, &salt, key.as_bytes(), ad.as_bytes());

			unsafe { memzero(&mut data[0], data.len()) };
		};

		let hdr = [0 as u8; 2];

		*res.status_mut() = StatusCode::Ok;

		{
			let hdrs = res.headers_mut();
			hdrs.set(header::ContentType(mime!(Application / OctetStream)));
			hdrs.set(header::ContentLength((hdr.len() + salt.len() + hash.len()) as
			                               u64));
		};

		{
			let mut res = res.start().unwrap();
			res.write_all(hdr.as_ref()).unwrap();
			res.write_all(salt.as_ref()).unwrap();
			res.write_all(hash.as_ref()).unwrap();
		};
	}

	fn verify(&self, mut req: Request, mut res: Response) {
		if req.method != Method::Post {
			res.headers_mut().set(header::Allow(vec![Method::Post]));
			return Hasher::error(res, StatusCode::MethodNotAllowed);
		};

		let (argon, salt_len, hash_len, rehash) = match req.read_u16::<BigEndian>() {
			Ok(0) => {
				(&self.argon_v0,
				 params::v0::SALT_LEN,
				 params::v0::HASH_LEN,
				 params::v0::REHASH)
			}
			_ => {
				return Hasher::error_msg(res,
				                         StatusCode::BadRequest,
				                         "unsupported version")
			}
		};

		let mut salt = Vec::with_capacity(salt_len);
		salt.resize(salt_len, 0);
		if let Err(err) = req.read_exact(&mut salt) {
			return Hasher::error_msg(res, StatusCode::BadRequest, err);
		};

		let mut hash = Vec::with_capacity(hash_len);
		hash.resize(hash_len, 0);
		if let Err(err) = req.read_exact(&mut hash) {
			return Hasher::error_msg(res, StatusCode::BadRequest, err);
		};

		let ok = {
			let ad = if let Some(ad) = req.headers.get::<XAssociatedData>() {
				ad.to_owned()
			} else {
				XAssociatedData(String::new())
			};

			let key = if let Some(hdr) = req.headers.get::<XKey>() {
				hdr.to_owned()
			} else {
				XKey(String::new())
			};

			if key.as_bytes().len() > 32 {
				return Hasher::error_msg(res,
				                         StatusCode::BadRequest,
				                         "X-Key header value too long");
			};

			let mut data = Vec::new();
			if let Err(err) = req.read_to_end(&mut data) {
				return Hasher::error_msg(res, StatusCode::InternalServerError, err);
			};

			let mut expect = Vec::with_capacity(hash_len);
			expect.resize(hash_len, 0);
			argon.hash(&mut expect, &data, &salt, key.as_bytes(), ad.as_bytes());

			unsafe { memzero(&mut data[0], data.len()) };

			constant_eq(&expect, &hash)
		};

		*res.status_mut() = if ok {
			StatusCode::Ok
		} else {
			StatusCode::Forbidden
		};

		{
			let hdr = res.headers_mut();
			hdr.set(header::ContentLength(0));
			hdr.set(XRehash(rehash));
		};
	}

	fn error(mut res: Response, code: StatusCode) {
		*res.status_mut() = code;

		res.send(format!("{}", code).as_bytes()).unwrap();
	}

	fn error_msg<T>(mut res: Response, code: StatusCode, msg: T)
		where T: ::std::fmt::Display
	{
		*res.status_mut() = code;

		res.send(format!("{}\n\n{}\n", code, msg).as_bytes()).unwrap();
	}
}

impl Handler for Hasher {
	fn handle(&self, req: Request, mut res: Response) {
		res.headers_mut().set(ServerHeader {});

		match match req.uri {
		                      RequestUri::AbsolutePath(ref s) => s,
		                      _ => return Hasher::error(res, StatusCode::BadRequest),
		              }
		              .as_ref() {
			"/hash" => self.hash(req, res),
			"/verify" => self.verify(req, res),
			_ => Hasher::error(res, StatusCode::NotFound),
		};
	}
}
