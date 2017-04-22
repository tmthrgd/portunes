pub mod v0 {
	use argon2rs::Variant;

	pub const PASSES: u32 = 3;
	pub const LANES: u32 = 2;
	pub const MEMORY: u32 = 1 << 19;
	pub const VARIANT: Variant = Variant::Argon2i;

	pub const SALT_LEN: usize = 14;
	pub const HASH_LEN: usize = 16;

	pub const REHASH: bool = false;

	pub const VERSION: u16 = 0;
}

pub use self::v0 as cur;
