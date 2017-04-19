// Copyright (C) 2016 quininer@live.com
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

use std::ptr;

#[inline(never)]
pub unsafe fn memset<T>(s: *mut T, c: i32, n: usize) {
	let s = s as *mut u8;
	let c = c as u8;

	for i in 0..n as isize {
		ptr::write_volatile(s.offset(i), c);
	}
}

#[inline]
pub unsafe fn memzero<T>(dest: *mut T, n: usize) {
	memset(dest, 0, n);
}
