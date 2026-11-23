//! Builders for synthetic captures, shared by the tests of this crate and of `wl-hybrid`.

mod big;
mod events;
mod files;
mod ng_options;
mod packets;
mod pcapng;
mod proc_mem;
mod raw;
mod sample;

pub use big::*;
pub use events::*;
pub use files::*;
pub use ng_options::*;
pub use packets::*;
pub use pcapng::*;
pub use proc_mem::*;
pub use raw::*;
pub use sample::*;

pub const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
pub const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
