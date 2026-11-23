//! TCP segments and connections for the hand-built captures.

use std::net::Ipv4Addr;

use wl_native::test_util::tcp4_raw;

pub const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const SYN_F: u8 = 0x02;
pub const ACK_F: u8 = 0x10;
pub const FIN_F: u8 = 0x01;
pub const RST_F: u8 = 0x04;
pub const PSH_F: u8 = 0x08;

/// A TCP segment between client `A` at `port` and server `B` at `server`.
#[derive(Clone, Copy)]
pub struct Seg<'a> {
    server: u16,
    from_a: bool,
    port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    opts: &'a [u8],
    data: &'a [u8],
}

impl<'a> Seg<'a> {
    pub fn new(server: u16, from_a: bool, port: u16, seq: u32, ack: u32, flags: u8) -> Self {
        Seg {
            server,
            from_a,
            port,
            seq,
            ack,
            flags,
            opts: &[],
            data: &[],
        }
    }

    pub fn opts(mut self, opts: &'a [u8]) -> Self {
        self.opts = opts;
        self
    }

    pub fn data(mut self, data: &'a [u8]) -> Self {
        self.data = data;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let (s, d) = if self.from_a {
            ((A, self.port), (B, self.server))
        } else {
            ((B, self.server), (A, self.port))
        };
        tcp4_raw(s, d, self.seq, self.ack, self.flags, self.opts, self.data)
    }
}

/// One TCP connection whose sequence numbers advance like a real one.
pub struct Conn {
    port: u16,
    server: u16,
    c_seq: u32,
    s_seq: u32,
    pub out: Vec<Vec<u8>>,
}

impl Conn {
    /// A connection after its three way handshake.
    pub fn open(port: u16, server: u16) -> Self {
        let out = vec![
            Seg::new(server, true, port, 1000, 0, SYN_F).build(),
            Seg::new(server, false, port, 5000, 1001, SYN_F | ACK_F).build(),
            Seg::new(server, true, port, 1001, 5001, ACK_F).build(),
        ];
        Conn {
            port,
            server,
            c_seq: 1001,
            s_seq: 5001,
            out,
        }
    }

    pub fn client(&mut self, data: &[u8]) {
        let seg = Seg::new(
            self.server,
            true,
            self.port,
            self.c_seq,
            self.s_seq,
            PSH_F | ACK_F,
        );
        self.out.push(seg.data(data).build());
        self.c_seq += data.len() as u32;
    }

    pub fn server(&mut self, data: &[u8]) {
        let seg = Seg::new(
            self.server,
            false,
            self.port,
            self.s_seq,
            self.c_seq,
            PSH_F | ACK_F,
        );
        self.out.push(seg.data(data).build());
        self.s_seq += data.len() as u32;
    }
}
