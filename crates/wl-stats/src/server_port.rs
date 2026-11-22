use std::collections::HashMap;

use wl_model::{ConversationStat, Transport};

use crate::service_name;

/// Tells the service side of a conversation from the ephemeral client side.
#[derive(Debug, Default)]
pub struct ServerPorts(HashMap<(Transport, u16), u32>);

impl ServerPorts {
    pub fn of(conversations: &[ConversationStat]) -> Self {
        let mut uses: HashMap<(Transport, u16), u32> = HashMap::new();
        for c in conversations {
            let (a, b) = (c.key.a_port, c.key.b_port);
            for p in a.into_iter().chain(b.filter(|_| b != a)) {
                *uses.entry((c.key.transport, p)).or_default() += 1;
            }
        }
        Self(uses)
    }

    /// The captured SYN-ACK wins; then the port used by more conversations (a server is reached
    /// by many clients, a client port by one), then a well-known service, then the lower port.
    pub fn pick(&self, c: &ConversationStat) -> Option<u16> {
        if c.server_port.is_some() {
            return c.server_port;
        }
        let t = c.key.transport;
        let (a, b) = match (c.key.a_port, c.key.b_port) {
            (Some(a), Some(b)) => (a, b),
            (a, b) => return a.or(b),
        };
        let uses = |p: u16| self.0.get(&(t, p)).copied().unwrap_or(0);
        let named = |p: u16| service_name(p, t).is_some();
        Some(match (uses(a).cmp(&uses(b)), named(a), named(b)) {
            (std::cmp::Ordering::Greater, ..) => a,
            (std::cmp::Ordering::Less, ..) => b,
            (_, true, false) => a,
            (_, false, true) => b,
            _ => a.min(b),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::FlowKey;

    fn conv(a_port: u16, b_port: u16, server_port: Option<u16>) -> ConversationStat {
        ConversationStat {
            key: FlowKey {
                a: "a".into(),
                b: "b".into(),
                transport: Transport::Tcp,
                a_port: Some(a_port),
                b_port: Some(b_port),
            },
            packets: 1,
            bytes: 1,
            first_rel: 0.0,
            last_rel: 0.0,
            protocol: "TCP".into(),
            server_port,
        }
    }

    fn pick(list: &[ConversationStat], i: usize) -> Option<u16> {
        ServerPorts::of(list).pick(&list[i])
    }

    #[test]
    fn syn_ack_beats_port_order() {
        assert_eq!(pick(&[conv(40001, 50051, Some(50051))], 0), Some(50051));
    }

    #[test]
    fn shared_port_is_the_server() {
        let list = [conv(40001, 50051, None), conv(40002, 50051, None)];
        assert_eq!(pick(&list, 0), Some(50051));
    }

    #[test]
    fn well_known_service_then_lower_port() {
        assert_eq!(pick(&[conv(40001, 443, None)], 0), Some(443));
        assert_eq!(pick(&[conv(40001, 50000, None)], 0), Some(40001));
    }
}
