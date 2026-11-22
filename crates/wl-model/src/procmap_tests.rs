use super::*;

const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22002 1 0000000000000000 100 0 0 10 0
   2: 0F02A8C0:C350 22D8B85D:01BB 01 00000000:00000000 02:000A1B2C 00000000  1000        0 33003 2 0000000000000000 20 4 30 10 -1
   3: 0F02A8C0:C351 22D8B85D:01BB 06 00000000:00000000 03:00000F9C 00000000     0        0 0 3 0000000000000000
   4: garbage
";

const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44004 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000F02A8C0:9C40 0000000000000000FFFF000022D8B85D:01BB 01 00000000:00000000 02:00000DAD 00000000  1000        0 55005 2 0000000000000000 20 4 30 10 -1
   2: B80D0120000000000000000001000000:D431 B80D0120000000000000000002000000:01BB 01 00000000:00000000 02:00000DAD 00000000  1000        0 66006 2 0000000000000000 20 4 30 10 -1
";

const UDP: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  120: 0F02A8C0:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 77007 2 0000000000000000 0
  200: 0F02A8C0:D2F1 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 88008 2 0000000000000000 0
";

fn owner(inode: u64, pid: u32, name: &str) -> (u64, ProcessInfo) {
    (
        inode,
        ProcessInfo {
            pid,
            name: name.into(),
        },
    )
}

fn sample_map() -> ProcessMap {
    let mut sockets = parse_proc_net(TCP, SockProto::Tcp);
    sockets.extend(parse_proc_net(TCP6, SockProto::Tcp));
    sockets.extend(parse_proc_net(UDP, SockProto::Udp));
    let owners = HashMap::from([
        owner(22002, 900, "nginx"),
        owner(33003, 1234, "firefox"),
        owner(55005, 1234, "firefox"),
        owner(66006, 4321, "curl"),
        owner(77007, 700, "dhclient"),
        owner(88008, 800, "systemd-resolve"),
    ]);
    ProcessMap::build(&sockets, &owners)
}

fn key(a: &str, ap: u16, b: &str, bp: u16, transport: Transport) -> FlowKey {
    FlowKey {
        a: a.into(),
        b: b.into(),
        transport,
        a_port: Some(ap),
        b_port: Some(bp),
    }
}

#[test]
fn parses_ipv4_rows_and_skips_inode_zero_and_garbage() {
    let rows = parse_proc_net(TCP, SockProto::Tcp);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].local, "127.0.0.1:8080".parse().unwrap());
    assert_eq!(rows[2].local, "192.168.2.15:50000".parse().unwrap());
    assert_eq!(rows[2].remote, "93.184.216.34:443".parse().unwrap());
    assert_eq!(rows[2].inode, 33003);
}

#[test]
fn parses_ipv6_rows_including_mapped_addresses() {
    let rows = parse_proc_net(TCP6, SockProto::Tcp);
    assert_eq!(rows[0].local, "[::1]:631".parse().unwrap());
    assert_eq!(
        rows[1].local,
        "[::ffff:192.168.2.15]:40000".parse().unwrap()
    );
    assert_eq!(rows[2].local, "[2001:db8::1]:54321".parse().unwrap());
    assert_eq!(rows[2].remote, "[2001:db8::2]:443".parse().unwrap());
}

#[test]
fn parses_udp_rows() {
    let rows = parse_proc_net(UDP, SockProto::Udp);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].remote, "8.8.8.8:53".parse().unwrap());
}

#[test]
fn socket_links_are_recognised() {
    assert_eq!(socket_inode("socket:[48213]"), Some(48213));
    assert_eq!(socket_inode("pipe:[48213]"), None);
    assert_eq!(socket_inode("/dev/null"), None);
    assert_eq!(socket_inode("socket:[x]"), None);
}

#[test]
fn connected_flow_matches_in_either_direction() {
    let m = sample_map();
    let fwd = key("192.168.2.15", 50000, "93.184.216.34", 443, Transport::Tcp);
    let rev = key("93.184.216.34", 443, "192.168.2.15", 50000, Transport::Tcp);
    assert_eq!(m.for_flow(&fwd).map(|p| p.pid), Some(1234));
    assert_eq!(m.for_flow(&rev).map(|p| p.pid), Some(1234));
}

#[test]
fn listener_matches_by_port_and_ipv6_flows_resolve() {
    let m = sample_map();
    let web = key("10.0.0.9", 51000, "127.0.0.1", 8080, Transport::Tcp);
    assert_eq!(m.for_flow(&web).map(|p| &*p.name), Some("nginx"));
    let v6 = key("2001:db8::1", 54321, "2001:db8::2", 443, Transport::Tcp);
    assert_eq!(m.for_flow(&v6).map(|p| &*p.name), Some("curl"));
    let dhcp = key("192.168.2.15", 68, "192.168.2.1", 67, Transport::Udp);
    assert_eq!(m.for_flow(&dhcp).map(|p| &*p.name), Some("dhclient"));
}

#[test]
fn unmatched_flows_and_other_transports_have_no_process() {
    let m = sample_map();
    assert!(
        m.for_flow(&key("1.1.1.1", 1, "2.2.2.2", 2, Transport::Tcp))
            .is_none()
    );
    assert!(
        m.for_flow(&key(
            "192.168.2.15",
            50000,
            "93.184.216.34",
            443,
            Transport::Icmp
        ))
        .is_none()
    );
    let mut no_port = key("192.168.2.15", 50000, "93.184.216.34", 443, Transport::Tcp);
    no_port.a_port = None;
    assert!(m.for_flow(&no_port).is_none());
}

#[test]
fn hosts_list_distinct_processes_sorted() {
    let m = sample_map();
    let list = m.for_host("93.184.216.34");
    assert_eq!(list.iter().map(|p| p.pid).collect::<Vec<_>>(), [1234]);
    assert_eq!(summarize(list), "firefox (1234)");
    assert_eq!(summarize(m.for_host("8.8.8.8")), "systemd-resolve (800)");
    assert!(m.for_host("not an ip").is_empty());
}

#[test]
fn summary_counts_the_extra_processes() {
    let p = |pid, n: &str| ProcessInfo {
        pid,
        name: n.into(),
    };
    assert_eq!(summarize(&[p(1, "a"), p(2, "b"), p(3, "c")]), "a (1) +2");
    assert_eq!(summarize(&[]), "");
}

#[test]
fn sockets_without_a_known_owner_are_ignored() {
    let sockets = parse_proc_net(TCP, SockProto::Tcp);
    assert!(ProcessMap::build(&sockets, &HashMap::new()).is_empty());
}
