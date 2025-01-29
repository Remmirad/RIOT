#![no_std]

use core::net;
use core::net::Ipv6Addr;

#[cfg(feature = "dtls")]
use {
    core::borrow::BorrowMut,
    core::cell::RefCell,
    core::ops::{DerefMut, Range},
    riot_wrappers::random::Random,
    rusty_dtls::{ConnectionId, DtlsPoll, DtlsStack, HandshakeSlot, HashFunction, Psk},
};

use riot_wrappers::println;
use riot_wrappers::riot_main;
use riot_wrappers::socket_embedded_nal::Stack;
use riot_wrappers::socket_embedded_nal::StackAccessor;
use riot_wrappers::socket_embedded_nal::UdpSocket;
use riot_wrappers::ztimer::LockedClock;
use riot_wrappers::{gnrc::Netif, riot_sys};

use embedded_nal::nb::Error;
use embedded_nal::SocketAddr;
use embedded_nal::UdpClientStack;
use embedded_nal::UdpFullStack;

const SERVER_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x64c6, 0x6b35, 0x1f15, 0x7368);

const CLIENT_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x6c2e, 0xdb20, 0x1cf9, 0xe26);

// How many messages should be sent.
const MESSAGES: usize = 5;

struct RiotLogger {}
impl log::Log for RiotLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        println!("[{}] {}", record.level(), record.args());
    }
    fn flush(&self) {}
}

static LOGGER: RiotLogger = RiotLogger {};

riot_main!(main);

fn to_core_addr(addr: &SocketAddr) -> net::SocketAddr {
    let SocketAddr::V6(ip) = addr else { panic!() };
    net::SocketAddr::new(ip.ip().octets().into(), addr.port())
}

fn to_nal_addr(addr: &net::SocketAddr) -> SocketAddr {
    let net::SocketAddr::V6(ip) = addr else {
        panic!()
    };
    SocketAddr::new(ip.ip().octets().into(), addr.port())
}

#[cfg(feature = "dtls")]
fn read_blocking_dtls<'a>(
    buffer: &mut [u8],
    socket: &RefCell<(UdpSocket<'a>, StackAccessor<'a, 1>)>,
    timeout: u32,
    clock: &LockedClock<1000>,
) -> Option<(usize, net::SocketAddr)> {
    let mut socket = socket.borrow_mut();
    read_blocking(buffer, socket.borrow_mut(), timeout, clock)
}

fn read_blocking<'a>(
    buffer: &mut [u8],
    socket: &mut (UdpSocket<'a>, StackAccessor<'a, 1>),
    timeout: u32,
    clock: &LockedClock<1000>,
) -> Option<(usize, net::SocketAddr)> {
    let time_end = clock.now().0 + timeout;
    let (s, st) = socket;
    loop {
        let time = clock.now().0;
        let res = st.receive(s, buffer);
        match res {
            Ok((read, addr)) => {
                return Some((read, to_core_addr(&addr)));
            }
            Err(Error::WouldBlock) => {}
            Err(Error::Other(e)) => {
                println!("{e:?}, {}", riot_sys::EAGAIN);
                // panic!("{e:?}");
            }
        }
        if time > time_end {
            return None;
        }
    }
}

#[cfg(not(feature = "dtls"))]
fn spawn_endpoint(mut stack: StackAccessor<'_, 1>, port: u16, peer_port: u16, server: bool) {
    let mut socket = stack.socket().unwrap();
    stack.bind(&mut socket, port).unwrap();
    let mut socket = (socket, stack);

    let clock = riot_wrappers::ztimer::Clock::msec();
    let clock = clock.acquire();
    let mut receive_buf = [0u8; 128];

    let mut i = MESSAGES;
    if server {
        while i > 0 {
            if let Some((read, addr)) = read_blocking(&mut receive_buf, &mut socket, 1000, &clock) {
                println!(
                    "[Server] Echo app data: {:?}",
                    core::str::from_utf8(&receive_buf[..read])
                );
                socket
                    .1
                    .send_to(&mut socket.0, to_nal_addr(&addr), &receive_buf[..read])
                    .unwrap();
                i -= 1;
            }
        }
    } else {
        let server_addr = to_nal_addr(&net::SocketAddr::new(
            net::IpAddr::V6(SERVER_ADDR),
            peer_port,
        ));
        while i > 0 {
            let step = 100;
            // Wait 5000ms
            for _ in 0..50 {
                if let Some((read, _)) = read_blocking(&mut receive_buf, &mut socket, step, &clock)
                {
                    println!(
                        "[Client] Got app data: {:?}",
                        core::str::from_utf8(&receive_buf[..read])
                    );
                }
            }
            socket
                .1
                .send_to(&mut socket.0, server_addr, "Hello World".as_bytes())
                .unwrap();
            i -= 1;
        }
    }
}

#[cfg(feature = "dtls")]
fn spawn_endpoint_dtls(mut stack: StackAccessor<'_, 1>, port: u16, peer_port: u16, server: bool) {
    let mut socket = stack.socket().unwrap();
    stack.bind(&mut socket, port).unwrap();
    let socket = RefCell::new((socket, stack));
    let i = RefCell::new(MESSAGES);

    println!("[{port}] bound on port {}", port);

    let mut receive_buf = [0u8; 128];
    #[cfg(not(feature = "netqueue"))]
    let mut buffer = [0; 512];
    #[cfg(feature = "netqueue")]
    let mut net_queue = rusty_dtls::NetQueue::new();
    let mut staging_buffer = [0; 256];

    let mut send_to_peer = |addr: &core::net::SocketAddr, buf: &[u8]| {
        println!("[{port}] Send message. Size: {}", buf.len());
        let mut socket = socket.borrow_mut();
        let (s, st) = socket.deref_mut();
        st.send_to(s, to_nal_addr(addr), buf).unwrap();
    };

    let mut handle_app_data =
        |id: ConnectionId, data: Range<usize>, stack: &mut DtlsStack<'_, 1>| {
            let len = data.end - data.start;
            if server {
                let len = receive_buf.len().min(len);
                receive_buf[..len]
                    .copy_from_slice(&stack.staging_buffer()[data.start..data.start + len]);
                println!(
                    "[{port}] Echo app data {:?}",
                    core::str::from_utf8(&receive_buf[..len])
                );
                let _ = stack.send_dtls_packet(id, &receive_buf[..len]);
                *i.borrow_mut() -= 1;
            } else {
                println!(
                    "[{port}] Got app data: {:?}",
                    core::str::from_utf8(&stack.staging_buffer()[data])
                );
            }
        };

    let mut random = Random::new();
    let psks = [Psk::new(&[123], &[1, 2, 3, 4, 5], HashFunction::Sha256)];
    let mut stack =
        DtlsStack::<1>::new(&mut random, &mut staging_buffer, &mut send_to_peer).unwrap();
    #[cfg(not(feature = "netqueue"))]
    let mut handshakes = [HandshakeSlot::new(&psks, &mut buffer)];
    #[cfg(feature = "netqueue")]
    let mut handshakes = [HandshakeSlot::new(&psks, &mut net_queue)];

    stack.require_cookie(true);

    if !server {
        assert!(stack.open_connection(
            &mut handshakes[0],
            &net::SocketAddr::new(net::IpAddr::V6(SERVER_ADDR), peer_port,)
        ));
    }

    let clock = riot_wrappers::ztimer::Clock::msec();
    let clock = clock.acquire();
    let start = clock.now().0;
    let mut server_id = None;
    while *i.borrow() > 0 {
        let time = clock.now().0;
        let poll = stack.poll(&mut handshakes, (time - start) as u64).unwrap();
        match poll {
            DtlsPoll::WaitTimeoutMs(ms) => {
                println!("[{port}] Wait {ms}");
                if let Some((read, addr)) =
                    read_blocking_dtls(stack.staging_buffer(), &socket, ms, &clock)
                {
                    stack
                        .handle_dtls_packet(&mut handshakes, &addr, read, &mut handle_app_data)
                        .unwrap();
                }
            }
            DtlsPoll::Wait => {
                println!("[{port}] Wait");
                loop {
                    if let Some((read, addr)) =
                        read_blocking_dtls(stack.staging_buffer(), &socket, 5000, &clock)
                    {
                        stack
                            .handle_dtls_packet(&mut handshakes, &addr, read, &mut handle_app_data)
                            .unwrap();
                        break;
                    } else {
                        if let Some(id) = server_id {
                            *i.borrow_mut() -= 1;
                            stack.send_dtls_packet(id, b"Hello world").unwrap();
                        }
                    }
                }
            }
            DtlsPoll::FinishedHandshake => {
                for hs in &mut handshakes {
                    let Some(id) = hs.try_take_connection_id() else {
                        continue;
                    };
                    if !server {
                        server_id = Some(id);
                    }
                    println!("[{port}] Got connection id: {:?}", id);
                }
            }
        }
    }
}

fn main() -> ! {
    log::set_logger(&LOGGER)
        .map(|_| log::set_max_level(log::LevelFilter::Info))
        .expect("set Riot Logger");
    riot_wrappers::ztimer::Clock::msec().sleep(riot_wrappers::ztimer::Ticks(2000));

    for (i, nif) in Netif::all().enumerate() {
        println!("NetIf {} {:02x?}", i, nif.l2addr());
    }

    let ip_addr = riot_wrappers::gnrc::Netif::all()
        .next()
        .expect("We need a netif")
        .ipv6_addrs()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    println!("IP Addr: {:?}", ip_addr);
    let mut stack: Stack<1> = Stack::new();

    stack.run(|stack| {
        println!("Run in stack");
        if ip_addr.raw() == &SERVER_ADDR.octets() {
            #[cfg(feature = "dtls")]
            spawn_endpoint_dtls(stack, 64777, 64774, true);
            #[cfg(not(feature = "dtls"))]
            spawn_endpoint(stack, 64777, 64774, true)
        } else if ip_addr.raw() == &CLIENT_ADDR.octets() {
            #[cfg(feature = "dtls")]
            spawn_endpoint_dtls(stack, 64774, 64777, false);
            #[cfg(not(feature = "dtls"))]
            spawn_endpoint(stack, 64774, 64777, false);
        } else {
            panic!()
        }
        print_peak_stack_usage();
        // don't leave function (see Stack::run)
        loop {}
    });

    loop {}
}

fn print_peak_stack_usage() {
    unsafe {
        let thread = riot_sys::inline::thread_get_active();
        let size = (*thread).stack_size as usize;
        let start = riot_sys::inline::thread_get_stackstart(thread);
        let free = riot_sys::inline::thread_measure_stack_free(start as _) as usize;
        println!("Stackusage: {}/{} B", (size - free), size);
    }
}
