#![no_std]

use core::mem::MaybeUninit;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::panic::PanicInfo;
use core::ptr;

use embassy_executor::Spawner;
use embassy_executor_riot::Executor;
use embedded_nal_async::UdpStack as _;
use riot_wrappers::println;
use riot_wrappers::random::Random;
use riot_wrappers::riot_main;
use riot_wrappers::riot_sys;
use riot_wrappers::socket_embedded_nal_async_udp::UdpStack;
use riot_wrappers::thread::ValueInThread;
use riot_wrappers::ztimer::Clock;
use riot_wrappers::ztimer::Delay;
use rusty_dtls::{DtlsStackAsync, HandshakeSlot, HashFunction, Psk};

riot_main!(main);

const SERVER_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x64c6, 0x6b35, 0x1f15, 0x7368);

const CLIENT_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x6c2e, 0xdb20, 0x1cf9, 0xe26);

static mut SOCKET: MaybeUninit<riot_sys::sock_udp_t> = MaybeUninit::uninit();

static mut EXECUTOR: Option<Executor> = None;

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

fn to_core_addr(addr: &SocketAddr) -> core::net::SocketAddr {
    let SocketAddr::V6(ip) = addr else { panic!() };
    core::net::SocketAddr::new(ip.ip().octets().into(), addr.port())
}

fn main() {
    unsafe {
        EXECUTOR = Some(Executor::new());
        EXECUTOR.as_mut().unwrap().run(main2);
    }
}

struct ClockWrapper(ValueInThread<Clock<1000>>);

impl ClockWrapper {
    pub fn new() -> Self {
        ClockWrapper(Clock::msec())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

impl embedded_time::Clock for ClockWrapper {
    type T = u32;

    const SCALING_FACTOR: embedded_time::rate::Fraction =
        embedded_time::rate::Fraction::new(1, 1000);
    fn try_now(&self) -> Result<embedded_time::Instant<Self>, embedded_time::clock::Error> {
        let c = self.0.acquire();
        let now = c.now();
        Ok(embedded_time::Instant::new(now.0))
    }
}

#[embassy_executor::task]
async fn spawn_endpoint(port: u16, peer_port: u16, server: bool) {
    println!("Bound on port {}", port);
    let mut buffer = [0; 512];
    let mut staging_buffer = [0; 256];
    let mut rand = Random::new();
    let psks = [Psk::new(&[123], &[1, 2, 3, 4, 5], HashFunction::Sha256)];

    let delay = Delay;

    let clock = ClockWrapper::new();

    let stack = UdpStack::new(|| unsafe { Some(ptr::addr_of_mut!(SOCKET).as_mut().unwrap()) });
    let (addr, socket) = stack
        .bind_single(SocketAddr::new(
            core::net::IpAddr::V6(if server { SERVER_ADDR } else { CLIENT_ADDR }),
            port,
        ))
        .await
        .unwrap();

    let mut stack = DtlsStackAsync::<'_, _, _, _, 1>::new(
        &mut rand,
        &mut staging_buffer,
        delay,
        clock,
        socket,
        to_core_addr(&addr),
    )
    .unwrap();

    let mut handshakes = [HandshakeSlot::new(&psks, &mut buffer)];
    if !server {
        assert!(stack.open_connection(
            &mut handshakes[0],
            &to_core_addr(&SocketAddr::new(
                core::net::IpAddr::V6(SERVER_ADDR),
                peer_port
            ))
        ));
    }

    let mut i = 5;
    let mut id = None;
    let mut receive_buf = [0u8; 11];
    loop {
        if i == 0 {
            print_peak_stack_usage();
            return;
        }
        let Ok(e) = stack.read(&mut handshakes, 5000).await else {
            continue;
        };
        match e {
            rusty_dtls::Event::AppData(_, range) => {
                if server {
                    receive_buf.copy_from_slice(&stack.staging_buffer()[range]);
                    println!(
                        "[{port}] Echo Appdata: {}",
                        core::str::from_utf8(&receive_buf).unwrap()
                    );
                    if let Some(id) = id {
                        stack.send_dtls_packet(id, &receive_buf).await.unwrap();
                    }
                } else {
                    println!(
                        "[{port}] Received Appdata: {}",
                        core::str::from_utf8(&stack.staging_buffer()[range]).unwrap()
                    );
                }
                i -= 1;
            }
            rusty_dtls::Event::OpenedConnection => {
                id = handshakes[0].try_take_connection_id();
                println!("[{port}] Opened connection id {id:?}");
            }
            rusty_dtls::Event::Timeout => {
                if !server {
                    if let Some(id) = id {
                        stack
                            .send_dtls_packet(id, "Hello World".as_bytes())
                            .await
                            .unwrap();
                    }
                }
            }
            _ => {}
        };
    }
}

fn main2(spawner: Spawner) {
    log::set_logger(&LOGGER)
        .map(|_| log::set_max_level(log::LevelFilter::Info))
        .expect("set Riot Logger");
    let ip_addr = riot_wrappers::gnrc::Netif::all()
        .next()
        .expect("We need a netif")
        .ipv6_addrs()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    if ip_addr.raw() == &SERVER_ADDR.octets() {
        spawner.spawn(spawn_endpoint(64777, 64774, true)).unwrap();
    } else if ip_addr.raw() == &CLIENT_ADDR.octets() {
        spawner.spawn(spawn_endpoint(64774, 64777, false)).unwrap();
    } else {
        panic!()
    }
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
