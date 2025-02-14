#![no_std]

use core::mem::MaybeUninit;
use core::net::IpAddr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::panic::PanicInfo;
use core::ptr;

use embassy_executor::Spawner;
use embassy_executor_riot::Executor;
use embedded_dtls::cipher_suites::ChaCha20Poly1305Cipher;
use embedded_dtls::cipher_suites::DtlsEcdhePskWithChacha20Poly1305Sha256;
use embedded_dtls::client::config::ClientConfig;
use embedded_dtls::client::config::Psk;
use embedded_dtls::client::open_client;
use embedded_dtls::server::config::Identity;
use embedded_dtls::server::config::Key;
use embedded_dtls::server::config::ServerConfig;
use embedded_dtls::server::open_server;
use embedded_dtls::ApplicationDataReceiver;
use embedded_dtls::ApplicationDataSender;
use embedded_dtls::RxEndpoint;
use embedded_dtls::TxEndpoint;
use embedded_hal_async::delay::DelayNs;
use embedded_nal_async::UdpStack as _;
use embedded_nal_async::UnconnectedUdp as _;
use riot_wrappers::println;
use riot_wrappers::random::Random;
use riot_wrappers::riot_main;
use riot_wrappers::riot_sys;
use riot_wrappers::socket_embedded_nal_async_udp::UdpStack;
use riot_wrappers::socket_embedded_nal_async_udp::UnconnectedUdpSocket;
use riot_wrappers::ztimer::Delay;

riot_main!(main);

const SERVER_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x64c6, 0x6b35, 0x1f15, 0x7368);

const CLIENT_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x6c2e, 0xdb20, 0x1cf9, 0xe26);

static mut SOCKETS: [MaybeUninit<riot_sys::sock_udp_t>; 2] =
    [MaybeUninit::uninit(), MaybeUninit::uninit()];
static mut SOCKET_COUNT: usize = 0;

static mut EXECUTOR: Option<Executor> = None;

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

fn main() {
    unsafe {
        EXECUTOR = Some(Executor::new());
        EXECUTOR.as_mut().unwrap().run(main2);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

struct Rx {
    rx_socket: UnconnectedUdpSocket,
}

impl core::fmt::Debug for Rx {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl RxEndpoint for Rx {
    type ReceiveError = ();
    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError> {
        let (len, _, _) = self.rx_socket.receive_into(buf).await.unwrap();
        Ok(&mut buf[..len])
    }
}

struct Tx {
    tx_socket: UnconnectedUdpSocket,
    remote: SocketAddr,
    local: SocketAddr,
}

impl core::fmt::Debug for Tx {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}
impl TxEndpoint for Tx {
    type SendError = ();
    async fn send(&mut self, buf: &[u8]) -> Result<(), Self::SendError> {
        self.tx_socket
            .send(self.local, self.remote, buf)
            .await
            .unwrap();
        Ok(())
    }
}

#[derive(Clone)]
struct AppTx {
    delay: Delay,
    is_client: bool,
    i: usize,
}

impl ApplicationDataReceiver for AppTx {
    type Error = ();

    async fn peek(&mut self) -> Result<impl AsRef<[u8]>, Self::Error> {
        if self.is_client {
            if self.i == 0 {
                return Err(());
            }
            self.delay.delay_ms(5000).await;
            self.i -= 1;
            Ok(b"Hello world")
        } else {
            loop {
                self.delay.delay_ms(5000).await;
            }
        }
    }

    fn pop(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct AppRx {
    i: usize,
}

impl ApplicationDataSender for AppRx {
    type Error = ();

    async fn send(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.i -= 1;
        println!(
            "Echo Appdata: {}",
            core::str::from_utf8(data.as_ref()).unwrap()
        );
        if self.i == 1 {
            return Err(());
        }
        Ok(())
    }
}

#[embassy_executor::task]
async fn spawn_endpoint(port: u16, peer_port: u16, server: bool) {
    println!("Bound on port {}", port);
    let stack = UdpStack::new(|| unsafe {
        let socket = ptr::addr_of_mut!(SOCKETS[SOCKET_COUNT]).as_mut().unwrap();
        SOCKET_COUNT += 1;
        Some(socket)
    });
    let local_addr = if server { SERVER_ADDR } else { CLIENT_ADDR };
    let (addr, tx_socket) = stack
        .bind_single(SocketAddr::new(IpAddr::V6(local_addr), peer_port))
        .await
        .unwrap();
    let (_, rx_socket) = stack
        .bind_single(SocketAddr::new(IpAddr::V6(local_addr), port))
        .await
        .unwrap();

    let mut rx_buf = [0; 256];
    let mut tx_buf = [0; 256];
    let psk_identity = b"hello world";
    let psk_key = b"12345";
    let psk = (Identity::from(psk_identity), Key::from(psk_key));
    let mut rng = Random::new();

    let rx = Rx { rx_socket };
    let tx = Tx {
        tx_socket,
        remote: SocketAddr::new(
            core::net::IpAddr::V6(if !server { SERVER_ADDR } else { CLIENT_ADDR }),
            peer_port,
        ),
        local: addr,
    };
    let mut app_rx = AppRx { i: MESSAGES };
    let mut app_tx = AppTx {
        i: MESSAGES,
        delay: Delay,
        is_client: false,
    };

    if server {
        let server_config = ServerConfig { psk: &[psk] };
        let server_connection = open_server(rx, tx, &server_config, &mut rng, &mut rx_buf)
            .await
            .unwrap();
        println!("[{port}] Opened connection");
        let _ = server_connection
            .run(&mut rx_buf, &mut tx_buf, &mut app_rx, &mut app_tx, Delay)
            .await;
    } else {
        app_tx.is_client = true;
        let client_config = ClientConfig {
            psk: Psk {
                identity: psk_identity,
                key: psk_key,
            },
        };
        let cipher = ChaCha20Poly1305Cipher::default();
        let client_connection = open_client::<_, _, _, DtlsEcdhePskWithChacha20Poly1305Sha256>(
            &mut rng,
            &mut rx_buf,
            rx,
            tx,
            cipher,
            &client_config,
        )
        .await
        .unwrap();
        println!("[{port}] Opened connection");
        let _ = client_connection
            .run(&mut rx_buf, &mut tx_buf, &mut app_rx, &mut app_tx, Delay)
            .await;
    }
    print_peak_stack_usage();
}

fn main2(spawner: Spawner) {
    log::set_logger(&LOGGER)
        .map(|_| log::set_max_level(log::LevelFilter::Trace))
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
