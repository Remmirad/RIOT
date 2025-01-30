#![no_std]

use core::net::Ipv6Addr;
use core::net::{self, SocketAddr};

#[cfg(feature = "dtls")]
use {
    core::borrow::BorrowMut,
    core::cell::RefCell,
    core::ops::{DerefMut, Range},
    riot_wrappers::random::Random,
    rusty_dtls::{ConnectionId, DtlsPoll, DtlsStack, HandshakeSlot, HashFunction, Psk},
};

use riot_wrappers::riot_main;
use riot_wrappers::ztimer::LockedClock;
use riot_wrappers::{gnrc::Netif, riot_sys};
use riot_wrappers::{
    println,
    thread::ValueInThread,
    ztimer::{Clock, Ticks},
};

use chunky::ReadBuf;

const SERVER_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x64c6, 0x6b35, 0x1f15, 0x7368);
const CLIENT_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x6c2e, 0xdb20, 0x1cf9, 0xe26);

// How many messages should be sent.
const MESSAGES: usize = 5;
// Debugging
static mut UART_COUNT: usize = 0;
static mut END_COUNT: usize = 0;

extern "C" fn uart_int_cb(arg: *mut riot_sys::libc::c_void, data: u8) {
    if arg.is_null() {
        return;
    }

    unsafe { UART_COUNT += 1 };

    let buf = unsafe { &mut *(arg as *mut ReadBuf) };
    buf.put(data);
}

extern "C" fn end_msg_int_cb(arg: *mut core::ffi::c_void) {
    if arg.is_null() {
        return;
    }

    unsafe { END_COUNT += 1 };

    let buf = unsafe { &mut *(arg as *mut ReadBuf) };
    buf.end();
}

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

#[cfg(feature = "dtls")]
fn read_blocking_dtls<'a>(
    uart_buf: &mut ReadBuf,
    buf: &mut [u8],
    timeout: u32,
    clock: &LockedClock<1000>,
) -> Option<usize> {
    read_blocking(uart_buf, buf, timeout, clock)
}

fn read_blocking<'a>(
    uart_buf: &mut ReadBuf,
    buf: &mut [u8],
    timeout: u32,
    clock: &LockedClock<1000>,
) -> Option<usize> {
    let time_end = clock.now().0 + timeout;
    loop {
        let time = clock.now().0;
        let res = uart_buf.next(buf);
        if res > 0 {
            return Some(res);
        }
        if time > time_end {
            return None;
        }
    }
}

#[cfg(not(feature = "dtls"))]
fn spawn_endpoint(
    uart_tx: UartTX,
    uart_buf: &mut ReadBuf,
    port: u16,
    peer_port: u16,
    server: bool,
) {
    let clock = riot_wrappers::ztimer::Clock::msec();
    let locked_clock = clock.acquire();
    let mut recv_buf = [0u8; 128];

    let mut i = MESSAGES;
    if server {
        while i > 0 {
            if let Some(read) = read_blocking(uart_buf, &mut recv_buf, 1000, &locked_clock) {
                println!(
                    "[Server] Echo app data: {:?}",
                    core::str::from_utf8(&recv_buf[..read])
                );
                uart_tx.send(&clock, &recv_buf[..read]);
                i -= 1;
            }
        }
    } else {
        while i > 0 {
            let step = 100;
            // Wait 5000ms
            for _ in 0..50 {
                if let Some(read) = read_blocking(uart_buf, &mut recv_buf, step, &locked_clock) {
                    println!(
                        "[Client] Got app data: {:?}",
                        core::str::from_utf8(&recv_buf[..read])
                    );
                }
            }
            uart_tx.send(&clock, "Hello World".as_bytes());
            i -= 1;
        }
    }
}

#[cfg(feature = "dtls")]
fn spawn_endpoint_dtls(
    uart_tx: UartTX,
    uart_buf: &mut ReadBuf,
    port: u16,
    peer_port: u16,
    server: bool,
) {
    let i = RefCell::new(MESSAGES);

    println!("[{port}] bound on port {}", port);

    let mut send_to_peer = |addr: &core::net::SocketAddr, buf: &[u8]| {
        println!("[{port}] Send message. Size: {}", buf.len());
        let clock = riot_wrappers::ztimer::Clock::msec();
        uart_tx.send(&clock, buf);
    };
    let mut receive_buf: [u8; 128] = [0u8; 128];
    let mut buffer: [u8; 512] = [0; 512];
    let mut staging_buffer: [u8; 256] = [0; 256];

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
    let mut handshakes = [HandshakeSlot::new(&psks, &mut buffer)];

    stack.require_cookie(true);

    if !server {
        assert!(stack.open_connection(
            &mut handshakes[0],
            &net::SocketAddr::new(net::IpAddr::V6(SERVER_ADDR), peer_port)
        ));
    }

    let other_addr = &net::SocketAddr::new(
        net::IpAddr::V6(if server { CLIENT_ADDR } else { SERVER_ADDR }),
        peer_port,
    );

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
                if let Some(read) = read_blocking_dtls(uart_buf, stack.staging_buffer(), ms, &clock)
                {
                    stack
                        .handle_dtls_packet(&mut handshakes, other_addr, read, &mut handle_app_data)
                        .unwrap();
                }
            }
            DtlsPoll::Wait => {
                println!("[{port}] Wait");
                loop {
                    if let Some(read) =
                        read_blocking_dtls(uart_buf, stack.staging_buffer(), 5000, &clock)
                    {
                        stack
                            .handle_dtls_packet(
                                &mut handshakes,
                                other_addr,
                                read,
                                &mut handle_app_data,
                            )
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

struct Pins {
    write: (u32, u32),
    read: (u32, u32),
    led: (u32, u32),
}

const PORT_B: u32 = 1;
const PORT_C: u32 = 2;

const BLUEPILL_PINS: Pins = Pins {
    write: (PORT_B, 9),
    read: (PORT_B, 8),
    led: (PORT_C, 13),
};

const NRF_PINS: Pins = Pins {
    write: (0, 26),
    read: (0, 7),
    led: (1, 10),
};

struct UartTX {
    uart_dev: riot_sys::uart_t,
    write_pin: riot_sys::gpio_t,
}

impl UartTX {
    fn send(&self, clock: &ValueInThread<Clock<1000>>, msg: &[u8]) {
        unsafe {
            riot_sys::uart_write(self.uart_dev, msg.as_ptr(), msg.len() as riot_sys::size_t);
            clock.sleep(Ticks(1));
            riot_sys::gpio_clear(self.write_pin);
            clock.sleep(Ticks(1));
            riot_sys::gpio_set(self.write_pin);
        }
    }
}

static mut UART_BUFFER: [u8; 512] = [0u8; 512];

fn main() -> ! {
    log::set_logger(&LOGGER)
        .map(|_| log::set_max_level(log::LevelFilter::Info))
        .expect("set Riot Logger");
    riot_wrappers::ztimer::Clock::msec().sleep(riot_wrappers::ztimer::Ticks(2000));

    let pins = NRF_PINS;
    let uart_dev: riot_sys::uart_t = unsafe { riot_sys::macro_UART_DEV(0) };
    let write_pin: riot_sys::gpio_t =
        unsafe { riot_sys::macro_GPIO_PIN(pins.write.0, pins.write.1) };
    let read_pin: riot_sys::gpio_t = unsafe { riot_sys::macro_GPIO_PIN(pins.read.0, pins.read.1) };
    let led_pin: riot_sys::gpio_t = unsafe { riot_sys::macro_GPIO_PIN(pins.led.0, pins.led.1) };

    let mut uart_buf = ReadBuf::new(unsafe { &mut UART_BUFFER });
    let uart_tx = UartTX {
        uart_dev,
        write_pin,
    };

    unsafe {
        riot_sys::gpio_init(write_pin, riot_sys::gpio_mode_t_GPIO_OUT);
        riot_sys::gpio_init(led_pin, riot_sys::gpio_mode_t_GPIO_OUT);
        riot_sys::gpio_set(led_pin);
        riot_sys::gpio_init_int(
            read_pin,
            riot_sys::gpio_mode_t_GPIO_IN,
            riot_sys::gpio_flank_t_GPIO_FALLING,
            Some(end_msg_int_cb),
            core::ptr::addr_of_mut!(uart_buf) as *mut riot_sys::libc::c_void,
        );
        riot_sys::gpio_set(write_pin);
        riot_sys::uart_init(
            riot_sys::macro_UART_DEV(0),
            115200,
            Some(uart_int_cb),
            core::ptr::addr_of_mut!(uart_buf) as *mut riot_sys::libc::c_void,
        );
    }

    let is_server = true;
    if is_server {
        #[cfg(feature = "dtls")]
        spawn_endpoint_dtls(uart_tx, &mut uart_buf, 64777, 64774, true);
        #[cfg(not(feature = "dtls"))]
        spawn_endpoint(uart_tx, &mut uart_buf, 64777, 64774, true)
    } else {
        #[cfg(feature = "dtls")]
        spawn_endpoint_dtls(uart_tx, &mut uart_buf, 64774, 64777, false);
        #[cfg(not(feature = "dtls"))]
        spawn_endpoint(uart_tx, &mut uart_buf, 64774, 64777, false);
    }
    print_peak_stack_usage();

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
