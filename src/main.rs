#![no_std]
#![no_main]

mod fmt;

extern crate alloc;

use alloc::string::ToString;
use chrono::{DateTime, NaiveDateTime};
use codec_sv2::{HandshakeRole, Initiator, State};
use const_sv2::RESPONDER_EXPECTED_HANDSHAKE_MESSAGE_SIZE;
use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr::addr_of_mut,
};
use edge_mdns::{
    buf::VecBufAccess,
    domain::base::Ttl,
    host::{Host, Service, ServiceAnswers},
    io::{self, IPV4_DEFAULT_SOCKET},
    HostAnswersMdnsHandler,
};
use edge_nal::UdpSplit;
use edge_nal_embassy::{Udp, UdpBuffers};
use embassy_executor::Spawner;
use embassy_net::{
    dns::DnsQueryType,
    tcp::TcpSocket,
    udp::{PacketMetadata, UdpSocket},
    StackResources,
};
use embassy_stm32::{
    bind_interrupts,
    eth::{self, generic_smi::GenericSMI, Ethernet, PacketQueue},
    gpio::{Level, Output, Speed},
    peripherals::{ETH, RNG},
    rng::{self, Rng},
    rtc::{Rtc, RtcConfig},
    time::Hertz,
};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex, signal::Signal};
use embassy_time::{Duration, Timer};
use embedded_alloc::LlffHeap as Heap;
use embedded_io_async::Write;
use fmt::*;
use key_utils::Secp256k1PublicKey;
use rand_core::RngCore;
use sntpc::{NtpContext, NtpTimestampGenerator};
use static_cell::StaticCell;

#[cfg(not(feature = "defmt"))]
use panic_halt as _;
#[cfg(feature = "defmt")]
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    RNG => rng::InterruptHandler<RNG>;
});

type Device = Ethernet<'static, ETH, GenericSMI>;
type RtcMutex = Mutex<NoopRawMutex, Rtc>;

const NTP_SERVER: &str = "pool.ntp.org";
const HOSTNAME: &str = env!("HOSTNAME");
const AUTHORITY_PUBLIC_K: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }
    let mut config = embassy_stm32::Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.ls = LsConfig::default_lse(); // needed for RTC
        config.rcc.hse = Some(Hse {
            freq: Hertz(8_000_000),
            mode: HseMode::Bypass,
        });
        config.rcc.pll_src = PllSource::HSE;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL216,
            divp: Some(PllPDiv::DIV2), // 8mhz / 4 * 216 / 2 = 216Mhz
            divq: None,
            divr: None,
        });
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.sys = Sysclk::PLL1_P;
    }
    let p = embassy_stm32::init(config);
    info!("Hello, World!");

    // Use a led to show Heartbeat
    let mut led = Output::new(p.PB7, Level::High, Speed::Low);

    // Generate random seed.
    let mut rng = Rng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    rng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    let mac_addr = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

    static PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    let device = Ethernet::new(
        PACKETS.init(PacketQueue::<4, 4>::new()),
        p.ETH,
        Irqs,
        p.PA1,  // ref_clk
        p.PA2,  // mdio
        p.PC1,  // eth_mdc
        p.PA7,  // CRS_DV: Carrier Sense
        p.PC4,  // RX_D0: Received Bit 0
        p.PC5,  // RX_D1: Received Bit 1
        p.PG13, // TX_D0: Transmit Bit 0
        p.PB13, // TX_D1: Transmit Bit 1
        p.PG11, // TX_EN: Transmit Enable
        GenericSMI::new(0),
        mac_addr,
    );

    let config = embassy_net::Config::dhcpv4(Default::default());

    // Init network stack
    static RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
    let (stack, runner) =
        embassy_net::new(device, config, RESOURCES.init(StackResources::new()), seed);

    // Launch network task
    unwrap!(spawner.spawn(net_task(runner)));

    // Ensure DHCP configuration is up before trying connect
    stack.wait_config_up().await;

    info!("Network task initialized");

    // Use mDNS responder to be easily findable
    unwrap!(spawner.spawn(mdns_task(
        stack,
        1234,
        "123456789",
        "stm32h743",
        HOSTNAME,
        "_tcp",
    )));

    let rtc = Rtc::new(p.RTC, RtcConfig::default());
    // debug!("RTC {:?}", rtc.now().unwrap()); // need https://github.com/embassy-rs/embassy/pull/3802
    static RTC_MUTEX: StaticCell<RtcMutex> = StaticCell::new();
    let rtc = RTC_MUTEX.init(Mutex::new(rtc));
    unwrap!(spawner.spawn(sntp_task(stack, rtc)));

    // Launch a test TCP task
    // unwrap!(spawner.spawn(test_tcp_task(stack)));

    // Launch a stratum v2 task
    unwrap!(spawner.spawn(stratum_v2_task(stack, rng, rtc)));

    loop {
        led.set_high();
        Timer::after(Duration::from_millis(500)).await;
        led.set_low();
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[embassy_executor::task]
async fn stratum_v2_task(
    stack: embassy_net::Stack<'static>,
    mut rng: Rng<'static, RNG>,
    rtc: &'static RtcMutex,
) -> ! {
    // Handshake
    let authority_public_k: Secp256k1PublicKey = AUTHORITY_PUBLIC_K
        .to_string()
        .try_into()
        .expect("Failed to convert receiver public key to Secp256k1PublicKey");
    let initiator = Initiator::from_raw_k_with_rng(authority_public_k.into_bytes(), &mut rng)
        .expect("Failed to create initiator role from raw pub key");

    let mut noise_state = State::initialized(HandshakeRole::Initiator(initiator));

    let first_message = noise_state
        .step_0()
        .expect("Initiator failed first step of handshake");
    let _first_message: [u8; RESPONDER_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = first_message
        .get_payload_when_handshaking()
        .try_into()
        .expect("Handshake remote invlaid message");
    //TODO: send first_message by TCP and receive the second_message as an answer

    let now: NaiveDateTime = rtc.lock().await.now().unwrap().into();
    let now = now.and_utc().timestamp() as u32;
    // let noise_state = noise_state
    //     .step_2_with_now(second_message, now)
    //     .expect("Initiator failed third step of handshake");

    let mut noise_state = match noise_state {
        State::Transport(c) => State::with_transport_mode(c),
        _ => fmt::panic!("todo"),
    };
    loop {
        //TODO: exchange some Mining related messages
    }
}

#[embassy_executor::task]
async fn mdns_task(
    stack: embassy_net::Stack<'static>,
    service_port: u16,
    serial_number: &'static str,
    model: &'static str,
    service: &'static str,
    protocol: &'static str,
) {
    stack
        .join_multicast_group(Ipv4Addr::new(224, 0, 0, 251))
        .unwrap();
    let udp_buffers: UdpBuffers<3, 1500, 1500, 2> = UdpBuffers::new();
    let udp = Udp::new(stack, &udp_buffers);
    let bind = io::bind(&udp, IPV4_DEFAULT_SOCKET, Some(Ipv4Addr::UNSPECIFIED), None).await;

    match bind {
        Ok(mut socket) => {
            let (recv, send) = socket.split();

            let signal = Signal::new();

            let (recv_buf, send_buf) = (
                VecBufAccess::<NoopRawMutex, 1500>::new(),
                VecBufAccess::<NoopRawMutex, 1500>::new(),
            );

            let mdns = io::Mdns::<NoopRawMutex, _, _, _, _>::new(
                Some(Ipv4Addr::UNSPECIFIED),
                None,
                recv,
                send,
                recv_buf,
                send_buf,
                |buf| buf.fill(0), //TODO: find a way to use the HW Rng
                &signal,
            );

            // Host we are announcing from - not sure how important this is
            let host = Host {
                hostname: HOSTNAME,
                ipv4: stack.config_v4().unwrap().address.address(),
                ipv6: Ipv6Addr::UNSPECIFIED,
                ttl: Ttl::from_secs(60),
            };

            // The service we will be announcing over mDNS
            let service = Service {
                name: serial_number,
                priority: 1,
                weight: 5,
                service,
                protocol,
                port: service_port,
                service_subtypes: &[],
                txt_kvs: &[
                    ("Serial", serial_number),
                    ("Model", model),
                    ("AppName", env!("CARGO_BIN_NAME")),
                    ("AppVersion", env!("CARGO_PKG_VERSION")),
                ],
            };

            info!("Starting mDNS responder");
            let ha = HostAnswersMdnsHandler::new(ServiceAnswers::new(&host, &service));
            if (mdns.run(ha).await).is_err() {
                error!("Could not run mdns responder");
            }

            info!("Exiting mDNS responder");
        }
        Err(_) => {
            error!("Could not bind to io Socket in mDNS");
        }
    }
}

#[embassy_executor::task]
async fn sntp_task(stack: embassy_net::Stack<'static>, rtc: &'static RtcMutex) -> ! {
    info!("Syncing RTC from SNTP...");

    #[derive(Copy, Clone, Default)]
    struct Timestamp {
        duration: Duration,
    }
    impl NtpTimestampGenerator for Timestamp {
        fn init(&mut self) {
            self.duration = Duration::from_secs(0);
        }
        fn timestamp_sec(&self) -> u64 {
            self.duration.as_secs()
        }
        fn timestamp_subsec_micros(&self) -> u32 {
            (self.duration.as_micros() - self.duration.as_secs() * 1_000_000) as u32
        }
    }

    loop {
        let ntp_addrs = stack.dns_query(NTP_SERVER, DnsQueryType::A).await;
        if ntp_addrs.is_err() {
            error!("Failed to resolve DNS");
            Timer::after(Duration::from_millis(5000)).await;
            continue;
        };
        let ntp_addrs = ntp_addrs.unwrap();
        if ntp_addrs.is_empty() {
            error!("Failed to resolve DNS");
            Timer::after(Duration::from_millis(5000)).await;
            continue;
        } else {
            debug!("Resolved NTP server addresses by DNS: {:?}", ntp_addrs);
        }
        let ntpd_addr: IpAddr = ntp_addrs[0].into();
        let mut rx_meta = [PacketMetadata::EMPTY; 16];
        let mut rx_buffer = [0; 4096];
        let mut tx_meta = [PacketMetadata::EMPTY; 16];
        let mut tx_buffer = [0; 4096];
        let mut socket = UdpSocket::new(
            stack,
            &mut rx_meta,
            &mut rx_buffer,
            &mut tx_meta,
            &mut tx_buffer,
        );
        socket.bind(123).unwrap();

        let context = NtpContext::new(Timestamp::default());

        match sntpc::get_time(SocketAddr::from((ntpd_addr, 123)), &socket, context).await {
            Ok(time) => {
                info!("NTP Time: {:?}", time);
                if let Err(_e) = rtc.lock().await.set_datetime(
                    DateTime::from_timestamp(time.seconds as i64 + 1, 0)
                        .unwrap()
                        .naive_utc()
                        .into(),
                ) {
                    // error!("Failed to set RTC: {}", e); // need https://github.com/embassy-rs/embassy/pull/3802
                    error!("Failed to set RTC");
                } else {
                    info!("RTC syncd from SNTP");
                    // debug!("RTC {:?}", rtc.now().unwrap()); // need https://github.com/embassy-rs/embassy/pull/3802
                }
            }
            Err(e) => {
                error!("Error getting time: {:?}", e);
            }
        }
        Timer::after(Duration::from_secs(60 * 60)).await; // every hour is enough
    }
}

#[embassy_executor::task]
async fn test_tcp_task(stack: embassy_net::Stack<'static>) -> ! {
    // Then we can use it!
    let mut rx_buffer = [0; 1024];
    let mut tx_buffer = [0; 1024];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));

        let remote_endpoint = (Ipv4Addr::new(142, 250, 185, 115), 80);
        debug!("connecting...");
        let r = socket.connect(remote_endpoint).await;
        if let Err(e) = r {
            error!("connect error: {:?}", e);
            Timer::after_secs(1).await;
            continue;
        }
        debug!("connected!");
        let mut buf = [0; 1024];
        loop {
            let r = socket
                .write_all(b"GET / HTTP/1.0\r\nHost: www.mobile-j.de\r\n\r\n")
                .await;
            if let Err(e) = r {
                error!("write error: {:?}", e);
                break;
            }
            let n = match socket.read(&mut buf).await {
                Ok(0) => {
                    debug!("read EOF");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!("read error: {:?}", e);
                    break;
                }
            };
            info!("{}", core::str::from_utf8(&buf[..n]).unwrap());
            Timer::after_secs(5).await;
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, Device>) -> ! {
    runner.run().await
}
