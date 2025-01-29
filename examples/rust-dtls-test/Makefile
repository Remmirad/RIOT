APPLICATION = rust-dtls-test
BOARD ?= feather-nrf52840

RIOTBASE ?= $(CURDIR)/../../

DEVELHELP ?= 1
QUIET ?= 0

APPLICATION_RUST_MODULE = rust_dtls_test
BASELIBS += $(APPLICATION_RUST_MODULE).module

FEATURES_REQUIRED += rust_target

USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_netif_single
USEMODULE += sock_udp
USEMODULE += random
USEMODULE += prng_sha256prng

USEMODULE += ztimer_msec

# Enables stacktests
CFLAGS += -D"SCHED_TEST_STACK=1"

# Enable RTT logging
USEMODULE += stdio_rtt

# Enable USB logging
# USEMODULE += stdio_cdc_acm

CFLAGS += '-DLOG_LEVEL=LOG_ALL'
CFLAGS += '-DDEBUG_ASSERT_VERBOSE'
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=10000'

CARGO_CHANNEL = stable
CARGO_PROFILE = release

# Enable dtls
CARGO_OPTIONS += --features dtls
# CARGO_OPTIONS += --features netqueue

PROGRAMMER = openocd
OPENOCD_DEBUG_ADAPTER = stlink
OPENOCD_TRANSPORT = swd

include $(RIOTBASE)/Makefile.include

# Flashing fails with stlink otherwise because it does not support `nrf52_recover`
OPENOCD_POST_INIT_CMDS = 
