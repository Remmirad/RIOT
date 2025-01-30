APPLICATION = rust-dtls-async-test

BOARD ?= feather-nrf52840

RIOTBASE ?= $(CURDIR)/../../

DEVELHELP ?= 1
QUIET ?= 1

APPLICATION_RUST_MODULE = rust_dtls_async_test
BASELIBS += $(APPLICATION_RUST_MODULE).module

USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_netif_single

USEMODULE += sock_udp
USEMODULE += sock_aux_local
USEMODULE += gnrc_sock_udp
USEMODULE += gnrc_netapi_callbacks
USEMODULE += gnrc_ipv6_static_addr

USEMODULE += sock_async
USEMODULE += gnrc_sock_async

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
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=6000'

CARGO_CHANNEL = nightly
CARGO_PROFILE = release

COMPILE_COMMANDS_PATH=$(CURDIR)/compile_commands.json

PROGRAMMER = openocd
OPENOCD_DEBUG_ADAPTER = stlink
OPENOCD_TRANSPORT = swd

FEATURES_REQUIRED += rust_target

include $(RIOTBASE)/Makefile.include

# Flashing fails with stlink otherwise because it does not support `nrf52_recover`
OPENOCD_POST_INIT_CMDS =
