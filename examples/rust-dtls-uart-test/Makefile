APPLICATION = rust-dtls-uart-test
BOARD ?= feather-nrf52840

RIOTBASE ?= $(CURDIR)/../../

DEVELHELP ?= 1
QUIET ?= 1

APPLICATION_RUST_MODULE = rust_dtls_uart_test
BASELIBS += $(APPLICATION_RUST_MODULE).module

FEATURES_REQUIRED += rust_target

USEMODULE += random
USEMODULE += prng_sha256prng

USEMODULE += ztimer_msec

USEMODULE += periph_uart
USEMODULE += periph_gpio
USEMODULE += periph_gpio_irq

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

PROGRAMMER = openocd
OPENOCD_DEBUG_ADAPTER = stlink
OPENOCD_TRANSPORT = swd

include $(RIOTBASE)/Makefile.include

# Flashing fails with stlink otherwise because it does not support `nrf52_recover`
OPENOCD_POST_INIT_CMDS = 
