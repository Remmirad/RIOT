include ../Makefile.drivers_common

USEMODULE += grove_ledbar

# disable native GPIOs for automatic test
ifneq (,$(filter native native64,$(BOARD)))
  USEMODULE += periph_gpio_mock
  # the same for Kconfig
  ifeq (1,$(TEST_KCONFIG))
    KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.native
  endif
endif

# set default device parameters in case they are undefined
# the following params are for board pba-d-01-kw2x and pins PA01 and PA02
TEST_GROVE_LEDBAR_CLK ?= 	GPIO_PIN\(0,1\)
TEST_GROVE_LEDBAR_DAT ?= 	GPIO_PIN\(0,2\)
TEST_GROVE_LEDBAR_DIR ?=	GROVE_LEDBAR_G2R

# export parameters
CFLAGS += -DGROVE_LEDBAR_CLK=$(TEST_GROVE_LEDBAR_CLK)
CFLAGS += -DGROVE_LEDBAR_DAT=$(TEST_GROVE_LEDBAR_DAT)
CFLAGS += -DGROVE_LEDBAR_DIR=$(TEST_GROVE_LEDBAR_DIR)

include $(RIOTBASE)/Makefile.include
