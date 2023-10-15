WIFI_MODULE = esp32_adapter

EXTRA_CFLAGS += -I$(src)/include

$(WIFI_MODULE)-objs := \
	src/thread/event.o \
	src/thread/transceiver.o \
	src/networking/esp32_cfg80211.o \
	src/networking/cfg80211_vendor_cmd.o \
	src/networking/ieee80211_mlme.o \
	src/networking/bss_info.o \
	src/networking/priv.o \
	src/networking/network_device.o \
	src/networking/hw_link_ctrl_protocol.o \
	src/hw/spi_ctrl.o \
	src/utils/ring_buff.o \
	src/wifi_adapter.o

obj-m += $(WIFI_MODULE).o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a

#uninstall:
#	rm -f /lib/modules/$(shell uname -r)/extra/wifi_adapter.ko
#	depmod -a
