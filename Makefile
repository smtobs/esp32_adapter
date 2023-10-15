WIFI_MODULE = esp32_adapter

$(WIFI_MODULE)-objs := network_device.o \
		esp32_cfg80211.o \
		cfg80211_vendor_cmd.o \
		ieee80211_mlme.o \
		bss_info.o \
		event.o \
		priv.o \
		recv.o \
		hw_link_ctrl_protocol.o \
		spi_ctrl.o \
		ring_buff.o \
		wifi_adapter.o

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

