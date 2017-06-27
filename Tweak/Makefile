include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MGHooker
MGHooker_FILES = Tweak.xm
MGHooker_LDFLAGS =   -lz -L. -v -force_load ./libcapstone.a
include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
