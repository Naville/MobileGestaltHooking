include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = TestMG
TestMG_FILES = main.m MGAppDelegate.m MGRootViewController.m
TestMG_FRAMEWORKS = UIKit CoreGraphics

include $(THEOS_MAKE_PATH)/application.mk

after-install::
	install.exec "killall \"TestMG\"" || true
