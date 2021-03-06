
PIDGIN_TREE_TOP ?= ../pidgin-2.10.12
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw/bin/gcc

PROTOC_C ?= protoc-c
PKG_CONFIG ?= pkg-config

REVISION_ID = $(shell git rev-parse --short HEAD)
REVISION_NUMBER = $(shell git rev-list --count HEAD)
ifneq ($(REVISION_ID),)
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d).git.r$(REVISION_NUMBER).$(REVISION_ID)
else
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d)
endif

CFLAGS	?= -O2 -g -pipe -Wall -DCHIMP_PLUGIN_VERSION='"$(PLUGIN_VERSION)"'
LDFLAGS ?= -Wl,-z,relro

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  CHIMP_TARGET = libchimp.dll
  CHIMP_DEST = "$(PROGRAMFILES)/Pidgin/plugins"
  CHIMP_ICONS_DEST = "$(PROGRAMFILES)/Pidgin/pixmaps/pidgin/protocols"
else

  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    CC ?= gcc
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      CHIMP_TARGET = FAILNOPURPLE
      CHIMP_DEST =
	  CHIMP_ICONS_DEST =
    else
      CHIMP_TARGET = libchimp.so
      CHIMP_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  CHIMP_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    CHIMP_TARGET = libchimp3.so
    CHIMP_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	CHIMP_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif
endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/json-glib-0.14/include/json-glib-1.0 -DENABLE_NLS -DCHIMP_PLUGIN_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(WIN32_DEV_TOP)/json-glib-0.14/lib -lpurple -lintl -lglib-2.0 -lgobject-2.0 -ljson-glib-1.0 -g -ggdb -static-libgcc -lz
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES := 
PURPLE_COMPAT_FILES := purple2compat/http.c purple2compat/purple-socket.c
PURPLE_C_FILES := libchimp.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE clean

all: $(CHIMP_TARGET)

libchimp.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb

libchimp3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 --libs --cflags` $(INCLUDES)  -g -ggdb

libchimp.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libchimp3.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

install: $(CHIMP_TARGET) install-icons
	mkdir -p $(CHIMP_DEST)
	install -p $(CHIMP_TARGET) $(CHIMP_DEST)

install-icons: icons/16/chimp.png icons/22/chimp.png icons/48/chimp.png
	mkdir -m $(DIR_PERM) -p $(CHIMP_ICONS_DEST)/16
	mkdir -m $(DIR_PERM) -p $(CHIMP_ICONS_DEST)/22
	mkdir -m $(DIR_PERM) -p $(CHIMP_ICONS_DEST)/48
	install -m $(FILE_PERM) -p icons/16/chimp.png $(CHIMP_ICONS_DEST)/16/chimp.png
	install -m $(FILE_PERM) -p icons/22/chimp.png $(CHIMP_ICONS_DEST)/22/chimp.png
	install -m $(FILE_PERM) -p icons/48/chimp.png $(CHIMP_ICONS_DEST)/48/chimp.png


FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(CHIMP_TARGET) 

