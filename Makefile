# Compiler settings
CC = g++
CFLAGS = -Wall -g -L$(JSONDIR)

# DEBUG print
# 0: DEBUG NOT, 1: DEBUG MODE
DEBUG ?= 1
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG
endif

# Service name
TARGET = program-service

# file root
SRCDIR = src
OBJDIR = obj
LIBDIR = lib
JSONDIR = lib/json

# Source file
SRCS = $(wildcard $(SRCDIR)/*.cpp)

# Object file
OBJS = $(SRCS:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Include directories
INCLUDES = -I$(SRCDIR) -I$(JSONDIR)

# Library link
LIBS = -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -ljsoncpp -ldl

# # Library link
# LIBS = -ljsoncpp -lcurl -lssl
# 
# # openssl 3.0 add
# export PKG_CONFIG_PATH := /usr/local/openssl/lib64/pkgconfig:$(PKG_CONFIG_PATH)
# OPENSSL_CFLAGS := $(shell PKG_CONFIG_PATH="/usr/local/openssl/lib64/pkgconfig" pkg-config --cflags openssl)
# OPENSSL_LIBS := $(shell PKG_CONFIG_PATH="/usr/local/openssl/lib64/pkgconfig" pkg-config --libs openssl)
# CFLAGS += $(OPENSSL_CFLAGS)
# LIBS += $(OPENSSL_LIBS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS) 

# Compile
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

# clean OBJ and TARGET
clean:
	rm -rf $(OBJDIR) $(TARGET)

.PHONY: all clean