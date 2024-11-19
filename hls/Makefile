# ========================================================================
# Makefile for HLS implementation of Kyber
# ========================================================================

# ------------------------------------------------------------------------
# Specify source files
# ------------------------------------------------------------------------

SOURCES = \
  kem.cpp \
  indcpa.cpp \
  polyvec.cpp \
  poly.cpp ntt.cpp \
  cbd.cpp reduce.cpp \
  verify.cpp \
  fips202.cpp \
  symmetric-shake.cpp \
  randombytes.cpp

TEST_FILES = \
  test/cpucycles.cpp \
  test/speed_print.cpp \
  test/cpucycles.h \
  test/speed_print.h \

HEADERS = \
  params.h \
  kem.h \
  indcpa.h \
  polyvec.h \
  poly.h \
  ntt.h \
  cbd.h \
  reduce.cpp \
  verify.h \
  symmetric.h \
  fips202.h \
  randombytes.h

# ------------------------------------------------------------------------
# Extract Vivado HLS include path
# ------------------------------------------------------------------------

XILINX_VIVADO?=/opt/xilinx/Vivado/2019.2
XIL_HLS=source $(XILINX_VIVADO)/settings64.sh; vivado_hls
VHLS_INC=$(XILINX_VIVADO)/include

# ------------------------------------------------------------------------
# Compiler setup
# ------------------------------------------------------------------------

CC = /usr/bin/g++
CFLAGS += -g -I${VHLS_INC} -DHLS_NO_XIL_FPO_LIB -O3 -lrt -std=c++11 -lstdc++
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

MAKEFLAGS := --jobs=$(shell nproc)

BUILD ?= build

$(BUILD):
	@mkdir build

# ------------------------------------------------------------------------
# Object file targets
# ------------------------------------------------------------------------

OBJECTS := $(addprefix $(BUILD)/,$(subst .cpp,.o,$(notdir $(SOURCES))))

$(OBJECTS): $(BUILD)/%.o: %.cpp $(HEADERS) $(BUILD)
	$(CC) $(CFLAGS) -DKYBER_K=2 -c $< -o $@

.PHONY: all speed clean

all: speed

speed: \
  build/test_speed512 \

# shared: \
#   lib/libpqcrystals_kyber512_hls.so \
#   lib/libpqcrystals_kyber768_hls.so \
#   lib/libpqcrystals_kyber1024_hls.so \

build/test_speed512: test/test_speed.cpp $(TEST_FILES) $(OBJECTS) $(HEADERS) $(BUILD)
	$(CC) $(CFLAGS) -DKYBER_K=2 $(TEST_FILES) $(OBJECTS) test/test_speed.cpp -o $@

# lib/libpqcrystals_kyber512_hls.so: $(SOURCES) $(HEADERS)
# 	mkdir -p lib
# 	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=2 $(SOURCES) -o $@

# lib/libpqcrystals_kyber768_hls.so: $(SOURCES) $(HEADERS) 
# 	mkdir -p lib
# 	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=3 $(SOURCES) -o $@

# lib/libpqcrystals_kyber1024_hls.so: $(SOURCES) $(HEADERS) 
# 	mkdir -p lib
# 	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=4 $(SOURCES) -o $@

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf lib/ $(BUILD)

