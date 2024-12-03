# ========================================================================
# Makefile for HLS implementation of Kyber
# ========================================================================

# ------------------------------------------------------------------------
# Specify source files
# ------------------------------------------------------------------------

KYBER_K = 3

HEADERS = \
  params.h \
  kem.h \
  indcpa.h \
  polyvec.h \
  poly.h \
  ntt.h \
  cbd.h \
  reduce.h \
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

.PHONY: clean

all: speed func

speed: \
	build/test_speed512 \

func: build/test_kyber

csim: build/test_kyber
	./build/test_kyber

# shared: \
#   lib/libpqcrystals_kyber512_hls.so \
#   lib/libpqcrystals_kyber768_hls.so \
#   lib/libpqcrystals_kyber1024_hls.so \

build/top.o: top.cpp $(HEADERS) $(BUILD)
	$(CC) $(CFLAGS) -DKYBER_K=$(KYBER_K) -c $< -o $@

build/test_kyber: test/test_kyber_cosim.cpp build/top.o $(BUILD)
	$(CC) $(CFLAGS) -DKYBER_K=$(KYBER_K) $< build/top.o -o $@

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
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so vivado_hls.log
	-$(RM) -rf lib/ $(BUILD) *.prj

# ------------------------------------------------------------------------
# Synthesis
# ------------------------------------------------------------------------

TCL_SCRIPT ?= run.tcl

synth:
	$(XIL_HLS) -f $(TCL_SCRIPT)

synth-ntt:
	$(XIL_HLS) -f run-ntt.tcl

synth-ntt-opt:
	$(XIL_HLS) -f run-ntt-opt.tcl