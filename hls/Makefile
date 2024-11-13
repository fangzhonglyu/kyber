# Extract Vivado HLS include path
XILINX_VIVADO?=/opt/xilinx/Vivado/2019.2
XIL_HLS=source $(XILINX_VIVADO)/settings64.sh; vivado_hls
VHLS_INC=$(XILINX_VIVADO)/include

CC ?= /usr/bin/g++
CFLAGS += -g -I${VHLS_INC} -DHLS_NO_XIL_FPO_LIB -O3 -lrt -std=c++11
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.cpp indcpa.cpp polyvec.cpp poly.cpp ntt.cpp cbd.cpp reduce.cpp verify.cpp
SOURCESKECCAK = $(SOURCES) fips202.cpp symmetric-shake.cpp
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.cpp verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

.PHONY: all speed shared clean

all: speed shared nistkat

shared: \
  lib/libpqcrystals_kyber512_hls.o \
  lib/libpqcrystals_kyber768_hls.o \
  lib/libpqcrystals_kyber1024_hls.o \
  lib/libpqcrystals_fips202_hls.o \


lib/libpqcrystals_fips202_hls.o: fips202.cpp fips202.h
	mkdir -p lib
	$(CC) $(CFLAGS) fips202.cpp -o $@

lib/libpqcrystals_kyber512_hls.o: $(SOURCES) $(HEADERS) symmetric-shake.cpp
	mkdir -p lib
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCES) symmetric-shake.cpp -o $@

lib/libpqcrystals_kyber768_hls.o: $(SOURCES) $(HEADERS) symmetric-shake.cpp
	mkdir -p lib
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES) symmetric-shake.cpp -o $@

lib/libpqcrystals_kyber1024_hls.o: $(SOURCES) $(HEADERS) symmetric-shake.cpp
	mkdir -p lib
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCES) symmetric-shake.cpp -o $@

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf lib/

