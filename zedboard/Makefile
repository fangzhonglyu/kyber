#==========================================================================
# Makefile
#==========================================================================
# @brief: A makefile the compiles and runs the bnn program
#
# @desc: 1. "make" or "make sw" runs software execution by default
#        2. "make fpga" invokes the HW accelerator
#        3. "make clean" cleans up the directory


INC_PATH=/usr/include/vivado_hls
CFLAGS = -I${INC_PATH} -DHLS_NO_XIL_FPO_LIB -O3

.PHONY: all sw fpga

all: sw

kyber-arm: top.cpp test/test_kyber.cpp
	@echo "Compiling & executing kyber software program on ARM ..."
	g++ ${CFLAGS} $^ -o $@ -std=c++11

ntt-arm: ntt-fpga.cpp test/test_ntt.cpp
	@echo "Compiling & executing ntt software program on ARM ..."
	g++ ${CFLAGS} $^ -o $@ -std=c++11

result/kyber_arm_sim.txt: kyber-arm
	mkdir -p result
	./$< | tee $@

result/ntt_arm_sim.txt: ntt-arm
	mkdir -p result
	./$< | tee $@

sw: result/kyber_arm_sim.txt result/ntt_arm_sim.txt
	@echo "Result saved to $@"

kyber-fpga: host-ntt.cpp ntt-fpga.cpp
	@echo "Compiling host program"
	g++ ${CFLAGS} $^ -o $@
	@echo "Make sure bitstream is loaded!"

ntt-fpga: host-ntt.cpp
	@echo "Compiling host program"
	g++ ${CFLAGS} $^ -o $@
	@echo "Make sure bitstream is loaded!"

fpga: kyber-fpga
	@echo "Running kyber accelerator ..."
	./$<

# Clean up the directory before submission
clean:
	@echo "Clean up output files"
	rm -rf kyber-arm kyber-ntt vivado_hls.log *.prj result out.dat *~
	rm -rf kyber-fpga ntt-fpga
