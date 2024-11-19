#=============================================================================
# run_base.tcl 
#=============================================================================
# @brief: A Tcl script for synthesizing the baseline digit recongnition design.

# Project name
set hls_prj kyber.prj

# Open/reset the project
open_project ${hls_prj} -reset

# Top function of the design is "dut"
set_top dut_enc

# Add source files
add_files "top.cpp \
          kem.cpp \
          indcpa.cpp \
          polyvec.cpp \
          poly.cpp ntt.cpp \
          cbd.cpp reduce.cpp \
          verify.cpp \
          fips202.cpp \
          symmetric-shake.cpp \
          randombytes.cpp" \
          -cflags "-std=c++11"

# Add testbench files
add_files -tb "test/cpucycles.cpp \
              test/speed_print.cpp \
              test/cpucycles.h \
              test/speed_print.h \
              test/test_kyber.cpp" \
              -cflags "-std=c++11"

open_solution "solution1"
# Use Zynq device
set_part {xc7z020clg484-1}

# Target clock period is 10ns
create_clock -period 10

### You can insert your own directives here ###

############################################

# Simulate the C++ design
csim_design -O
# Synthesize the design
csynth_design
# Co-simulate the design
#cosim_design
exit
