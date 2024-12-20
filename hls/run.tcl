#=============================================================================
# run_base.tcl 
#=============================================================================
# @brief: A Tcl script for synthesizing the baseline digit recongnition design.

# Project name
set hls_prj kyber.prj

# Open/reset the project
open_project ${hls_prj} -reset

# Top function of the design is "dut"
set_top dut

# Add source files
add_files "top.cpp" \
          -cflags "-std=c++11"

# Add testbench files
add_files -tb "test/test_kyber_cosim.cpp" \
              -cflags "-std=c++11"

open_solution "solution1"
# Use Zynq device
set_part {xc7z020clg484-1}

# Target clock period is 10ns
create_clock -period 9

### You can insert your own directives here ###

############################################

# Simulate the C++ design
csim_design -O
# Synthesize the design
csynth_design
# Co-simulate the design
# cosim_design
exit
