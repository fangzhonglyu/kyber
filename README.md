# ECE 6775 Final Project: FPGA Acceleration of Post-Quantum Cryptography

In this project, we explored porting the
[reference CRYSTALS-Kyber implementation](https://github.com/pq-crystals/kyber)
to FPGA hardware using Vivado HLS.

Authors:
 - Aidan McNay (acm289)
 - Barry Lyu (fl327)
 - Edmund Lam (el595)
 - Nita Kattimani (nsk62)

# Synthesis

We have two different implementations of Kyber for the FPGA:
 - One with the entire design on the FPGA (`full-kyber`)
 - One with only the NTT kernel on the FPGA, using more optimizations (`ntt`)

To make the bitstream for `full-kyber`:

```bash
cd hls
make synth     # Synthesize the design using run.tcl
make bitstream # Make the bitstream using 
```

To make the bitstream for `ntt`:

```bash
cd hls
make synth-ntt     # Synthesize the design using run-ntt.tcl
make bitstream-ntt # Make the bitstream using 
```

Both of these will leave you with a `xillidemo.bit`, a bitstream that
can be loaded onto the Zynq FPGA as previously done in class. Synthesis
will additionally test our designs with `hls/test/test_kyber_cosim.cpp` and
`hls/test/test_ntt.cpp`, to verify the functionality. Note that the entire
implementation uses a different testing file for simulation compared to the
actual implementation, as to not run the many batch jobs needed for analysis
in simulation.

# Running on the FPGA

To run either bitstream on the FPGA, you will need a copy of the
repository on the FPGA, so that the software can access the Linux
file objects to read/write to the hardware streams.

## Software Implementation

To generate and run the pure software implementation of the Kyber tests:

```bash
cd zedboard
make kyber-arm # Makes the software binary
./kyber-arm
```

To generate and run the pure software implementation of the NTT tests:

```bash
cd zedboard
make ntt-arm # Makes the software binary
./ntt-arm
```

## FPGA Implementations

To run the Kyber implementation on the FPGA, assuming that the `full-kyber`
bitstream is loaded:

```bash
cd zedboard
make kyber-fpga # Make the binary that access the FPGA hardware
./kyber-fpga
```

To run the NTT implementation on the FPGA, assuming that the `ntt`
bitstream is loaded:

```bash
cd zedboard
make ntt-fpga # Make the binary that access the FPGA hardware
./ntt-fpga
```