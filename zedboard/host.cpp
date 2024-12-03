#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>

#include <iostream>
#include <fstream>

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "top.h"

#define NTESTS 10
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#ifndef PRINT_UINT_ARR
#define PRINT_UINT_ARR(name, arr, len) \
  printf("\n%s: ", (name)); \
  for (int ii = 0; ii < (len); ii++) { \
    printf("%2x ", (int)(arr)[ii]); \
  } \
  printf("\n");
#endif


bit8_t lfsr_random(bit8_t seed);

template <int L>
void gen_randombytes(bit8_t out[L]) {
  static bit8_t seed = 0xc0;
  for (int i = 0; i < L; i++) {
    out[i] = lfsr_random(seed);
    seed = out[i];
  }
}


int main(int argc, char **argv)
{
  // Open channels to the FPGA board.
  // These channels appear as files to the Linux OS
  int fdr = open("/dev/xillybus_read_32", O_RDONLY);
  int fdw = open("/dev/xillybus_write_32", O_WRONLY);
  
  // Check that the channels are correctly opened
  if ((fdr < 0) || (fdw < 0)) {
    fprintf(stderr, "Failed to open Xillybus device channels\n");
    exit(-1);
  }


  bit8_t pk[CRYPTO_PUBLICKEYBYTES];
  bit8_t sk[CRYPTO_SECRETKEYBYTES];
  bit8_t ct[CRYPTO_CIPHERTEXTBYTES];

  gen_randombytes<CRYPTO_CIPHERTEXTBYTES>(ct);

  bit8_t key_a[CRYPTO_BYTES];
  bit8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  keypair(pk, sk);

  //Bob derives a secret key and creates a response

  // Send public key to Bob
  for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i = i + 4) {
    bit32_t pk_word;
    pk_word(7, 0) = pk[i + 0];
    pk_word(15, 8) = pk[i + 1];
    pk_word(23, 16) = pk[i + 2];
    pk_word(31, 24) = pk[i + 3];

    int nbytes = write(fdw, (void *)&pk_word, sizeof(pk_word));
    assert(nbytes == sizeof(pk_word));
  }
  // Receive shared secret from Bob
  for (int i = 0; i < CRYPTO_BYTES; i = i + 4) {
    bit32_t key_b_word;
    int nbytes = read(fdr, (void *)&key_b_word, sizeof(key_b_word));
    assert(nbytes == sizeof(key_b_word);

    key_b[i + 0] = key_b_word(7, 0);
    key_b[i + 1] = key_b_word(15, 8);
    key_b[i + 2] = key_b_word(23, 16);
    key_b[i + 3] = key_b_word(31, 24);
  }
  // Receive ciphertext from Bob
  for (int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i = i + 4) {
    bit32_t ct_word;
    int nbytes = read(fdr, (void *)&ct_word, sizeof(ct_word));
    assert(nbytes == sizeof(ct_word));

    ct[i + 0] = ct_word(7, 0);
    ct[i + 1] = ct_word(15, 8);
    ct[i + 2] = ct_word(23, 16);
    ct[i + 3] = ct_word(31, 24);
  }

  //Alice uses Bobs response to get her shared key
  dec(key_a, ct, sk);

  for(int i = 0; i < CRYPTO_BYTES; i++) {
    if(key_a[i] != key_b[i]) {
      printf("ERROR keys\n");
      for (int i = 0; i < CRYPTO_BYTES; i++) {
        if (key_a[i] == key_b[i]) {
          printf(ANSI_COLOR_GREEN "%d: %s == %s\n" ANSI_COLOR_RESET, i, key_a[i].to_string(AP_HEX).c_str(), key_b[i].to_string(AP_HEX).c_str());
        } else {
          printf(ANSI_COLOR_RED "%d: %s != %s\n" ANSI_COLOR_RESET, i, key_a[i].to_string(AP_HEX).c_str(), key_b[i].to_string(AP_HEX).c_str());
        }
      }
      return 1;
    }
  }

  return 0;
}

//------------------------------------------------------------------------
// Helper function for reading images and labels
//------------------------------------------------------------------------
const int TEST_SIZE = 100; // number of test instances
const int REPS = 20; // run over the 100 test instances 20 times to saturate the accelerator

void read_test_images(int8_t test_images[TEST_SIZE][256]) {
  std::ifstream infile("data/test_images.dat");
  if (infile.is_open()) {
    for (int index = 0; index < TEST_SIZE; index++) {
      for (int pixel = 0; pixel < 256; pixel++) {
        int i;
        infile >> i;
        test_images[index][pixel] = i;
      }
    }
    infile.close();
  }
}

void read_test_labels(int test_labels[TEST_SIZE]) {
  std::ifstream infile("data/test_labels.dat");
  if (infile.is_open()) {
    for (int index = 0; index < TEST_SIZE; index++) {
      infile >> test_labels[index];
    }
    infile.close();
  }
}

//--------------------------------------
// main function
//--------------------------------------
int main(int argc, char **argv) {
  // Open channels to the FPGA board.
  // These channels appear as files to the Linux OS
  int fdr = open("/dev/xillybus_read_32", O_RDONLY);
  int fdw = open("/dev/xillybus_write_32", O_WRONLY);

  // Check that the channels are correctly opened
  if ((fdr < 0) || (fdw < 0)) {
    fprintf(stderr, "Failed to open Xillybus device channels\n");
    exit(-1);
  }

  // Arrays to store test data and expected results (labels)
  int8_t test_images[TEST_SIZE][256];
  bit32_t test_image;
  int test_labels[TEST_SIZE];

  // Timer
  Timer timer("digitrec bnn on FPGA");
  // intermediate results
  int nbytes;
  int error = 0;
  int num_test_insts = 0;
  float correct = 0.0;

  //--------------------------------------------------------------------
  // Read data from the input file into two arrays
  //--------------------------------------------------------------------
  read_test_images(test_images);
  read_test_labels(test_labels);

  //--------------------------------------------------------------------
  // Run it once without timer to test accuracy
  //--------------------------------------------------------------------
  std::cout << "Testing accuracy over " << TEST_SIZE << " images." << std::endl;
  // Send data to accelerator
  for (int i = 0; i < TEST_SIZE; ++i) {
    // Send 32-bit value through the write channel
    for (int j = 0; j < 8; j++) {
      for (int k = 0; k < 32; k++) {
        test_image(k, k) = test_images[i][j * 32 + k];
      }
      nbytes = write(fdw, (void *)&test_image, sizeof(test_image));
      assert(nbytes == sizeof(test_image));
    }
  }
  // Receive data from the accelerator
  for (int i = 0; i < TEST_SIZE; ++i) {
    bit32_t output;
    nbytes = read(fdr, (void *)&output, sizeof(output));
    assert(nbytes == sizeof(output));
    // verify results
    if (output == test_labels[i])
      correct += 1.0;
  }
  // Calculate error rate
  std::cout << "Accuracy: " << correct / TEST_SIZE << std::endl;

  //--------------------------------------------------------------------
  // Run it 20 times to test performance
  //--------------------------------------------------------------------
  std::cout << "Testing performance over " << REPS*TEST_SIZE << " images." << std::endl;
  timer.start();
  // Send data to accelerator
  for (int r = 0; r < REPS; r++) {
    for (int i = 0; i < TEST_SIZE; ++i) {
      // Send 32-bit value through the write channel
      for (int j = 0; j < 8; j++) {
        for (int k = 0; k < 32; k++) {
          test_image(k, k) = test_images[i][j * 32 + k];
        }
        nbytes = write(fdw, (void *)&test_image, sizeof(test_image));
        assert(nbytes == sizeof(test_image));
      }
    }
  }
  // Receive data from the accelerator
  for (int r = 0; r < REPS; r++) {
    for (int i = 0; i < TEST_SIZE; ++i) {
      bit32_t output;
      nbytes = read(fdr, (void *)&output, sizeof(output));
      assert(nbytes == sizeof(output));
      // verify results
      if (output == test_labels[i])
        correct += 1.0;
    }
  }
  timer.stop();
  // total time wil be automatically printed upon exit.

  return 0;
}
