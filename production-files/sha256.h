/**
 */

#ifndef SHA256_H
#define SHA256_H

#include "sha256constants.h"
#include <stdlib.h>
#include <stdio.h>

/** Type used to represent a byte. */
typedef unsigned char byte;

/** Type used to represent a 64-bit value. */
typedef unsigned long word64;

/** Number of bits in a byte. */
#define BBITS 8

/** Size of an input block in bytes. */
#define BLOCK_SIZE 64

/** Number of bits in a word. */
#define WORD_LEN 32

/** Initial length of w array */
#define INIT_W_LEN 16

/** Size of the hash, in words. */
#define HASH_WORDS 8



/** State of the SHA256 algorithm, including bytes of input data
    waiting to be hashed. */
typedef struct {
  /** Input data not yet hashed. */
  byte pending[ BLOCK_SIZE ];

  /** Number of byes currently in the pending array. */
  int pcount;

  // Add any fields you need.
  /** Number of total bytes in the input file */
  int len;
  
  /** Checks to see if len is initialized */
  int foundLen;

  /** Current hash value. */
  word h[ HASH_WORDS ];
} SHAState;

SHAState *makeState();

void freeState( SHAState *state );

word rotate( word val, int bits );

word Sigma0( word a );

word Sigma1( word a );

word ChFunction( word e, word f, word g );

word MaFunction( word a, word b, word c );

void compression( SHAState *state );

void extendMessage( byte const pending[ BLOCK_SIZE ], word w[ BLOCK_SIZE ] );

void update( SHAState *state, const byte data[], int len );

void digest( SHAState *state, word hash[ HASH_WORDS ] );

#endif
