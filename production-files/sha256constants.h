/**
  @file sha256constants.h
  @author CSC 230
  This file defines a few constants and types used by the SHA256 algorithm.
 */

#ifndef SHA256CONSTANTS_H
#define SHA256CONSTANTS_H

/** This file contains specific constant values used by the SHA256
    algorithm.  Putting them a separate file lets us avoid magic
    numbers in the rest of the implementation. */

/** Type used to represent a 32-bit word. */
typedef unsigned int word;

/** This contains the 8 initial vales for the h[0] .. h[7] hash
    state. */
extern word initial_h[];

/** This contains the k[] values used in the compression function of
    the SHA256 algorithm. */
extern word constant_k[];

#endif
