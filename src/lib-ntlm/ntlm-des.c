/*
 * Implements DES encryption, but not decryption.
 * DES is used to create LM password hashes and both LM and NTLM Responses.
 *
 * Copyright (C) 2003, 2004 by Christopher R. Hertel <crh@ubiqx.mn.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * Notes:
 *
 *  This implementation was created by studying many existing examples
 *  found in Open Source, in the public domain, and in various documentation.
 *  The SMB protocol makes minimal use of the DES function, so this is a
 *  minimal implementation.  That which is not required has been removed.
 *
 *  The SMB protocol uses the DES algorithm as a hash function, not an
 *  encryption function.  The auth_DEShash() implemented here is a one-way
 *  function.  The reverse is not implemented in this module.  Also, there
 *  is no attempt at making this either fast or efficient.  There is no
 *  need, as the auth_DEShash() function is used for generating the LM
 *  Response from a 7-byte key and an 8-byte challenge.  It is not intended
 *  for use in encrypting large blocks of data or data streams.
 *
 *  As stated above, this implementation is based on studying existing work
 *  in the public domain or under Open Source (specifically LGPL) license.
 *  The code, however, is written from scratch.  Obviously, I make no claim
 *  with regard to those earlier works (except to claim that I am grateful
 *  to the previous implementors whose work I studied).  See the list of
 *  references below for resources I used.
 *
 *  References:
 *    I read through the libmcrypt code to see how they put the pieces
 *    together.  See: http://mcrypt.hellug.gr/
 *    Libmcrypt is available under the terms of the LGPL.
 *
 *    The libmcrypt implementation includes the following credits:
 *      written 12 Dec 1986 by Phil Karn, KA9Q; large sections adapted
 *      from the 1977 public-domain program by Jim Gillogly
 *      Modified for additional speed - 6 December 1988 Phil Karn
 *      Modified for parameterized key schedules - Jan 1991 Phil Karn
 *      modified in order to use the libmcrypt API by Nikos Mavroyanopoulos
 *      All modifications are placed under the license of libmcrypt.
 *
 *    See also Phil Karn's privacy and security page:
 *      http://www.ka9q.net/privacy.html
 *
 *    I relied heavily upon:
 *      Applied Cryptography, Second Edition:
 *        Protocols, Algorithms, and Source Code in C
 *      by Bruce Schneier. ISBN 0-471-11709-9, John Wiley & Sons, Inc., 1996
 *    Particularly Chapter 12.
 *
 *    Here's one more DES resource, which I found quite helpful (aside from
 *    the Clinton jokes):
 *      http://www.aci.net/kalliste/des.htm
 *
 *    Finally, the use of DES in SMB is covered in:
 *      Implementing CIFS - the Common Internet File System
 *      by your truly.  ISBN 0-13-047116-X, Prentice Hall PTR., August 2003
 *    Section 15.3, in particular.
 *    (Online at: http://ubiqx.org/cifs/SMB.html#SMB.8.3)
 */

#include "ntlm-des.h"

/*
 * Initial permutation map.
 * In the first step of DES, the bits of the initial plaintext are rearranged 
 * according to the map given below.  This map and those like it are read by
 * the permute() function (below) which uses the maps as a guide when moving
 * bits from one place to another.
 *
 * Note that the values here are all one less than those shown in Schneier.
 * That's because C likes to start counting from 0, not 1.
 *
 * According to Schneier (Ch12, pg 271), the purpose of the initial
 * permutation was to make it easier to load plaintext and ciphertext into
 * a DES ecryption chip.  I have no idea why that would be the case.
 */
static const unsigned char InitialPermuteMap[64] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6
};

/*
 * Key permutation map.
 * Like the input data and encryption result, the key is permuted before
 * the algorithm really gets going.  The original algorithm called for an
 * eight-byte key in which each byte contained a parity bit.  During the
 * key permutiation, the parity bits were discarded.  The DES algorithm,
 * as used with SMB, does not make use of the parity bits.  Instead, SMB
 * passes 7-byte keys to DES.  For DES implementations that expect parity,
 * the parity bits must be added.  In this case, however, we're just going
 * to start with a 7-byte (56 bit) key.  KeyPermuteMap, below, is adjusted
 * accordingly and, of course, each entry in the map is reduced by 1 with
 * respect to the documented values because C likes to start counting from
 * 0, not 1.
 */
static const unsigned char KeyPermuteMap[56] = {
	49, 42, 35, 28, 21, 14,  7,  0,
	50, 43, 36, 29, 22, 15,  8,  1,
	51, 44, 37, 30, 23, 16,  9,  2,
	52, 45, 38, 31, 55, 48, 41, 34,
	27, 20, 13,  6, 54, 47, 40, 33,
	26, 19, 12,  5, 53, 46, 39, 32,
	25, 18, 11,  4, 24, 17, 10,  3
};

/*
 * Key rotation table.
 * At the start of each round of encryption, the key is split and each
 * 28-bit half is rotated left.  The number of bits of rotation per round
 * is given in the table below.
 */
static const unsigned char KeyRotation[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/*
 * Key compression table.
 * This table is used to select 48 of the 56 bits of the key.
 * The left and right halves of the source text are each 32 bits,
 * but they are expanded to 48 bits and the results are XOR'd
 * against the compressed (48-bit) key.
 */
static const unsigned char KeyCompression[48] = {
	13, 16, 10, 23,  0,  4,  2, 27,
	14,  5, 20,  9, 22, 18, 11,  3,
	25,  7, 15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54, 29, 39,
	50, 44, 32, 47, 43, 48, 38, 55,
	33, 52, 45, 41, 49, 35, 28, 31
};

/*
 * Data expansion table.
 * This table is used after the data block (64-bits) has been split
 * into two 32-bit (4-byte) halves (generally denoted L and R).
 * Each 32-bit half is "expanded", using this table, to a 48 bit
 * data block, which is then XOR'd with the 48 bit subkey for the
 * round.
 */
static const unsigned char DataExpansion[48] = {
	31,  0,  1,  2,  3,  4,  3,  4,
	 5,  6,  7,  8,  7,  8,  9, 10,
	11, 12, 11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20, 19, 20,
	21, 22, 23, 24, 23, 24, 25, 26,
	27, 28, 27, 28, 29, 30, 31,  0
};

/*
 * The (in)famous S-boxes.
 * These are used to perform substitutions.
 * Six bits worth of input will return four bits of output.
 * The four bit values are stored in these tables.  Each table has
 * 64 entries...and 6 bits provides a number between 0 and 63.
 * There are eight S-boxes, one per 6 bits of a 48-bit value.
 * Thus, 48 bits are reduced to 32 bits.  Obviously, this step
 * follows the DataExpansion step.
 *
 * Note that the literature generally shows this as 8 arrays each
 * with four rows and 16 colums.  There is a complex formula for
 * mapping the 6 bit input values to the correct row and column.
 * I've pre-computed that mapping, and the tables below provide
 * direct 6-bit input to 4-bit output.  See pp 274-274 in Schneier.
 */
static const unsigned char sbox[8][64] = {
	{	/* S0 */
		14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
		 3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
		 4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
		15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
	},
	{	/* S1 */
		15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
		 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
		 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
		 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9
	},
	{	/* S2 */
		10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
		 1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
		13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
		11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
	},
	{	/* S3 */
		 7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
		 1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
		10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
		15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
	},
	{	/* S4 */
		 2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
		 8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
		 4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
		15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
	},
	{	/* S5 */
		12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
		 0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
		 9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
		 7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
	},
	{	/* S6 */
		 4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
		 3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
		 1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
		10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
	},
	{	/* S7 */
		13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
		10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
		 7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
		 0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
	}
};

/*
 * P-Box permutation.
 * This permutation is applied to the result of the S-Box Substitutions.
 * It's a straight-forward re-arrangement of the bits.
 */
static const unsigned char pbox[32] = {
	15,  6, 19, 20, 28, 11, 27, 16,
	 0, 14, 22, 25,  4, 17, 30,  9,
	 1,  7, 23, 13, 31, 26,  2,  8,
	18, 12, 29,  5, 21, 10,  3, 24
};

/*
 * Final permutation map.
 * This is supposed to be the inverse of the Initial Permutation,
 * but there's been a bit of fiddling done.
 * As always, the values given are one less than those in the literature
 * (because C starts counting from 0, not 1).  In addition, the penultimate
 * step in DES is to swap the left and right hand sides of the ciphertext.
 * The inverse of the Initial Permutation is then applied to produce the
 * final result.
 * To save a step, the map below does the left/right swap as well as the
 * inverse permutation.
 */
static const unsigned char FinalPermuteMap[64] = {
	7, 39, 15, 47, 23, 55, 31, 63,
	6, 38, 14, 46, 22, 54, 30, 62,
	5, 37, 13, 45, 21, 53, 29, 61,
	4, 36, 12, 44, 20, 52, 28, 60,
	3, 35, 11, 43, 19, 51, 27, 59,
	2, 34, 10, 42, 18, 50, 26, 58,
	1, 33,  9, 41, 17, 49, 25, 57,
	0, 32,  8, 40, 16, 48, 24, 56
};

/*
 * Macros:
 *
 *  CLRBIT( STR, IDX )
 *    Input:  STR - (uchar *) pointer to an array of 8-bit bytes.
 *            IDX - (int) bitwise index of a bit within the STR array
 *                  that is to be cleared (that is, given a value of 0).
 *    Notes:  This macro clears a bit within an array of bits (which is
 *            built within an array of bytes).
 *          - The macro converts to an assignment of the form A &= B.
 *          - The string of bytes is viewed as an array of bits, read from
 *            highest order bit first.  The highest order bit of a byte
 *            would, therefore, be bit 0 (within that byte).
 *
 *  SETBIT( STR, IDX )
 *    Input:  STR - (uchar *) pointer to an array of 8-bit bytes.
 *            IDX - (int) bitwise index of a bit within the STR array
 *                  that is to be set (that is, given a value of 1).
 *    Notes:  This macro sets a bit within an array of bits (which is
 *            built within an array of bytes).
 *          - The macro converts to an assignment of the form A |= B.
 *          - The string of bytes is viewed as an array of bits, read from
 *            highest order bit first.  The highest order bit of a byte
 *            would, therefore, be bit 0 (within that byte).
 *
 *  GETBIT( STR, IDX )
 *    Input:  STR - (uchar *) pointer to an array of 8-bit bytes.
 *            IDX - (int) bit-wise index of a bit within the STR array
 *                  that is to be read.
 *    Output: True (1) if the indexed bit was set, else false (0).
 */
#define CLRBIT(STR, IDX) ((STR)[(IDX)/8] &= ~(0x01 << (7 - ((IDX)%8))))

#define SETBIT( STR, IDX ) ( (STR)[(IDX)/8] |= (0x01 << (7 - ((IDX)%8))) )

#define GETBIT( STR, IDX ) (( ((STR)[(IDX)/8]) >> (7 - ((IDX)%8)) ) & 0x01)

/*
 * Performs a DES permutation, which re-arranges the bits in an array of
 * bytes.
 *
 *  Input:  dst     - Destination into which to put the re-arranged bits.
 *          src     - Source from which to read the bits.
 *          map     - Permutation map.
 *          mapsize - Number of bytes represented by the <map>.  This also
 *                    represents the number of bytes to be copied to <dst>.
 *
 *  Output: none.
 *
 *  Notes:  <src> and <dst> must not point to the same location.
 *
 *        - No checks are done to ensure that there is enough room
 *          in <dst>, or that the bit numbers in <map> do not exceed
 *          the bits available in <src>.  A good reason to make this
 *          function static (private).
 *
 *        - The <mapsize> value is in bytes.  All permutations in DES
 *          use tables that are a multiple of 8 bits, so there is no
 *          need to handle partial bytes.  (Yes, I know that there
 *          are some machines out there that still use bytes of a size
 *          other than 8 bits.  For our purposes we'll stick with 8-bit
 *          bytes.)
 */
static void
permute(unsigned char *dst, const unsigned char *src,
	const unsigned char * map, const int mapsize)
{
	int bitcount;
	int i;

	/* Clear all bits in the destination. */
	for (i = 0; i < mapsize; i++)
		dst[i] = 0;

	/* Set destination bit if the mapped source bit it set. */
	bitcount = mapsize * 8;
	for (i = 0; i < bitcount; i++) {
		if (GETBIT(src, map[i]))
			SETBIT(dst, i);
	}
}

/*
 * Split the 56-bit key in half & left rotate each half by <numbits> bits.
 *
 *  Input:  key     - The 56-bit key to be split-rotated.
 *          numbits - The number of bits by which to rotate the key.
 *
 *  Output: none.
 *
 *  Notes:  There are probably several better ways to implement this.
 */
static void
keyshift(unsigned char *key, const int numbits)
{
	int i;
	unsigned char keep = key[0];	/* Copy the highest order bits of the key. */

	/* Repeat the shift process <numbits> times. */
	for (i = 0; i < numbits; i++) {
		int j;

		/* Shift the entire thing, byte by byte.
		 */
		for (j = 0; j < 7; j++) {
			if (j && (key[j] & 0x80))	/* If the top bit of this byte is set. */
				key[j - 1] |= 0x01;	/* ...shift it to last byte's low bit. */
			key[j] <<= 1;	/* Then left-shift the whole byte.     */
		}

		/* Now move the high-order bits of each 28-bit half-key to their
		 * correct locations.
		 * Bit 27 is the lowest order bit of the first half-key.
		 * Before the shift, it was the highest order bit of the 2nd half-key.
		 */
		if (GETBIT(key, 27)) {	/* If bit 27 is set... */
			CLRBIT(key, 27);	/* ...clear bit 27. */
			SETBIT(key, 55);	/* ...set lowest order bit of 2nd half-key. */
		}

		/* We kept the highest order bit of the first half-key in <keep>.
		 * If it's set, copy it to bit 27.
		 */
		if (keep & 0x80)
			SETBIT(key, 27);

		/* Rotate the <keep> byte too, in case <numbits> is 2 and there's
		 * a second round coming.
		 */
		keep <<= 1;
	}
}

/*
 * Perform S-Box substitutions.
 *
 *  Input:  dst - Destination byte array into which the S-Box substituted
 *                bitmap will be written.
 *          src - Source byte array.
 *
 *  Output: none.
 *
 *  Notes:  It's really not possible (for me, anyway) to understand how
 *          this works without reading one or more detailed explanations.
 *          Quick overview, though:
 *
 *          After the DataExpansion step (in which a 32-bit bit array is
 *          expanded to a 48-bit bit array) the expanded data block is
 *          XOR'd with 48-bits worth of key.  That 48 bits then needs to
 *          be condensed back into 32 bits.
 *
 *          The S-Box substitution handles the data reduction by breaking
 *          the 48-bit value into eight 6-bit values.  For each of these
 *          6-bit values there is a table (an S-Box table).  The table
 *          contains 64 possible values.  Conveniently, a 6-bit integer
 *          can represent a value between 0 and 63.
 *
 *          So, if you think of the 48-bit bit array as an array of 6-bit
 *          integers, you use S-Box table 0 with the 0th 6-bit value.
 *          Table 1 is used with the 6-bit value #1, and so on until #7.
 *          Within each table, the correct substitution is found based
 *          simply on the value of the 6-bit integer.
 *
 *          Well, the original algorithm (and most documentation) don't
 *          make it so simple.  There's a complex formula for mapping
 *          the 6-bit values to the correct substitution.  Fortunately,
 *          those lookups can be precomputed (and have been for this
 *          implementation).  See pp 274-274 in Schneier.
 *
 *          Oh, and the substitute values are all 4-bit values, so each
 *          6-bits gets reduced to 4-bits resulting in a 32-bit bit array.
 */
static void
s_box(unsigned char *dst, const unsigned char *src)
{
	int i;

	/* Clear the destination array. */
	for (i = 0; i < 4; i++)
		dst[i] = 0;

	/* For each set of six input bits... */
	for (i = 0; i < 8; i++) {
		int j;
		int Snum;
		int bitnum;

		/* Extract the 6-bit integer from the source.
		 * This will be the lookup key within the sbox[i] array.
		 */
		for (Snum = j = 0, bitnum = (i * 6); j < 6; j++, bitnum++) {
			Snum <<= 1;
			Snum |= GETBIT(src, bitnum);
		}

		/* Find the correct value in the correct sbox[]
		 * and copy it into the destination.
		 * Left shift the nibble four bytes for even values of <i>.
		 */
		if (0 == (i % 2))
			dst[i / 2] |= ((sbox[i][Snum]) << 4);
		else
			dst[i / 2] |= sbox[i][Snum];
	}
}

/*
 * Perform an XOR operation on two byte arrays.
 *
 *  Input:  dst   - Destination array to which the result will be written.
 *          a     - The first string of bytes.
 *          b     - The second string of bytes.
 *          count - Number of bytes to XOR against one another.
 *
 *  Output: none.
 *
 *  Notes:  This function operates on whole byte chunks.  There's no need
 *          to XOR partial bytes so no need to write code to handle it.
 *
 *        - This function essentially implements dst = a ^ b; for byte
 *          arrays.
 *
 *        - <dst> may safely point to the same location as <a> or <b>.
 */
static void xor(unsigned char *dst, const unsigned char *a, 
		const unsigned char *b,	const int count)
{
	int i;
	for (i = 0; i < count; i++)
		dst[i] = a[i] ^ b[i];
}

/*
 * DES encryption of the input data using the input key.
 *
 *  Input:  dst - Destination buffer.  It *must* be at least eight bytes
 *                in length, to receive the encrypted result.
 *          key - Encryption key.  Exactly seven bytes will be used.
 *                If your key is shorter, ensure that you pad it to seven
 *                bytes.
 *          src - Source data to be encrypted.  Exactly eight bytes will
 *                be used.  If your source data is shorter, ensure that
 *                you pad it to eight bytes.
 *
 *  Output: A pointer to the encrpyted data (same as <dst>).
 *
 *  Notes:  In SMB, the DES function is used as a hashing function rather
 *          than an encryption/decryption tool.  When used for generating
 *          the LM hash the <src> input is the known value "KGS!@#$%" and
 *          the key is derived from the password entered by the user.
 *          When used to generate the LM or NTLM response, the <key> is
 *          derived from the LM or NTLM hash, and the challenge is used
 *          as the <src> input.
 *          See: http://ubiqx.org/cifs/SMB.html#SMB.8.3
 *
 *        - This function is called "DEShash" rather than just "DES"
 *          because it is only used for creating LM hashes and the
 *          LM/NTLM responses.  For all practical purposes, however, it
 *          is a full DES encryption implementation.
 *
 *        - This DES implementation does not need to be fast, nor is a
 *          DES decryption function needed.  The goal is to keep the
 *          code small, simple, and well documented.
 *
 *        - The input values are copied and refiddled within the module
 *          and the result is not written to <dst> until the very last
 *          step, so it's okay if <dst> points to the same memory as
 *          <key> or <src>.
 */
unsigned char *
deshash(unsigned char *dst, const unsigned char *key,
	const unsigned char *src)
{
	int i;			/* Loop counter. */
	unsigned char K[7];	/* Holds the key, as we manipulate it. */
	unsigned char D[8];	/* The data block, as we manipulate it. */

	/* Create the permutations of the key and the source. */
	permute(K, key, KeyPermuteMap, 7);
	permute(D, src, InitialPermuteMap, 8);

	/* DES encryption proceeds in 16 rounds.
	 * The stuff inside the loop is known in the literature as "function f".
	 */
	for (i = 0; i < 16; i++) {
		int j;
		unsigned char *L = D;		/* The left 4 bytes (half) of the data block. */
		unsigned char *R = &(D[4]);	/* The right half of the ciphertext block. */
		unsigned char Rexp[6];		/* Expanded right half. */
		unsigned char Rn[4];		/* New value of R, as we manipulate it. */
		unsigned char SubK[6];		/* The 48-bit subkey. */

		/* Generate the subkey for this round. */
		keyshift(K, KeyRotation[i]);
		permute(SubK, K, KeyCompression, 6);

		/* Expand the right half (R) of the data block to 48 bytes,
		 * then XOR the result with the Subkey for this round.
		 */
		permute(Rexp, R, DataExpansion, 6);
		xor(Rexp, Rexp, SubK, 6);

		/* S-Box substitutions, P-Box permutation, and final XOR.
		 * The S-Box substitutions return a 32-bit value, which is then
		 * run through the 32-bit to 32-bit P-Box permutation.  The P-Box
		 * result is then XOR'd with the left-hand half of the key.
		 * (Rexp is used as a temporary variable between the P-Box & XOR).
		 */
		s_box(Rn, Rexp);
		permute(Rexp, Rn, pbox, 4);
		xor(Rn, L, Rexp, 4);

		/* The previous R becomes the new L,
		 * and Rn is moved into R ready for the next round.
		 */
		for (j = 0; j < 4; j++) {
			L[j] = R[j];
			R[j] = Rn[j];
		}
	}

	/* The encryption is complete.
	 * Now reverse-permute the ciphertext to produce the final result.
	 * We actually combine two steps here.  The penultimate step is to
	 * swap the positions of L and R in the result of the 16 rounds,
	 * after which the reverse of the Initial Permutation is applied.
	 * To save a step, the FinalPermuteMap applies both the L/R swap
	 * and the inverse of the Initial Permutation.
	 */
	permute(dst, D, FinalPermuteMap, 8);
	return dst;
}
