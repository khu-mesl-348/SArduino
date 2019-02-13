#include "sha256.h"
// application reads from the specified serial port and reports the collected data

void Sha256_Init(CSha256 *p)
{	p->state[0] = 0x6a09e667;
	p->state[1] = 0xbb67ae85;
	p->state[2] = 0x3c6ef372;
	p->state[3] = 0xa54ff53a;
	p->state[4] = 0x510e527f;
	p->state[5] = 0x9b05688c;
	p->state[6] = 0x1f83d9ab;
	p->state[7] = 0x5be0cd19;
	p->count = 0;
}

static void Sha256_Transform(UInt32 *state, const UInt32 *data)
{	
	UInt32 W[16];
	unsigned j;
#ifdef _SHA256_UNROLL2
	UInt32 a,b,c,d,e,f,g,h;
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
#else
	UInt32 T[8];
	for (j = 0; j < 8; j++)
		T[j] = state[j];
#endif
	for (j = 0; j < 64; j += 16)
	{
#if defined(_SHA256_UNROLL) || defined(_SHA256_UNROLL2)
		RX_8(0); RX_8(8);
#else
		unsigned i;
		for (i = 0; i < 16; i++) { R(i); }
#endif
	}
#ifdef _SHA256_UNROLL2
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
#else
	for (j = 0; j < 8; j++)
		state[j] += T[j];
#endif
	/* Wipe variables */
	/* memset(W, 0, sizeof(W)); */
	/* memset(T, 0, sizeof(T)); */
}
#undef S0
#undef S1
#undef s0
#undef s1
static void Sha256_WriteByteBlock(CSha256 *p)
{	UInt32 data32[16];
	unsigned i;
	for (i = 0; i < 16; i++)
		data32[i] =
		((UInt32)(p->buffer[i * 4    ]) << 24) +
		((UInt32)(p->buffer[i * 4 + 1]) << 16) +
		((UInt32)(p->buffer[i * 4 + 2]) <<  8) +
		((UInt32)(p->buffer[i * 4 + 3]));
	Sha256_Transform(p->state, data32);
}

void Sha256_Update(CSha256 *p, const Byte *data, size_t size)
{	UInt32 curBufferPos = (UInt32)p->count & 0x3F;
	while (size > 0)
	{
		p->buffer[curBufferPos++] = *data++;
		p->count++;
		size--;
		if (curBufferPos == 64)
		{
			curBufferPos = 0;
			Sha256_WriteByteBlock(p);
		}
	}
}void Sha256_Final(CSha256 *p, Byte *digest)
{	UInt64 lenInBits = (p->count << 3);
	UInt32 curBufferPos = (UInt32)p->count & 0x3F;
	unsigned i;
	p->buffer[curBufferPos++] = 0x80;
	while (curBufferPos != (64 - 8))
	{
		curBufferPos &= 0x3F;
		if (curBufferPos == 0)
			Sha256_WriteByteBlock(p);
		p->buffer[curBufferPos++] = 0;
	}
	for (i = 0; i < 8; i++)
	{
		p->buffer[curBufferPos++] = (Byte)(lenInBits >> 56);
		lenInBits <<= 8;
	}
	Sha256_WriteByteBlock(p);
	for (i = 0; i < 8; i++)
	{
		*digest++ = (Byte)(p->state[i] >> 24);
		*digest++ = (Byte)(p->state[i] >> 16);
		*digest++ = (Byte)(p->state[i] >> 8);
		*digest++ = (Byte)(p->state[i]);
	}
	Sha256_Init(p);
}