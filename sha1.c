#include "sha1.h"

static inline uint32_t EndianSwap16(uint16_t val) { return (val << 8) | (val >> 8); }
static inline uint32_t EndianSwap32(uint32_t val) { return (val << 24) | ((val & 0xFF00) << 8) | ((val >> 8) & 0xFF00) | (val >> 24); }
static inline uint64_t EndianSwap64(uint64_t val) { return (val << 56) | ((val & 0xFF00) << 40) | ((val & 0xFF0000) << 24) | ((val & 0xFF000000) << 8) | ((val >> 8) & 0xFF000000) | ((val >> 24) & 0xFF0000) | ((val >> 40) & 0xFF00) | (val >> 56); }

static inline uint16_t BigEndian16(uint16_t val) { return EndianSwap16(val); }
static inline uint32_t BigEndian32(uint32_t val) { return EndianSwap32(val); }
static inline uint64_t BigEndian64(uint64_t val) { return EndianSwap64(val); }

static inline uint32_t rotate_left(uint32_t val, uint32_t rot) { return (val << rot) | (val >> (32 - rot)); }

static void sha1_block(struct Sha1* sha1, const uint32_t* data)
{
	uint32_t w[80];
	for (int i = 0; i < 16; ++i)
		w[i] = BigEndian32(data[i]);
	for (int i = 16; i < 80; ++i)
		w[i] = rotate_left(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

	uint32_t a = sha1->m_h0;
	uint32_t b = sha1->m_h1;
	uint32_t c = sha1->m_h2;
	uint32_t d = sha1->m_h3;
	uint32_t e = sha1->m_h4;

	for (int i = 0; i < 20; ++i)
	{
		uint32_t f = (b & c) | ((~b) & d);
		uint32_t k = 0x5A827999;
		uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = temp;
	}
	for (int i = 20; i < 40; ++i)
	{
		uint32_t f = b ^ c ^ d;
		uint32_t k = 0x6ED9EBA1;
		uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = temp;
	}
	for (int i = 40; i < 60; ++i)
	{
		uint32_t f = (b & c) | (b & d) | (c & d);
		uint32_t k = 0x8F1BBCDC;
		uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = temp;
	}
	for (int i = 60; i < 80; ++i)
	{
		uint32_t f = b ^ c ^ d;
		uint32_t k = 0xCA62C1D6;
		uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = temp;
	}

	sha1->m_h0 += a;
	sha1->m_h1 += b;
	sha1->m_h2 += c;
	sha1->m_h3 += d;
	sha1->m_h4 += e;
}

void sha1(const void* data, size_t size, struct Sha1* sha1)
{
	size_t ml = 8 * size;

	sha1->m_h0 = 0x67452301;
	sha1->m_h1 = 0xEFCDAB89;
	sha1->m_h2 = 0x98BADCFE;
	sha1->m_h3 = 0x10325476;
	sha1->m_h4 = 0xC3D2E1F0;

	const uint32_t* dataU32 = (const uint32_t*)data;
	for (; size >= 16*sizeof(uint32_t); size -= 16*sizeof(uint32_t), dataU32 += 16)
		sha1_block(sha1, dataU32);

	uint32_t buffer[16];
	uint8_t* bufferU8 = (uint8_t*)buffer;
	const uint8_t* dataU8 = (const uint8_t*)dataU32;
	for (size_t i = 0; i < size; ++i)
		bufferU8[i] = dataU8[i];
	bufferU8[size++] = 0x80;
	if (size + sizeof(uint64_t) > sizeof(buffer))
	{
		for (; size < sizeof(buffer); ++size)
			bufferU8[size] = 0x00;
		sha1_block(sha1, buffer);
		size = 0;
	}
	for (; size < sizeof(buffer) - sizeof(uint64_t); ++size)
		bufferU8[size] = 0x00;
	uint64_t* bufferU64 = (uint64_t*)&bufferU8[size];
	*bufferU64 = BigEndian64(ml);
	sha1_block(sha1, buffer);
}
