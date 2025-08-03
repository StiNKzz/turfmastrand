#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <math.h>
#include "sha1.h"
#include "pcg-c-basic-0.9/pcg_basic.h"

enum { kVersionMajor = 0, kVersionMinor = 1 };

static inline uint32_t EndianSwap16(uint16_t val) { return (val << 8) | (val >> 8); }
static inline uint32_t EndianSwap32(uint32_t val) { return (val << 24) | ((val & 0xFF00) << 8) | ((val >> 8) & 0xFF00) | (val >> 24); }
static inline uint64_t EndianSwap64(uint64_t val) { return (val << 56) | ((val & 0xFF00) << 40) | ((val & 0xFF0000) << 24) | ((val & 0xFF000000) << 8) | ((val >> 8) & 0xFF000000) | ((val >> 24) & 0xFF0000) | ((val >> 40) & 0xFF00) | (val >> 56); }

static inline uint16_t BigEndian16(uint16_t val) { return EndianSwap16(val); }
static inline uint32_t BigEndian32(uint32_t val) { return EndianSwap32(val); }
static inline uint64_t BigEndian64(uint64_t val) { return EndianSwap64(val); }

static inline uint32_t rotate_left(uint32_t val, uint32_t rot) { return (val << rot) | (val >> (32 - rot)); }

static inline float rand_float(void)
{
	return pcg32_random() / (float)(0x100000000);
}

void shuffle(const uint16_t* indicesOldToNew, void* fileData, uint32_t offset0, uint32_t offset1, uint32_t offset2, uint32_t offset3, unsigned int size, unsigned int stride)
{
	uint8_t* datas[4];
	datas[0] = (uint8_t*)( (uintptr_t)fileData + offset0 );
	datas[1] = (uint8_t*)( (uintptr_t)fileData + offset1 );
	datas[2] = (uint8_t*)( (uintptr_t)fileData + offset2 );
	datas[3] = (uint8_t*)( (uintptr_t)fileData + offset3 );

	uint8_t* buffers[4];
	for (int i = 0; i < 4; ++i)
	{
		buffers[i] = malloc(18 * stride);
		memcpy(buffers[i], datas[i], 18 * stride);
	}

	for (unsigned int i = 0; i < 18*4; ++i)
	{
		unsigned int newIndex = indicesOldToNew[i];
		unsigned int newCourse = newIndex / 18;
		unsigned int newHole = newIndex % 18;

		unsigned int oldCourse = i / 18;
		unsigned int oldHole = i % 18;

		memcpy(datas[newCourse] + newHole * stride, buffers[oldCourse] + oldHole * stride, size);
	}

	for (int i = 0; i < 4; ++i)
		free(buffers[i]);
}

void reindex16(const uint16_t* indicesOldToNew, void* fileData, uint32_t offset, unsigned int stride, uint16_t terminator, unsigned int count)
{
	uint16_t* data = (uint16_t*)( (uintptr_t)fileData + offset );
	for (unsigned int i = 0; i < count; ++i, data += stride)
	{
		uint16_t dataCourseHole = BigEndian16(*data);
		if (terminator == dataCourseHole)
			break;
		unsigned int dataCourse = dataCourseHole >> 8;
		unsigned int dataHole = (dataCourseHole & 0xFF) - 1;
		unsigned int index = dataCourse * 18 + dataHole;
		index = indicesOldToNew[index];
		dataCourse = index / 18;
		dataHole = index % 18;
		dataCourseHole = (dataCourse << 8) | (dataHole + 1);
		*data = BigEndian16(dataCourseHole);
	}
}

void reindex32(const uint16_t* indicesOldToNew, void* fileData, uint32_t offset, unsigned int stride, uint32_t terminator, unsigned int count)
{
	uint32_t* data = (uint32_t*)( (uintptr_t)fileData + offset );
	for (unsigned int i = 0; i < count; ++i, data += stride)
	{
		uint32_t dataCourseHole = BigEndian32(*data);
		if (terminator == dataCourseHole)
			break;
		unsigned int dataCourse = dataCourseHole >> 16;
		unsigned int dataHole = (dataCourseHole & 0xFFFF) - 1;
		unsigned int index = dataCourse * 18 + dataHole;
		index = indicesOldToNew[index];
		dataCourse = index / 18;
		dataHole = index % 18;
		dataCourseHole = (dataCourse << 16) | (dataHole + 1);
		*data = BigEndian32(dataCourseHole);
	}
}

void randomizepins(void* fileData, uint32_t holeInfoOffset)
{
	for (unsigned int holeIdx = 0; holeIdx < 18; ++holeIdx, holeInfoOffset += 24)
	{
		uint32_t holeDataOffset = 0x100000 ^ BigEndian32(*(uint32_t*)( (uintptr_t)fileData + holeInfoOffset ));
		uint32_t pinsOffset = 0x100000 ^ BigEndian32(*(uint32_t*)( (uintptr_t)fileData + holeDataOffset + 2 ));
		uint16_t* pins = (uint16_t*)( (uintptr_t)fileData + pinsOffset );
		uint32_t objectsOffset = 0x100000 ^ BigEndian32(*(uint32_t*)( (uintptr_t)fileData + holeDataOffset + 6 ));
		uint16_t* objects = (uint16_t*)( (uintptr_t)fileData + objectsOffset );
		for (; objects[0] != 0xFFFF; objects += 3)
		{
			uint16_t typeFlags = BigEndian16(objects[0]);
			uint8_t type = typeFlags >> 8;
			if (0x00 == type)
				break;
		}
		uint16_t greenPosX = BigEndian16(objects[1]);
		uint16_t greenPosY = BigEndian16(objects[2]);
		for (unsigned int pinIndex = 0; pinIndex < 8; ++pinIndex, pins += 2)
		{
			float radius = 64.f * sqrtf(rand_float());
			float theta = rand_float() * 6.283185307179586476925286766559f;
			float localPosX = radius * cosf(theta);
			float localPosY = radius * sinf(theta);
			uint16_t pinPosX = greenPosX + (int16_t)(localPosX + 0.5f);
			uint16_t pinPosY = greenPosY + (int16_t)(localPosY + 0.5f);
			pins[0] = BigEndian16(pinPosX);
			pins[1] = BigEndian16(pinPosY);
		}
	}
}

void patchtrees(void* fileData, uint32_t holeInfoOffset, uint8_t expectedTreeType)
{
	for (unsigned int holeIdx = 0; holeIdx < 18; ++holeIdx, holeInfoOffset += 24)
	{
		uint32_t holeDataOffset = 0x100000 ^ BigEndian32(*(uint32_t*)( (uintptr_t)fileData + holeInfoOffset ));
		uint32_t objectsOffset = 0x100000 ^ BigEndian32(*(uint32_t*)( (uintptr_t)fileData + holeDataOffset + 6 ));
		uint16_t* objects = (uint16_t*)( (uintptr_t)fileData + objectsOffset );
		for (; objects[0] != 0xFFFF; objects += 3)
		{
			uint16_t typeFlags = BigEndian16(objects[0]);
			uint8_t type = typeFlags >> 8;
			switch (type)
			{
			case 0x4:
			case 0x5:
			case 0xa:
				type = expectedTreeType;
				typeFlags = (typeFlags & 0xFF) | (type << 8);
				break;
			}
			objects[0] = BigEndian16(typeFlags);
		}
	}
}

void byteswap(uint16_t* data, size_t count)
{
	for (unsigned int i = 0; i < count; ++i)
		data[i] = EndianSwap16(data[i]);
}

void stringify(char* buffer, int len)
{
	for (int i = 0; i < len; ++i)
	{
		if (buffer[i] >= 'A' && buffer[i] <= 'Z')
			buffer[i] += 0x99;
		else if (buffer[i] >= '0' && buffer[i] <= '9')
			buffer[i] += 0xA0;
		else if (' ' == buffer[i])
			buffer[i] = 0xF6;
		else if ('.' == buffer[i])
			buffer[i] = 0xF9;
		else if ('\n' == buffer[i])
			buffer[i] = 0xFD;
		else
			buffer[i] = 0xF5; // '?'
	}
}

int main(int argc, char* argv[])
{
	const pcg32_random_t defaultRand = PCG32_INITIALIZER;
	pcg32_srandom(time(NULL), defaultRand.inc);
	uint32_t seed = pcg32_random();
	pcg32_srandom(seed, defaultRand.inc);

	const char* p1Filename = NULL;
	const char* outFilename = NULL;
	int holes = 0;
	int pins = 0;

	for (int i = 1; i < argc; ++i)
	{
		if (0 == strcmp(argv[i], "--p1"))
			p1Filename = argv[++i];
		else if (0 == strcmp(argv[i], "--out"))
			outFilename = argv[++i];
		else if (0 == strcmp(argv[i], "--seed"))
		{
			if (1 != sscanf_s(argv[++i], "%x", &seed))
			{
				printf("Expected a hexidecimal number after --seed parameter");
				return 1;
			}
		}
		else if (0 == strcmp(argv[i], "--holes"))
			holes = 1;
		else if (0 == strcmp(argv[i], "--pins"))
			pins = 1;
		else
		{
			printf("Unknown parameter: %s\n", argv[i]);
			return 1;
		}
	}

	if (!p1Filename || !outFilename || (0 == holes && 0 == pins))
	{
		printf("Usage: %s <--p1 filename> <--out filename> [--seed hexadecimal] [--holes] [--pins]\n", argv[0]);
		printf("  --holes : randomizes the order of the holes\n");
		printf("  --pins  : generates new pin locations for each hole\n");
		return 1;
	}

	FILE* f;
	
	f = fopen(p1Filename, "rb");
	if (!f)
	{
		printf("Unable to open p1 file: %s\n", p1Filename);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	size_t fileSize = ftell(f);
	fseek(f, 0, SEEK_SET);
	void* fileData = malloc(fileSize);
	fread(fileData, 1, fileSize, f);
	fclose(f);

	struct Sha1 sha1context;
	static const struct Sha1 s_sha1expected =
	{
		0xe7ef87e1,
		0xde21d2bb,
		0x17ef17bb,
		0x08657e92,
		0x363f0e9a,
	};
	sha1(fileData, fileSize, &sha1context);
	if (s_sha1expected.m_h0 != sha1context.m_h0 ||
		s_sha1expected.m_h1 != sha1context.m_h1 ||
		s_sha1expected.m_h2 != sha1context.m_h2 ||
		s_sha1expected.m_h3 != sha1context.m_h3 ||
		s_sha1expected.m_h4 != sha1context.m_h4)
	{
		printf("Expected p1 SHA1 to be %08x%08x%08x%08x%08x but it was %08x%08x%08x%08x%08x\n",
			s_sha1expected.m_h0, s_sha1expected.m_h1, s_sha1expected.m_h2, s_sha1expected.m_h3, s_sha1expected.m_h4,
			sha1context.m_h0, sha1context.m_h1, sha1context.m_h2, sha1context.m_h3, sha1context.m_h4);
		free(fileData);
		return 1;
	}

	byteswap((uint16_t*)fileData, fileSize / sizeof(uint16_t));

	if (holes)
	{
		pcg32_srandom(seed + 0x100000, defaultRand.inc);
		uint16_t indicesOldToNew[18*4];
		for (unsigned int i = 0; i < _countof(indicesOldToNew); ++i)
			indicesOldToNew[i] = i;
		unsigned int remaining = _countof(indicesOldToNew);
		for (unsigned int i = 0; remaining > 1; ++i, --remaining)
		{
			unsigned int j = i + (pcg32_random() % remaining);
			uint16_t temp = indicesOldToNew[i];
			indicesOldToNew[i] = indicesOldToNew[j];
			indicesOldToNew[j] = temp;
		}

		shuffle(indicesOldToNew, fileData, 0x157B6C, 0x157EFC, 0x1580C4, 0x157D34, 24, 24); // hole data
		shuffle(indicesOldToNew, fileData, 0x17A280+2, 0x17A2EC+2, 0x17A358+2, 0x17A3C4+2, 4, 6); // preview audio cues
		shuffle(indicesOldToNew, fileData, 0x17A74C, 0x17A794, 0x17A7DC, 0x17A824, 4, 4); // preview graphic pointers
		shuffle(indicesOldToNew, fileData, 0x17A9E0, 0x17AA16, 0x17AA4C, 0x17AA82, 3, 3); // preview yard ranges

		reindex16(indicesOldToNew, fileData, 0x155622, 1, 0x0000, ~0U); // holes using alternate wind meter hud location
		reindex16(indicesOldToNew, fileData, 0x1614E4, 5, 0xFFFF, ~0U); // holes with cliff face sprites	
		reindex16(indicesOldToNew, fileData, 0x161522, 1, 0xFFFF, ~0U); // holes that play $104E audio cue (waterfall splash) at hole start
		reindex16(indicesOldToNew, fileData, 0x161C18, 4, 0x0000, 2); // holes with animating water planes
		reindex16(indicesOldToNew, fileData, 0x17A86C, 2, 0xFFFF, ~0U); // preview topdown x-coord
		reindex32(indicesOldToNew, fileData, 0x10F2EA, 1, 0x00000000, 5); // demo holes
		reindex32(indicesOldToNew, fileData, 0x15A1DC, 2, 0xFFFFFFFF, ~0U); // holes with cliffs

		patchtrees(fileData, 0x157B6C, 0xA);
		patchtrees(fileData, 0x157EFC, 0x5);
		patchtrees(fileData, 0x1580C4, 0x5);
		patchtrees(fileData, 0x157D34, 0x4);
	}

	if (pins)
	{
		pcg32_srandom(seed + 0x200000, defaultRand.inc);
		randomizepins(fileData, 0x157B6C);
		randomizepins(fileData, 0x157EFC);
		randomizepins(fileData, 0x1580C4);
		randomizepins(fileData, 0x157D34);
	}

	char buffer[48];
	int buflen;

	// patch the title screen banner with randomizer info
	buflen = sprintf(buffer, "TurfMastRand V%d.%d Seed %08X\xFE", kVersionMajor, kVersionMinor, seed);
	memcpy((uint8_t*)fileData + 0xFFFC0, buffer, buflen);
	*(uint32_t*)( (uintptr_t)fileData + 0x17EEDE ) = BigEndian32(0x2FFFC0);
	*(uint16_t*)( (uintptr_t)fileData + 0x17EEE6 ) = BigEndian16(0x7097);
	*(uint32_t*)( (uintptr_t)fileData + 0x17EECE ) = BigEndian32(0x2FFFC0);
	*(uint16_t*)( (uintptr_t)fileData + 0x17EECA ) = BigEndian16(0x7097);

	byteswap((uint16_t*)fileData, fileSize / sizeof(uint16_t));

	// place a human readable watermark in the rom
	buflen = sprintf(buffer, "TurfMastRandV%d.%dSeed%08XGLHF", kVersionMajor, kVersionMinor, seed);
	memcpy((uint8_t*)fileData + 0xFFFE0, buffer, buflen);

	f = fopen(outFilename, "wb");
	if (!f)
	{
		printf("Couldn't open out file: %s\n", outFilename);
		free(fileData);
		return 1;
	}
	fwrite(fileData, 1, fileSize, f);
	fclose(f);

	printf("TurfMastRand Version %d.%d\n", kVersionMajor, kVersionMinor);
	printf("Seed: %08X\n", seed);

	free(fileData);
	return 0;
}
