#pragma once
#include <stdint.h>

struct Sha1
{
	uint32_t	m_h0;
	uint32_t	m_h1;
	uint32_t	m_h2;
	uint32_t	m_h3;
	uint32_t	m_h4;
};

void sha1(const void* data, size_t size, struct Sha1* sha1);
