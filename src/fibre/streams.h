// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_FIBRE_STREAMS_H
#define BITCOIN_FIBRE_STREAMS_H

#include <serialize.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <ios>
#include <span>
#include <vector>

/** Write-only stream for FIBRE chunk serialization into a vector. */
class VectorOutputStream
{
private:
    std::vector<unsigned char>* v;

    size_t nPos;

    inline void resize_v(size_t nCount)
    {
        if (nPos > v->max_size() || nCount > v->max_size() - nPos)
            throw std::ios_base::failure("VectorOutputStream: size overflow");
        v->resize(std::max(v->size(), nPos + nCount));
    }

public:
    VectorOutputStream(std::vector<unsigned char>* vIn, std::ptrdiff_t nPosIn = -1) : v(vIn)
    {
        if (nPosIn < -1) throw std::ios_base::failure("VectorOutputStream: negative position");
        nPos = nPosIn == -1 ? v->size() : nPosIn;
    }

    template <typename T>
    VectorOutputStream& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }

    VectorOutputStream& write(std::span<const std::byte> src)
    {
        resize_v(src.size());
        if (!src.empty()) memcpy(v->data() + nPos, src.data(), src.size());
        nPos += src.size();
        return *this;
    }

    void skip_bytes(size_t nCount)
    {
        resize_v(nCount);
        nPos += nCount;
    }

    size_t pos() const { return nPos; }
};

/** Read-only stream for serialization from a vector */
class VectorInputStream
{
private:
    const std::vector<unsigned char>* v;

    size_t nReadPos;

public:
    VectorInputStream(const std::vector<unsigned char>* vIn) : v(vIn), nReadPos(0) {}

    template <typename T>
    VectorInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

    VectorInputStream& read(std::span<std::byte> dst)
    {
        // Read from the beginning of the buffer
        if (nReadPos > v->size() || dst.size() > v->size() - nReadPos)
            throw std::ios_base::failure("VectorInputStream::read(): end of data");
        if (!dst.empty()) memcpy(dst.data(), v->data() + nReadPos, dst.size());
        nReadPos += dst.size();
        return (*this);
    }

    void seek(size_t nReadPosIn)
    {
        if (nReadPosIn > v->size())
            throw std::ios_base::failure("VectorInputStream::seek(): end of data");
        nReadPos = nReadPosIn;
    }

    size_t pos() const { return nReadPos; }
};

#endif // BITCOIN_FIBRE_STREAMS_H
