/**
 * @file	Entry.cpp
 * @brief	Implementation of Entry struct
 * @author	Astatine387
 */

#include "Core/Entry.h"
#include <cstring>

size_t Entry::size() const {
    return sizeof(uint32_t) + site.size() + sizeof(uint32_t) + acc.size() + sizeof(uint32_t) + pw.getSize();
}

size_t Entry::ser(uint8_t *dst) const {
    size_t cur = 0;
    uint32_t dataLen;


    /* Write site */

    dataLen = static_cast<uint32_t>(site.size());

    memcpy(dst + cur, &dataLen, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    memcpy(dst + cur, site.data(), dataLen);
    cur += dataLen;


    /* Write account */

    dataLen = static_cast<uint32_t>(acc.size());

    memcpy(dst + cur, &dataLen, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    memcpy(dst + cur, acc.data(), dataLen);
    cur += dataLen;


    /* Write password */

    dataLen = static_cast<uint32_t>(pw.getSize());

    memcpy(dst + cur, &dataLen, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    memcpy(dst + cur, pw.getData(), dataLen);
    cur += dataLen;


    return cur;
}

size_t Entry::deser(const uint8_t *src, size_t srcLen) {
    size_t cur = 0;
    uint32_t dataLen;


    /* Read site */

    if (cur + sizeof(uint32_t) > srcLen) return 0;

    memcpy(&dataLen, src + cur, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    if (cur + dataLen > srcLen || dataLen > kMaxSiteLen) return 0;

    site.assign(reinterpret_cast<const char *>(src + cur), dataLen);
    cur += dataLen;


    /* Read account */

    if (cur + sizeof(uint32_t) > srcLen) return 0;

    memcpy(&dataLen, src + cur, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    if (cur + dataLen > srcLen || dataLen > kMaxAccLen) return 0;

    acc.assign(reinterpret_cast<const char *>(src + cur), dataLen);
    cur += dataLen;


    /* Read password */

    if (cur + sizeof(uint32_t) > srcLen) return 0;

    memcpy(&dataLen, src + cur, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    if (cur + dataLen > srcLen || dataLen > kMaxPWLen) return 0;

    if (pw.setData(reinterpret_cast<const char *>(src + cur), dataLen)) return 0;
    cur += dataLen;


    return cur;
}