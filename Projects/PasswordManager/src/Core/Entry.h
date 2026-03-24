/**
 * @file	Entry.h
 * @brief	Password entry
 * @author	Astatine387
 */

#pragma once

#include "Common/constants.h"
#include "Utils/Password.h"
#include <cstdint>
#include <cstddef>
#include <string>

/**
 * @struct     Entry
 * @brief      Password entry
 */
struct Entry {
    std::string site;
    std::string acc;
    Password pw;

    /**
     * @brief   Calculate serialized size in bytes
     * @return  Serialized size in bytes
     */
    size_t size() const;

    /**
     * @brief   Serialize entry to buffer
     * @param   dst     Destination buffer (must have enough space)
     * @return  Number of bytes written
     */
    size_t ser(uint8_t *dst) const;

    /**
     * @brief   Deserialize entry from buffer
     * @param   src         Source buffer
     * @param   srcLen      Source buffer size
     * @return  Number of bytes read on success, 0 on failure
     */
    size_t deser(const uint8_t *src, size_t srcLen);
};

/**
 * @struct  EntryCmp
 * @brief   Comparator for Entry set ordering
 */
struct EntryCmp {
    bool operator()(const Entry &a, const Entry &b) const {
        if (a.site != b.site) return a.site < b.site;
        return a.acc < b.acc;
    }
};