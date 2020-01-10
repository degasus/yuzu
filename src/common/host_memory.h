// Copyright 2019 yuzu Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <memory>
#include "common/common_types.h"

namespace Common {

/**
 * A low level linear memory buffer, which supports multiple mappings
 * Its purpose is to rebuild a given sparse memory layout, including mirrors.
 */
class HostMemory {
    friend class VirtualMemoryRegion;

public:
    HostMemory(std::string_view usage = "HostMemory");
    ~HostMemory();

    /**
     * Constructor with inlined memory allocation
     * This is identical to calling resize(bytes) on a default created object.
     */
    explicit HostMemory(size_t bytes, std::string_view usage = "HostMemory");

    /**
     * Copy constructors. They shall return a copy of the buffer without the mappings.
     * TODO: Implement them with COW if needed.
     */
    HostMemory(HostMemory& other) = delete;
    HostMemory& operator=(HostMemory& other) = delete;

    /**
     * Move constructors. They will move the buffer and the mappings to the new object.
     */
    HostMemory(HostMemory&& other);
    HostMemory& operator=(HostMemory&& other);

    /**
     * Expand of shrink the buffer
     * On expanding, it will be extended with (sparse) zeros.
     * On shrinking, overlapping mappings will be cleared.
     *
     * This call might fail if the system runs out of memory.
     */
    bool resize(size_t bytes);

    /**
     * Zeros a region of the buffer
     * Compared to memset, this method will try to generate sparse pages to save physical memory.
     *
     * @pre length + offset must not be larger than size
     */
    void clearRegion(size_t length, size_t offset);

    /**
     * Try to map a region of the buffer to a given pointer
     *
     * Length, offset and pointer must be page aligned (4k on linux, 64k on windows).
     *
     * @pre length + offset must not be larger than size
     * @return true of the mapping was successful
     */
    bool map(size_t length, size_t offset, u8* pointer);

    /**
     * Unmap (partial) region(s) of the buffer
     * This method unmaps all overlapping mappings of this buffer.
     *
     * Length and pointer must be page aligned (4k on linux, 64k on windows).
     *
     * @pre length + offset must not be larger than size
     * @return true if any mapping was cleared
     */
    bool unmap(size_t length, u8* pointer);

    /**
     * Query the current size of the buffer
     * @return the size of the buffer in bytes
     */
    size_t size() const;

    /**
     * Query the pointer of the internal storage
     * This pointer will be invalidated by the next resize call.
     * @return pointer to the begin of the internal storage
     */
    u8* data();
    const u8* data() const;

private:
    // Low level handler for the platform dependent memory routines
    class Impl;
    std::unique_ptr<Impl> impl;
    std::string usage;
};

class VirtualMemoryRegion {
public:
    static constexpr u8* invalid_base_pointer = nullptr;

    VirtualMemoryRegion(size_t size, u8* base_pointer_hint = invalid_base_pointer);
    ~VirtualMemoryRegion();

    VirtualMemoryRegion(VirtualMemoryRegion& other) = delete;
    VirtualMemoryRegion(VirtualMemoryRegion&& other) = delete;
    VirtualMemoryRegion& operator=(VirtualMemoryRegion& other) = delete;
    VirtualMemoryRegion& operator=(VirtualMemoryRegion&& other) = delete;

    u8* getBasePointer();
    const u8* getBasePointer() const;

    bool map(HostMemory& memory, size_t host_offset, size_t length, size_t virtual_offset);
    void unmap(size_t offset, size_t length);

    bool mprotect(size_t offset, size_t length, bool read, bool write);

private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Common
