// Copyright 2019 yuzu Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common/alignment.h"

namespace Kernel {

// This encapsulation serves 2 purposes:
// - First, to encapsulate host physical memory under a single type and set an
// standard for managing it.
// - Second to ensure all host backing memory used is aligned to 256 bytes due
// to strict alignment restrictions on GPU memory.

//using PhysicalMemory = std::vector<u8, Common::AlignmentAllocator<u8, 256>>;

class PhysicalMemory {
public:
    PhysicalMemory() = default;

    PhysicalMemory(size_t bytes) : PhysicalMemory() {
        resize(bytes);
    }

    PhysicalMemory(PhysicalMemory&& other) : PhysicalMemory() {
        // *this = other;

        current_size = other.current_size;
        pointer = other.pointer;
        fd = other.fd;

        other.current_size = 0;
        other.pointer = nullptr;
        other.fd = 0;
    }

    PhysicalMemory& operator= (PhysicalMemory&& other) {
        // Free local memory
        resize(0);

        current_size = other.current_size;
        pointer = other.pointer;
        fd = other.fd;

        other.current_size = 0;
        other.pointer = nullptr;
        other.fd = 0;

        return *this;
    }

    ~PhysicalMemory() {
        // Free local memory
        resize(0);
    }

    void resize(size_t bytes) {
        if (bytes == current_size)
            return;

        int ret2 = 0;
        if (current_size) {
            ret2 = munmap(pointer, current_size);
        } else {
            fd = memfd_create("PhysicalMemory", 0);
        }

        int ret = ftruncate(fd, bytes);
        current_size = bytes;

        if (current_size) {
            pointer = (u8*)mmap(nullptr, current_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        } else {
            close(fd);
            pointer = nullptr;
            fd = 0;
        }

        printf("resizing PhysicalMemory fd %d to %zx bytes, mapped to %p -> %d, %d\n", fd, bytes, pointer, ret, ret2);
    }

    void discard(size_t len, size_t offset) {
        int err = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, len);
        if (0 != err) {
            /* handle error */
        }
        printf("discarding PhysicalMemory fd %d, %zx bytes at %zx offset -> %d\n", fd, len, offset, err);

    }

    size_t size() const {
        return current_size;
    }

    u8* data() const {
        return pointer;
    }

    bool map(size_t len, size_t offset, u8* dest_pointer) {

        u8* ret = (u8*)mmap(dest_pointer, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, offset);

        printf("map PhysicalMemory fd %d, %zx bytes at %zx offset to %p -> %p\n", fd, len, offset, dest_pointer, ret);

        return ret == dest_pointer;
    }

    size_t current_size = 0;
    u8* pointer = nullptr;
    int fd = 0;
};

} // namespace Kernel
