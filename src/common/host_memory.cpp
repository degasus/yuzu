#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <fileapi.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#pragma comment(lib, "Kernel32.lib")
#endif

#include <cassert>
#include <cstring>
#include "common/assert.h"
#include "common/host_memory.h"

static size_t total_memory_used = 0;

namespace Common {

#ifdef __linux__

class HostMemory::Impl {
public:
    Impl(std::string_view usage) : fd(memfd_create(std::string(usage).c_str(), 0)) {}

    ~Impl() {
        close(fd);
    }

    bool resize(size_t bytes) {
        int err = ftruncate(fd, bytes);
        if (err != 0)
            return false;

        if (size) {
            err = munmap(pointer, size);
            assert(err == 0);
        }

        if (bytes) {
            pointer =
                static_cast<u8*>(mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
            if (pointer == MAP_FAILED) {
                pointer = nullptr;
                return false;
            }
        } else {
            pointer = nullptr;
        }

        size = bytes;

        return true;
    }

    void clearRegion(size_t length, size_t offset) {
        int err = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, length);
        (void)err;
        assert(err == 0);
    }

    bool map(size_t length, size_t offset, u8* pointer) {
        void* ret =
            mmap(pointer, length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, offset);

        return ret != MAP_FAILED && ret == pointer;
    }

    bool unmap(size_t length, u8* pointer) {
        int ret = munmap(pointer, length);

        return ret == 0;
    }

    size_t size = 0;
    u8* pointer = nullptr;
    const int fd;
};

class VirtualMemoryRegion::Impl {
public:
    Impl(size_t size, u8* base_pointer_hint) {
        base_pointer = static_cast<u8*>(
            mmap(base_pointer_hint, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        ASSERT_MSG(base_pointer == MAP_FAILED, "no virtual memory region could be allocated");
        if (base_pointer == MAP_FAILED)
            base_pointer = nullptr;
    }

    u8* base_pointer{};
};

#elif defined(_WIN32)

class HostMemory::Impl {
    Impl() {
        handle = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0, nullptr);
        assert(handle != nullptr);
    }

    ~Impl() {
        CloseHandle(handle);
        handle = 0;
    }

    bool resize(size_t bytes) {
        bool success = SetFilePointerEx(handle, bytes, nullptr, FILE_BEGIN) && SetEndOfFile(handle);
        if (!success)
            return false;

        if (size) {
            success = UnmapViewOfFile(pointer);
            assert(success);
        }

        if (bytes) {
            pointer = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, bytes);
        } else {
            pointer = nullptr;
        }

        size = bytes;

        return true;
    }

    void clearRegion(size_t length, size_t offset) {
        // TODO: implement me
        std::memset(pointer + offset, 0, length);
    }

    bool map(size_t length, size_t offset, u8* pointer) {
        u8* ret = MapViewOfFileEx(handle, FILE_MAP_ALL_ACCESS, 0, offset, length, pointer);

        return ret == pointer;
    }

    bool unmap(size_t length, u8* pointer) {
        return UnmapViewOfFile(pointer);
    }

    size_t size = 0;
    u8* pointer = nullptr;
    HANDLE handle;
};

class VirtualMemoryRegion::Impl {
    // TODO: big todo...
};

#else

#error Please implement the host memory for your platform

#endif

HostMemory::HostMemory(std::string_view usage) : usage(usage) {}

HostMemory::~HostMemory() {
    // Free all memory
    resize(0);
}

HostMemory::HostMemory(size_t bytes, std::string_view usage) : HostMemory(usage) {
    resize(bytes);
}

HostMemory::HostMemory(HostMemory&& other) : HostMemory(std::string_view{}) {
    impl.swap(other.impl);
    usage.swap(other.usage);
}

HostMemory& HostMemory::operator=(HostMemory&& other) {
    // Free all memory
    resize(0);

    impl.swap(other.impl);

    return *this;
}

bool HostMemory::resize(size_t bytes) {
    // size does not change, so nothing to do
    if (bytes == size())
        return true;

    // buffer was empty, so create the implementation
    if (!impl)
        impl = std::make_unique<Impl>(usage);

    total_memory_used -= size();

    bool success = impl->resize(bytes);

    total_memory_used += bytes;

    printf("resizing HostMemory fd %d to %zx bytes, mapped to %p -> %d, total memory usage: %zd "
           "bytes\n",
           impl->fd, bytes, impl->pointer, success, total_memory_used);

    // buffer shall be of zero bytes, so free it
    if (!bytes)
        impl.reset();

    return success;
}

void HostMemory::clearRegion(size_t length, size_t offset) {
    assert(length + offset <= size());

    if (!length)
        return;

    impl->clearRegion(length, offset);

    printf("clearing HostMemory fd %d, %zx bytes at %zx offset\n", impl->fd, length, offset);
}

bool HostMemory::map(size_t length, size_t offset, u8* pointer) {
    assert(length + offset <= size());

    if (!length)
        return true;

    bool success = impl->map(length, offset, pointer);

    printf("map HostMemory fd %d, %zx bytes at %zx offset to %p (base ptr %p) -> %d\n", impl->fd,
           length, offset, pointer, pointer - offset, success);

    return success;
}

bool HostMemory::unmap(size_t length, u8* pointer) {
    assert(length + offset <= size());

    if (!length)
        return true;

    bool success = impl->unmap(length, pointer);

    printf("unmap HostMemory fd %d, %zx bytes from %p -> %d\n", impl->fd, length, pointer, success);

    return success;
}

size_t HostMemory::size() const {
    if (!impl)
        return 0;

    return impl->size;
}

u8* HostMemory::data() {
    if (!impl)
        return nullptr;

    return impl->pointer;
}

const u8* HostMemory::data() const {
    if (!impl)
        return nullptr;

    return impl->pointer;
}

VirtualMemoryRegion::VirtualMemoryRegion(size_t size, u8* base_pointer_hint)
    : impl{std::make_unique<Impl>(size, base_pointer_hint)} {}

VirtualMemoryRegion::~VirtualMemoryRegion() {}

u8* VirtualMemoryRegion::getBasePointer() {
    return impl->base_pointer;
}

const u8* VirtualMemoryRegion::getBasePointer() const {
    return impl->base_pointer;
}

bool VirtualMemoryRegion::map(HostMemory& memory, size_t host_offset, size_t length,
                              size_t virtual_offset) {
    return memory.map(length, host_offset, impl->base_pointer + virtual_offset);
}

void VirtualMemoryRegion::unmap(size_t offset, size_t length) {
    int ret = munmap(impl->base_pointer + offset, length);
    (void)ret;
}

bool VirtualMemoryRegion::mprotect(size_t offset, size_t length, bool read, bool write) {
    int flags = 0;
    if (read)
        flags |= PROT_READ;
    if (write)
        flags |= PROT_WRITE;
    int ret = ::mprotect(impl->base_pointer + offset, length, flags);
    (void)ret;
    return true;
}

} // namespace Common
