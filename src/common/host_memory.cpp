#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <bit>
#include <map>
#include <Windows.h>
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

class VirtualMemoryRegion::Impl {
public:
    Impl(size_t size, u8* base_pointer_hint) {
        /*
        base_pointer = static_cast<u8*>(
            mmap(base_pointer_hint, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        ASSERT_MSG(base_pointer == MAP_FAILED, "no virtual memory region could be allocated");
        if (base_pointer == MAP_FAILED)
            base_pointer = nullptr;
            */

        base_pointer =
            (u8*)VirtualAlloc(base_pointer_hint, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    u8* base_pointer{};
    std::map<u64, u16> page_mask;
    static constexpr u64 host_page_bits{16};
    static constexpr u64 host_page_size{1 << host_page_bits};
    static constexpr u64 host_page_mask{host_page_size - 1};

    static constexpr u64 guest_page_bits{12};
    static constexpr u64 guest_page_size{1 << guest_page_bits};
    static constexpr u64 guest_page_mask{guest_page_size - 1};

    static constexpr u64 sub_page_bits{host_page_bits - guest_page_bits};
    static constexpr u64 sub_page_count{1 << sub_page_bits};
    static constexpr u64 sub_page_mask{sub_page_count - 1};
};

class HostMemory::Impl {
public:
    Impl() {
        handle = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                   static_cast<DWORD>(0x1), static_cast<DWORD>(0), L"test");
        ASSERT(handle != nullptr);
    }

    ~Impl() {
        CloseHandle(handle);
        handle = 0;
    }

    bool resize(size_t bytes) {
        // LARGE_INTEGER bytes_large_integer{};
        // bytes_large_integer.QuadPart = bytes;
        // bool success = /* SetFilePointerEx(handle, bytes_large_integer, nullptr, FILE_BEGIN) &&*/
        //    SetEndOfFile(handle);
        // if (!success)
        //    return false;

        if (size) {
            bool success = UnmapViewOfFile(pointer);
            ASSERT(success);
        }

        if (bytes) {
            pointer = (u8*)MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, bytes);
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

    bool map(size_t length, size_t offset, u8* pointer_) {
        u8* ret = (u8*)MapViewOfFileEx(handle, FILE_MAP_ALL_ACCESS, 0, (DWORD)offset, (DWORD)length,
                                       pointer_);

        return ret == pointer_;
    }

    bool unmap([[maybe_unused]] size_t length, u8* pointer_) {
        return UnmapViewOfFile(pointer_);
    }

    size_t size = 0;
    u8* pointer = nullptr;
    HANDLE handle;
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
        impl = std::make_unique<Impl>(/*usage*/);

    total_memory_used -= size();

    bool success = impl->resize(bytes);

    total_memory_used += bytes;

    // printf("resizing HostMemory fd %d to %zx bytes, mapped to %p -> %d, total memory usage: %zd "
    //       "bytes\n",
    //       impl->fd, bytes, impl->pointer, success, total_memory_used);

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

    // printf("clearing HostMemory fd %d, %zx bytes at %zx offset\n", impl->fd, length, offset);
}

bool HostMemory::map(size_t length, size_t offset, u8* pointer) {
    assert(length + offset <= size());

    if (!length)
        return true;

    bool success = impl->map(length, offset, pointer);

    // printf("map HostMemory fd %d, %zx bytes at %zx offset to %p (base ptr %p) -> %d\n", impl->fd,
    //       length, offset, pointer, pointer - offset, success);

    return success;
}

bool HostMemory::unmap(size_t length, u8* pointer) {
    assert(length + offset <= size());

    if (!length)
        return true;

    bool success = impl->unmap(length, pointer);

    // printf("unmap HostMemory fd %d, %zx bytes from %p -> %d\n", impl->fd, length, pointer,
    // success);

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
    size_t final_offset = virtual_offset;
    size_t final_length = length;
#if defined(_WIN32)
    const u64 start_address = static_cast<u64>(virtual_offset);
    const u64 end_address = static_cast<u64>(virtual_offset + length);
    const u64 aligned_start_address = start_address & (~Impl::host_page_mask);
    const u64 aligned_end_address = end_address & (~Impl::host_page_mask);

    if (start_address != aligned_start_address) {
        const u64 page_base = start_address >> Impl::host_page_bits;
        const u64 pages_start = (start_address & Impl::host_page_mask) >> Impl::guest_page_bits;
        const u64 sub_pages = (~0U) ^ ((1 << pages_start) - 1);
        const [[maybe_unused]] auto [item, is_allocated] =
            impl->page_mask.try_emplace(page_base, static_cast<u16>(0U));
        auto& page_info = item->second;
        page_info |= static_cast<u16>(sub_pages);
        if (std::popcount(page_info) == static_cast<size_t>(Impl::sub_page_count)) {
            const size_t gained_length = static_cast<size_t>(start_address - aligned_start_address);
            final_offset = static_cast<size_t>(aligned_start_address);
            final_length += gained_length;
            impl->page_mask.erase(item);
        } else {
            const size_t lost_length =
                static_cast<size_t>((aligned_start_address + Impl::host_page_size) - start_address);
            final_offset += lost_length;
            final_length -= lost_length;
        }
    }
    if (final_length == 0) {
        return true;
    }
    if (end_address != aligned_end_address) {
        const u64 page_base = end_address >> Impl::host_page_bits;
        const u64 pages_end = (end_address & Impl::host_page_mask) >> Impl::guest_page_bits;
        const u64 sub_pages = (1ULL << pages_end) - 1ULL;
        const [[maybe_unused]] auto [item, is_allocated] =
            impl->page_mask.try_emplace(page_base, static_cast<u16>(Impl::sub_page_mask));
        auto& page_info = item->second;
        page_info |= static_cast<u16>(sub_pages);
        if (std::popcount(page_info) == static_cast<size_t>(Impl::sub_page_count)) {
            const size_t gained_length =
                static_cast<size_t>(Impl::host_page_size - (end_address & Impl::host_page_mask));
            final_length += gained_length;
            impl->page_mask.erase(item);
        } else {
            const size_t lost_length = static_cast<size_t>(end_address - aligned_end_address);
            final_length -= lost_length;
        }
    }
    if (final_length == 0) {
        return true;
    }
#endif
    return memory.map(final_length, host_offset, impl->base_pointer + final_offset);
}

void VirtualMemoryRegion::unmap(size_t offset, [[maybe_unused]] size_t length) {
#ifdef __linux__
    [[maybe_unused]] int ret = munmap(impl->base_pointer + offset, length);
#elif defined(_WIN32)
    const u64 start_address = static_cast<u64>(offset);
    const u64 end_address = static_cast<u64>(offset + length);
    const u64 aligned_start_address = start_address & (~Impl::host_page_mask);
    const u64 aligned_end_address = end_address & (~Impl::host_page_mask);
    const u64 page_base_start = start_address >> Impl::host_page_bits;
    const u64 page_base_end = end_address >> Impl::host_page_bits;

    auto it_start = impl->page_mask.lower_bound(page_base_start);
    const auto clean_up = [&] {
        auto it = it_start;
        while (it != impl->page_mask.end() && it->first < page_base_end) {
            it = impl->page_mask.erase(it);
        }
    };
    const auto unmap_mem = [&] {
        if (start_address != aligned_start_address) {
            offset = static_cast<size_t>(aligned_start_address + Impl::host_page_size);
        }
        VirtualFree(impl->base_pointer + offset, 0, MEM_RELEASE);
    };
    if (it_start == impl->page_mask.end() || it_start->first >= page_base_end) {
        unmap_mem();
        return;
    }
    if (it_start->first == page_base_start && start_address != aligned_start_address) {
        const u64 pages_start = (start_address & Impl::host_page_mask) >> Impl::guest_page_bits;
        const u64 not_sub_pages = ((1ULL << pages_start) - 1ULL);
        it_start->second &= static_cast<u16>(not_sub_pages);
        if (it_start->second != 0) {
            it_start = std::next(it_start);
        }
    }
    if (it_start == impl->page_mask.end() || it_start->first >= page_base_end) {
        unmap_mem();
        return;
    }
    if (end_address != aligned_end_address) {
        auto it_end = impl->page_mask.find(page_base_end);
        if (it_end == impl->page_mask.end()) {
            clean_up();
            unmap_mem();
            return;
        }
        const u64 pages_end = (end_address & Impl::host_page_mask) >> Impl::guest_page_bits;
        const u64 not_sub_pages = ~((1ULL << pages_end) - 1ULL);
        it_end->second &= static_cast<u16>(not_sub_pages);
        if (it_end->second == 0) {
            impl->page_mask.erase(it_end);
        }
    }
    clean_up();
    unmap_mem();
#endif
}

bool VirtualMemoryRegion::mprotect(size_t offset, size_t length, bool read, bool write) {
#ifdef __linux__
    int flags = 0;
    if (read)
        flags |= PROT_READ;
    if (write)
        flags |= PROT_WRITE;
    int ret = ::mprotect(impl->base_pointer + offset, length, flags);
    (void)ret;
#elif defined(_WIN32)
    DWORD new_flags{};
    DWORD old_flags{};

    if (read && write) {
        new_flags = PAGE_READWRITE;
    } else if (read && !write) {
        new_flags = PAGE_READONLY;
    }

    VirtualProtect(impl->base_pointer + offset, length, new_flags, &old_flags);
#endif
    return true;
}

} // namespace Common
