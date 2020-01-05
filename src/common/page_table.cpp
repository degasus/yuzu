// Copyright 2019 yuzu Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#ifdef __linux__
#include <sys/mman.h>
#endif

#include "common/page_table.h"

namespace Common {

PageTable::PageTable(std::size_t page_size_in_bits) : page_size_in_bits{page_size_in_bits} {}

PageTable::~PageTable() {
    FreeTables();
}

void PageTable::Resize(std::size_t address_space_width_in_bits) {
    FreeTables();

    size = 1ULL << (address_space_width_in_bits - page_size_in_bits);

    AllocTables();
}

void PageTable::Clear() {
    special_regions.clear();

#ifdef __linux__
    FreeTables();
    AllocTables();
#else
    std::fill(pointers, pointers + size, nullptr);
    std::fill(attributes, attributes + size, Common::PageType::Unmapped);
    std::fill(backing_addr, backing_addr + size, 0);
#endif
}

void PageTable::AllocTables() {
#ifdef __linux__
    pointers = reinterpret_cast<u8**>(mmap(NULL, size * sizeof(u8*), PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
    attributes = reinterpret_cast<PageType*>(mmap(NULL, size * sizeof(PageType), PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
    backing_addr = reinterpret_cast<u64*>(mmap(NULL, size * sizeof(u64), PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
#else
    pointers = new u8*[size];
    attributes = new PageType[size];
    backing_addr = new u64[size];

    Clear();
#endif
}

void PageTable::FreeTables() {
#ifdef __linux__
    munmap(pointers, size * sizeof(u8*));
    munmap(attributes, size * sizeof(PageType));
    munmap(backing_addr, size * sizeof(u64));
#else
    delete [] pointers;
    delete [] attributes;
    delete [] backing_addr;
#endif

    pointers = nullptr;
    attributes = nullptr;
    backing_addr = nullptr;

    size = 0;
}

} // namespace Common
