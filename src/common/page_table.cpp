// Copyright 2019 yuzu Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/page_table.h"

namespace Common {

PageTable::PageTable(std::size_t page_size_in_bits) : page_size_in_bits{page_size_in_bits} {}

PageTable::~PageTable() {
    FreeTables();
}

void PageTable::Resize(std::size_t address_space_width_in_bits) {
    FreeTables();

    size = 1ULL << (address_space_width_in_bits - page_size_in_bits);

    pointers = new u8*[size];
    attributes = new PageType[size];
    backing_addr = new u64[size];

    Clear();
}

void PageTable::Clear() {
    special_regions.clear();

    std::fill(pointers, pointers + size, nullptr);
    std::fill(attributes, attributes + size, Common::PageType::Unmapped);
    std::fill(backing_addr, backing_addr + size, 0);
}

void PageTable::FreeTables() {
    delete [] pointers;
    delete [] attributes;
    delete [] backing_addr;

    pointers = nullptr;
    attributes = nullptr;
    backing_addr = nullptr;

    size = 0;
}

} // namespace Common
