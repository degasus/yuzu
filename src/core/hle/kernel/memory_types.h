// Copyright 2020 yuzu Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <array>

#include "common/common_types.h"

namespace Kernel {

constexpr std::size_t PageBits{12};
constexpr std::size_t PageSize{1 << PageBits};
#if defined(_WIN32)
constexpr std::size_t HostPageBits{16};
#else
constexpr std::size_t HostPageBits{12};
#endif

constexpr std::size_t HostPageSize{1 << HostPageBits};

using Page = std::array<u8, PageSize>;
using HostPage = std::array<u8, HostPageSize>;

} // namespace Kernel
