#pragma once

#include <string>
#include <bit>

namespace leaf {

	struct binary_object {

		virtual std::string to_bytestring(std::endian = std::endian::big) const = 0;

		virtual ~binary_object() = default;
	};
}
