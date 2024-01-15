#pragma once
#include <string>

namespace leaf {

	struct binary_object {
		virtual std::string to_bytestring() const = 0;

		virtual ~binary_object() = default;
	};
}
