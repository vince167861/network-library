#include "http2/type.h"

#include "macro.h"

namespace leaf::network::http2 {

	std::ostream& operator<<(std::ostream& s, error_t t) {
		switch (t) {
			build_enum_item(s, error_t, no_error);
			build_enum_item(s, error_t, protocol_error);
			build_enum_item(s, error_t, internal_error);
			build_enum_item(s, error_t, flow_control_error);
			build_enum_item(s, error_t, settings_timeout);
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << static_cast<uint32_t>(t) << ')';
		return s;
	}
}
