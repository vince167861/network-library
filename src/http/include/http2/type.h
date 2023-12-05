#pragma once

#include <cstdint>
#include <iostream>

namespace leaf::network::http2 {


	enum class frame_type_t: uint8_t {
		data = 0x00, headers = 0x01, priority = 0x02, rst_stream = 0x03, settings = 0x04, push_promise = 0x05,
		ping = 0x06, go_away = 0x07, window_update = 0x08, continuation = 0x09
	};

	enum class error_t: uint32_t {
		no_error = 0x00, protocol_error = 0x01, internal_error = 0x02, flow_control_error = 0x03,
		settings_timeout = 0x04, stream_closed = 0x05, frame_size_error = 0x06, refused_stream = 0x07, cancel = 0x08,
		compression_error = 0x09, connect_error = 0x0a, enhance_your_calm = 0x0b, inadequate_security = 0x0c,
		http_1_1_required = 0x0d
	};

	std::ostream& operator<<(std::ostream&, error_t);

	enum class settings_t: uint16_t {
		header_table_size = 0x01, enable_push = 0x02, max_concurrent_stream = 0x03, initial_window_size = 0x04,
		max_frame_size = 0x05, max_header_list_size = 0x06
	};
}
