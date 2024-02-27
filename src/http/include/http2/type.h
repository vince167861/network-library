#pragma once
#include <cstdint>
#include <list>
#include <format>

namespace leaf::network::http2 {

	using stream_id_t = std::uint32_t;


	enum class frame_type_t: std::uint8_t {
		data = 0x00, headers = 0x01, priority = 0x02, rst_stream = 0x03, settings = 0x04, push_promise = 0x05,
		ping = 0x06, go_away = 0x07, window_update = 0x08, continuation = 0x09
	};


	enum class error_t: std::uint32_t {
		no_error = 0x00, protocol_error = 0x01, internal_error = 0x02, flow_control_error = 0x03,
		settings_timeout = 0x04, stream_closed = 0x05, frame_size_error = 0x06, refused_stream = 0x07, cancel = 0x08,
		compression_error = 0x09, connect_error = 0x0a, enhance_your_calm = 0x0b, inadequate_security = 0x0c,
		http_1_1_required = 0x0d
	};


	enum class settings_t: uint16_t {
		header_table_size = 0x01, enable_push = 0x02, max_concurrent_stream = 0x03, initial_window_size = 0x04,
		max_frame_size = 0x05, max_header_list_size = 0x06
	};


	using setting_values_t = std::list<std::pair<settings_t, std::uint32_t>>;


	struct endpoint_state_t {
		uint32_t max_concurrent_streams = 100;
		stream_id_t last_open_stream = 0;
		std::uint32_t max_frame_size: 24 = 16384;
		uint32_t header_table_size = 4096;
		uint32_t init_window_size = 65535;
		uint32_t current_window_bytes = init_window_size;
		bool enable_push = true;
	};


	struct connection_error: std::runtime_error {

		error_t type;

		connection_error(const error_t __t, std::string __d = "")
			: std::runtime_error(std::move(__d)), type(__t) {
		}
	};


	union frame_flags {
		struct {
			bool ack: 1;
		};
		struct {
			bool end_stream: 1;
			bool: 1;
			bool end_headers: 1;
			bool padded: 1;
			bool: 1;
			bool has_priority: 1;
		};
		std::uint8_t value: 8 = 0;
	};

	struct priority_t {
		bool exclusive: 1;
		uint32_t dependency: 31;
		uint8_t weight;
	};


	enum class frame_parsing_error {
		unspecified, unknown_frame
	};
}

template<>
struct std::formatter<leaf::network::http2::error_t> {

	constexpr format_parse_context::iterator parse(const format_parse_context& context) {
		return context.begin();
	}

	format_context::iterator format(const leaf::network::http2::error_t&, format_context&) const;
};

template<>
struct std::formatter<leaf::network::http2::settings_t> {

	constexpr format_parse_context::iterator parse(const format_parse_context& context) {
		return context.begin();
	}

	format_context::iterator format(const leaf::network::http2::settings_t&, format_context&) const;
};
