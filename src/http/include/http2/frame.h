#pragma once

#include "byte_stream.h"
#include "http/message.h"
#include "http2/type.h"
#include "http2/header_packer.h"

#include <cstdint>
#include <format>
#include <string>
#include <list>
#include <memory>
#include <optional>
#include <variant>


namespace leaf::network::http2 {


	/**
	 * \brief A *potentially* stream-associated frame.
	 */
	class stream_frame {
	public:
		stream_id_t stream_id;

		explicit stream_frame(uint32_t stream_id);
	};


	class headers_based_frame: public stream_frame {
		bool conclude_ = false;

	public:
		byte_string pending_fragments;

		explicit headers_based_frame(uint32_t stream_id);

		void add_fragment(byte_string_view, bool last_frame);

		http::http_fields get_headers(header_packer& decoder) const;

		void set_header(header_packer& encoder, const http::http_fields&);
	};


	class data_frame final: public stream_frame {
	public:
		bool end_stream: 1;

		std::optional<uint8_t> padding;

		byte_string data;

		explicit data_frame(uint32_t stream_id, bool end_stream = false);
	};


	class headers_frame final: public headers_based_frame {
	public:
		struct priority_t {
			bool exclusive: 1;
			uint32_t dependency;
			uint8_t weight;
		};

		bool end_stream: 1 = false;

		std::optional<priority_t> priority;

		std::optional<uint8_t> padding;

		explicit headers_frame(stream_id_t);
	};


	class priority_frame final: public stream_frame {
	public:
		bool exclusive: 1 = false;

		uint32_t stream_dependence = 0;

		uint8_t weight = 0;

		explicit priority_frame(stream_id_t);
	};


	class rst_stream final: public stream_frame {
	public:
		error_t error_code = error_t::no_error;

		explicit rst_stream(stream_id_t);
	};


	class settings_frame final {
	public:
		bool ack: 1;

		setting_values_t values;

		settings_frame();

		explicit settings_frame(setting_values_t);
	};


	class push_promise_frame final: public headers_based_frame {
	public:
		uint32_t promised_stream_id;

		explicit push_promise_frame(stream_id_t);
	};


	class ping_frame final {
	public:
		bool ack: 1;

		uint64_t data;
	};


	class go_away final {
	public:
		uint32_t last_stream_id;

		error_t error_code;

		std::string additional_data;

		go_away() = default;

		go_away(uint32_t last_stream_id, error_t, std::string_view additional_data = "");
	};


	class window_update_frame final: public stream_frame {
	public:
		uint32_t window_size_increment;

		explicit window_update_frame(uint32_t stream_id);
	};


	using frame = std::variant<data_frame, headers_frame, priority_frame, rst_stream, settings_frame,
	push_promise_frame, ping_frame, go_away, window_update_frame>;

	frame parse_frame(stream&);
}


template<>
struct std::formatter<leaf::network::http2::frame> {

	std::format_parse_context::iterator
	constexpr parse(const std::format_parse_context& context) {
		return context.begin();
	}

	format_context::iterator
	format(const leaf::network::http2::frame& f, format_context& context) const;
};
