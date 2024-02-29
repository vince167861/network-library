#pragma once
#include "byte_stream.h"
#include "http/message.h"
#include "http2/type.h"
#include "http2/header_packer.h"
#include <variant>
#include <expected>
#include <coroutine>


namespace leaf::network::http2 {

	struct frame_generator_promise {

		std::exception_ptr exception;

		void return_void() {}

		auto get_return_object() {
			return std::coroutine_handle<frame_generator_promise>::from_promise(*this);
		}

		std::suspend_never initial_suspend() {
			return {};
		}

		std::suspend_always final_suspend() noexcept {
			return {};
		}

		void unhandled_exception() {
			exception = std::current_exception();
		}
	};

	struct frame_generator: std::coroutine_handle<frame_generator_promise> {

		using promise_type = frame_generator_promise;

		frame_generator(std::coroutine_handle<promise_type> handle)
			: std::coroutine_handle<frame_generator_promise>(std::move(handle)) {
		}

		bool done() const {
			if (const auto& __exp = promise().exception)
				std::rethrow_exception(__exp);
			return std::coroutine_handle<frame_generator_promise>::done();
		}
	};


	struct basic_frame {

		virtual std::format_context::iterator format(std::format_context::iterator) const = 0;

		virtual ~basic_frame() = default;
	};


	struct connection_state;

	struct connection_frame: virtual basic_frame {

		// second parameter is reserved for future potential uses
		virtual void generator(ostream&, connection_state&) const = 0;
	};


	struct stream_state;

	/// \brief A *potentially* stream-associated frame.
	struct stream_frame: virtual basic_frame {

		stream_id_t stream_id;

		explicit stream_frame(stream_id_t);

		virtual frame_generator generator(ostream&, stream_state&) const = 0;
	};


	struct headers_holder: stream_frame {

		byte_string fragments;

		explicit headers_holder(stream_id_t);

		void add_fragment(byte_string_view, bool last_frame);

		http::http_fields get_headers(header_packer& decoder) const;

		void set_header(header_packer& encoder, const http::http_fields&);

	private:
		bool conclude_ = false;
	};


	struct data final: stream_frame {

		bool end_stream: 1;

		std::optional<uint8_t> padding;

		byte_string content;

		explicit data(stream_id_t, bool end_stream = false);

		frame_generator generator(ostream&, stream_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct headers final: headers_holder {

		bool end_stream;

		std::optional<priority_t> priority;

		std::optional<uint8_t> padding;

		explicit headers(stream_id_t, bool end_stream = false);

		frame_generator generator(ostream&, stream_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct priority final: stream_frame {

		priority_t values;

		explicit priority(stream_id_t);

		frame_generator generator(ostream&, stream_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct rst_stream final: stream_frame {

		error_t error_code = error_t::no_error;

		explicit rst_stream(stream_id_t);

		frame_generator generator(ostream&, stream_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct settings final: connection_frame {

		bool ack: 1;

		setting_values_t values;

		settings();

		settings(setting_values_t);

		void generator(ostream&, connection_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct push_promise final: headers_holder {

		stream_id_t promised_stream_id;

		explicit push_promise(stream_id_t);

		virtual frame_generator generator(ostream&, stream_state&) const;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct ping final: connection_frame {

		bool ack: 1;

		uint64_t data;

		ping(const bool __a, const std::uint64_t __d)
			: ack(__a), data(__d) {
		}

		void generator(ostream&, connection_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct go_away final: connection_frame {

		uint32_t last_stream_id;

		error_t error_code;

		std::string additional_data;

		go_away() = default;

		go_away(stream_id_t last, error_t, std::string_view additional_data = "");

		void generator(ostream&, connection_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};


	struct window_update final: virtual stream_frame, virtual connection_frame {

		uint32_t window_size_increment;

		explicit window_update(stream_id_t);

		void generator(ostream&, connection_state&) const override;

		frame_generator generator(ostream&, stream_state&) const override;

		std::format_context::iterator format(std::format_context::iterator) const override;
	};

	std::expected<std::pair<frame_type_t, std::unique_ptr<basic_frame>>, frame_parsing_error>
	parse_frame(istream&);
}


template<>
struct std::formatter<leaf::network::http2::basic_frame> {

	auto constexpr parse(const std::format_parse_context& context) {
		return context.begin();
	}

	auto format(const leaf::network::http2::basic_frame& __f, format_context& ctx) const {
		return __f.format(ctx.out());
	}
};
