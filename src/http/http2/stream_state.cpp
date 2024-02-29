#include "http2/frame.h"
#include "http2/state.h"
#include "internal/utils.h"
#include <iostream>

namespace leaf::network::http2 {

	stream_state::stream_state(const stream_id_t __id, ostream& __s, connection_state& context, const http::request& __req)
		: stream_id_(__id), state_(state_t::idle), connection_(context), out_(__s), request_(__req), window_bytes_(connection_.remote_config.init_window_size) {
		write_request_();
	}

	stream_state::stream_state(const stream_id_t __id, ostream& __s, connection_state& __c, http::http_fields __h)
		: stream_id_(__id), state_(state_t::remote_reserved), connection_(__c), out_(__s), window_bytes_(connection_.remote_config.init_window_size) {
		request_.headers = std::move(__h);
	}

	void stream_state::notify(http::http_fields __f, const bool __es) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed && state_ != state_t::remote_reserved)
			throw std::runtime_error{"unexpected HEADERS"};

		if (state_ == state_t::remote_reserved)
			state_ = state_t::local_half_closed;
		if (const auto __n = __f.extract(":status"))
			pending_response_.status = std::stol(__n.mapped());
		pending_response_.headers = std::move(__f);
		if (__es) {
			response_promise_.set_value(std::move(pending_response_));
			set_remote_closed_();
		}
	}

	void stream_state::notify(const byte_string_view __s, const bool __es) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed)
			throw std::runtime_error{"Unexpected DATA at closed/half-closed stream."};
		pending_response_.content += reinterpret_cast<const std::string_view&>(__s);
		if (__es) {
			response_promise_.set_value(std::move(pending_response_));
			set_remote_closed_();
		}
	}

	void stream_state::remote_reset(error_t err) {
		response_promise_.set_exception(std::make_exception_ptr(std::runtime_error(std::format("remote reset stream: {}", err))));
		state_ = state_t::closed;
	}

	void stream_state::increase_window(const std::uint32_t size) {
		window_bytes_ += size;
	}

	std::uint32_t stream_state::available_window() const {
		return std::min(connection_.remote_config.max_frame_size, window_bytes_);
	}

	bool stream_state::request_window(std::uint32_t __s) {
		if (__s < window_bytes_ && __s < connection_.remote_config.max_frame_size) {
			window_bytes_ -= __s;
			return true;
		}
		return false;
	}

	stream_id_t stream_state::stream_id() const {
		return stream_id_;
	}

	stream_state::state_t stream_state::state() const {
		return state_;
	}

	void stream_state::local_close() {
		if (state_ == state_t::remote_half_closed || state_ == state_t::open)
			write(data(stream_id_, true));
		set_local_closed_();
	}

	void stream_state::write(const stream_frame& __f) {
		std::cout << std::format("[HTTP/2] sending {}\n", static_cast<const basic_frame&>(__f));
		connection_.task_add(__f.generator(out_, *this));
	}

	void stream_state::set_local_closed_() {
		switch (state_) {
			case state_t::open:
				state_ = state_t::local_half_closed;
				break;
			case state_t::remote_half_closed:
				state_ = state_t::closed;
				break;
			default:
				break;
		}
	}

	void stream_state::set_remote_closed_() {
		switch (state_) {
			case state_t::open:
				state_ = state_t::remote_half_closed;
				break;
			case state_t::local_half_closed:
				state_ = state_t::closed;
				break;
			default:
				break;
		}
	}

	void stream_state::write_request_() {
		if (state_ != state_t::idle && state_ != state_t::local_reserved)
			throw std::runtime_error(std::format("stream {} is in use", stream_id_));

		state_ = state_t::open;

		auto& __h = request_.headers;
		__h.set(":path", request_.target.requesting_uri_string());
		__h.set(":method", request_.method);
		__h.set(":authority", request_.target.host);
		__h.set(":scheme", request_.target.scheme);

		headers __hf(stream_id_);
		__hf.end_stream = request_.content.empty();
		__hf.set_header(connection_.local_packer, __h);
		write(__hf);

		if (!request_.content.empty()) {
			data d_f(stream_id_);
			d_f.content = reinterpret_cast<const byte_string&>(request_.content);
			d_f.end_stream = true;
			write(d_f);
		}

		set_local_closed_();
	}
}
