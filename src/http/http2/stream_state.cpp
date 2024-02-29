#include "http2/frame.h"
#include "http2/state.h"
#include "internal/utils.h"
#include <iostream>
#include <utility>

namespace leaf::network::http2 {

	stream_state::stream_state(const stream_id_t __id, ostream& __s, connection_state& context, http::request __req)
	: stream_id(__id), state_(state_t::open), connection_(context), out_(__s), request_(std::move(__req)), window_size_(connection_.remote_config.init_window_size) {
		auto& __h = request_.headers;
		__h.set(":path", request_.target.origin_form());
		__h.set(":method", request_.method);
		__h.set(":authority", request_.target.host);
		__h.set(":scheme", request_.target.scheme);

		headers _hf(stream_id);
		_hf.end_stream = request_.content.empty();
		_hf.set_header(connection_.local_packer, __h);
		write(_hf);
		if (!request_.content.empty()) {
			data _df(stream_id);
			_df.content = reinterpret_cast<const byte_string&>(request_.content);
			_df.end_stream = true;
			write(_df);
		}
		set_local_closed_();
	}

	stream_state::stream_state(const stream_id_t __id, ostream& __s, connection_state& __c, http::http_fields __h)
		: stream_id(__id), state_(state_t::remote_reserved), connection_(__c), out_(__s), window_size_(connection_.remote_config.init_window_size) {
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

	void stream_state::remote_reset(const error_t err) {
		response_promise_.set_exception(std::make_exception_ptr(std::runtime_error(std::format("remote reset stream: {}", err))));
		state_ = state_t::closed;
	}

	void stream_state::increase_window(const std::uint32_t size) {
		window_size_ += size;
	}

	std::size_t stream_state::available_window() const {
		return std::min(std::min<std::size_t>(connection_.remote_config.max_frame_size, window_size_), connection_.remote_window_size);
	}

	bool stream_state::request_window(const std::size_t _s) {
		if (_s > window_size_ && _s > connection_.remote_window_size && _s > connection_.remote_config.max_frame_size)
			return false;
		window_size_ -= _s;
		return true;
	}

	stream_state::state_t stream_state::state() const {
		return state_;
	}

	void stream_state::local_close() {
		if (state_ == state_t::remote_half_closed || state_ == state_t::open)
			write(data(stream_id, true));
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

}
