#include "http2/stream.h"

#include "utils.h"


namespace leaf::network::http2 {

	const std::runtime_error
	stream_unavailable{"This stream is reserved by remote or used by another request."};

	stream_handler::stream_handler(const stream_id_t stream_id, context& context, const state_t state)
		: state_(state), context_(context), stream_id_(stream_id),
			window_bytes_(context_.remote_config.init_window_size) {
	}

	task<void> stream_handler::write_to_(stream& s, const frame& frame) {
		if (std::holds_alternative<headers_frame>(frame)) {
			auto& casted = std::get<headers_frame>(frame);
			byte_string_view fragments{casted.pending_fragments};
			for (bool first_frame = true; !fragments.empty(); first_frame = false) {
				auto fragment = fragments.substr(0, window_bytes_);
				fragments.remove_prefix(fragment.size());
				write(std::endian::big, s, fragment.size(), 3);
				write(std::endian::big, s, first_frame ? frame_type_t::headers : frame_type_t::continuation);
				write(std::endian::big, s, (fragments.empty() ? 1 << 2 : 0) |
					(first_frame ? (casted.priority ? 1 << 5 : 0) | (casted.padding ? 1 << 3 : 0) | casted.end_stream : 0), 1);
				write(std::endian::big, s, stream_id_);
				if (casted.priority) {
					const auto& [exclusive, dependency, weight] = casted.priority.value();
					write(std::endian::big, s, exclusive << 31 | dependency, 4);
					write(std::endian::big, s, weight);
				}
				s.write(fragment);
			}
			co_return;
		}
		if (std::holds_alternative<data_frame>(frame)) {
			const auto casted = std::get<data_frame>(frame);
			byte_string_view fragments{casted.data};
			while (!fragments.empty()) {
				if (const auto available = get_available_window()) {
					auto fragment = fragments.substr(available);
					fragments.remove_prefix(fragment.size());
					write(std::endian::big, s, fragment.length(), 3);
					write(std::endian::big, s, frame_type_t::data);
					write(std::endian::big, s, casted.end_stream && fragments.empty() ? 1 : 0, 1);
					write(std::endian::big, s, stream_id_);
					s.write(fragments);
				}
				else
					co_await std::suspend_always{};
			}
			co_return;
		}
		if (std::holds_alternative<rst_stream>(frame)) {
			auto& casted = std::get<rst_stream>(frame);
			write(std::endian::big, s, 4, 3);
			write(std::endian::big, s, frame_type_t::rst_stream);
			write(std::endian::big, s, 0, 1);
			write(std::endian::big, s, stream_id_);
			write(std::endian::big, s, casted.error_code);
			co_return;
		}
		if (std::holds_alternative<priority_frame>(frame)) {
			auto& casted = std::get<priority_frame>(frame);
			write(std::endian::big, s, 5, 3);
			write(std::endian::big, s, frame_type_t::priority);
			write(std::endian::big, s, 0, 1);
			write(std::endian::big, s, stream_id_);
			write(std::endian::big, s, casted.stream_dependence | (casted.exclusive ? 1 << 31 : 0), 4);
			write(std::endian::big, s, casted.weight);
			co_return;
		}
		if (std::holds_alternative<push_promise_frame>(frame)) {
			auto& casted = std::get<push_promise_frame>(frame);
			byte_string_view fragments{casted.pending_fragments};
			for (bool first_frame = true; !fragments.empty(); first_frame = false) {
				auto fragment = fragments.substr(0, window_bytes_);
				fragments.remove_prefix(fragment.size());
				write(std::endian::big, s, fragment.size(), 3);
				write(std::endian::big, s, first_frame ? frame_type_t::push_promise : frame_type_t::continuation);
				write(std::endian::big, s, fragments.empty() ? 1 << 2 : 0, 1);
				write(std::endian::big, s, stream_id_);
				write(std::endian::big, s, casted.promised_stream_id);
				s.write(fragment);
			}
			co_return;
		}
		throw std::runtime_error("Unimplemented or invalid frame.");
	}

	void stream_handler::write_request_to_(stream& stream) {
		if (state_ != state_t::idle && state_ != state_t::local_reserved)
			throw std::runtime_error{std::format("stream {} is in use", stream_id_)};

		state_ = state_t::open;

		auto& headers = request_.headers;
		headers.set(":path", request_.request_url.requesting_uri_string());
		headers.set(":method", request_.method);
		headers.set(":authority", request_.request_url.host);
		headers.set(":scheme", request_.request_url.scheme);

		headers_frame h_f{stream_id_};
		h_f.end_stream = request_.body.empty();
		h_f.set_header(context_.local_packer, headers);
		context_.add_task(write_to_(stream, std::move(h_f)));

		if (!request_.body.empty()) {
			data_frame d_f{stream_id_};
			d_f.data = reinterpret_cast<const byte_string&>(request_.body);
			d_f.end_stream = true;
			context_.add_task(write_to_(stream, d_f));
		}

		set_local_closed_();
	}

	void stream_handler::increase_window(const std::uint32_t size) {
		window_bytes_ += size;
	}

	std::uint32_t stream_handler::get_available_window() const {
		return std::min(context_.remote_config.max_frame_size, window_bytes_);
	}

	stream_id_t stream_handler::stream_id() const {
		return stream_id_;
	}

	stream_handler::state_t stream_handler::state() const {
		return state_;
	}

	void stream_handler::write_close_to_(stream& s) {
		if (state_ == state_t::remote_half_closed || state_ == state_t::open)
			context_.add_task(write_to_(s, data_frame{stream_id_, true}));
		set_local_closed_();
	}

	void stream_handler::set_local_closed_() {
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

	void stream_handler::set_remote_closed_() {
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

	response_handler::response_handler(stream& stream, context& context, const http::request& request)
			: stream_handler(context.next_local_stream_id(), context, stream_handler::state_t::idle) {
		request_ = request;
		write_request_to_(stream);
	}

	response_handler::response_handler(stream_id_t promised, http::http_fields headers, context& context)
			: stream_handler(promised, context, stream_handler::state_t::remote_reserved) {
		const auto next = context_.next_remote_stream_id();
		if (next != promised)
			throw std::runtime_error{"invalid promised stream identifier."};
		request_.headers = std::move(headers);
	}

	void response_handler::notify(const http::http_fields& headers, const bool end_stream) {
		if (state_ != state_t::open && state_ != stream_handler::state_t::local_half_closed && state_ != stream_handler::state_t::remote_reserved)
			throw std::runtime_error{"unexpected HEADER"};

		if (state_ == stream_handler::state_t::remote_reserved)
			state_ = stream_handler::state_t::local_half_closed;
		response_.headers = headers;
		if (auto status_node = response_.headers.extract(":status"))
			response_.status = std::stol(status_node.mapped());
		if (end_stream) {
			pending_promise_.set_value(response_);
			set_remote_closed_();
		}
	}

	void response_handler::notify(const byte_string_view data, bool end_stream) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed)
			throw std::runtime_error{"Unexpected DATA at closed/half-closed stream."};

		response_.body += reinterpret_cast<const std::string_view&>(data);
		if (end_stream) {
			pending_promise_.set_value(response_);
			set_remote_closed_();
		}
	}

	void response_handler::reserve(stream_id_t promised, http::http_fields headers) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed)
			throw std::runtime_error{"unexpected PUSH_PROMISE"};

		auto promised_stream = std::make_unique<response_handler>(promised, std::move(headers), context_);
		promised_stream_.emplace_back(*promised_stream);
		context_.register_handler(std::move(promised_stream));
	}

	void response_handler::reset() {
		pending_promise_.set_exception(std::make_exception_ptr(
			std::runtime_error{"Stream reset by peer (RST_STREAM)."}));
		state_ = state_t::closed;
	}

	std::future<http::response> response_handler::get_future() {
		return pending_promise_.get_future();
	}

	event_stream_handler::event_stream_handler(context& context, const http::request& request)
		: stream_handler(context.next_local_stream_id(), context, stream_handler::state_t::idle) {
		request_ = request;
		request_.headers.set("content-type", "text/event-stream");
	}

	http::event_source event_stream_handler::get_event_source(stream& s) {
		write_request_to_(s);
		while (state_ == stream_handler::state_t::open || state_ == stream_handler::state_t::local_half_closed) {
			if (buffer_.empty())
				co_await std::suspend_always{};
			else {
				auto event_data = http::http_fields::from_event_stream(s);
				http::event event;
				if (event_data.contains("event"))
					event.event_type = event_data.at("event");
				if (event_data.contains("data"))
					event.data += event_data.at("data");
				if (event_data.contains("id"))
					event.id = event_data.at("id");
				co_yield event;
			}
		}
	}

	void event_stream_handler::notify(const http::http_fields& headers, const bool end_stream) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed)
			throw std::runtime_error{"Unexpected HEADER from closed/half-closed stream."};
		if (!headers.contains("content-type") || !headers.at("content-type").starts_with("text/event-stream"))
			throw std::runtime_error{"server does not response with text/event-stream"};
		if (end_stream)
			set_remote_closed_();
	}

	void event_stream_handler::notify(const byte_string_view view, bool end_stream) {
		buffer_ += reinterpret_cast<const std::string_view&>(view);
		if (end_stream)
			set_remote_closed_();
	}

	void event_stream_handler::reserve(stream_id_t promised, http::http_fields headers) {
		auto handler = std::make_unique<response_handler>(promised, std::move(headers), context_);
		handler.reset();
		context_.register_handler(std::move(handler));
	}

	void event_stream_handler::reset() {
		state_ = state_t::closed;
	}
}
