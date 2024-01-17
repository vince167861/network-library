#include "http2/stream_control.h"

#include "utils.h"


namespace leaf::network::http2 {

	const std::runtime_error
	stream_unavailable{"This stream is reserved by remote or used by another request."};

	stream_handler::stream_handler(const stream_id_t stream_id, context& context, const state_t state)
		: state_(state), context_(context), stream_id_(stream_id),
			window_bytes_(context_.remote_config.init_window_size) {
	}

	void stream_handler::send_request(stream& s, const http::request& req) {
		if (state_ != state_t::local_reserved && state_ != state_t::idle)
			throw stream_unavailable;
		request_ = req;

		auto copy = request_.headers;
		copy.set(":path", request_.request_url.requesting_uri_string());
		copy.set(":method", request_.method);
		copy.set(":authority", request_.request_url.host);
		copy.set(":scheme", request_.request_url.scheme);

		headers_frame h_f{stream_id_};
		h_f.end_stream = req.body.empty();
		h_f.set_header(context_.local_packer, copy);
		context_.add_task(send(s, std::move(h_f)));

		if (!req.body.empty()) {
			data_frame d_f{stream_id_};
			d_f.data = req.body;
			d_f.end_stream = true;
			context_.add_task(send(s, d_f));
		}

		state_ = state_t::open;
	}

	task<void> stream_handler::send(stream& s, const frame& frame) {
		if (std::holds_alternative<headers_frame>(frame)) {
			auto& casted = std::get<headers_frame>(frame);
			std::string_view fragments{casted.pending_fragments};
			for (bool first_frame = true; !fragments.empty(); first_frame = false) {
				auto fragment = fragments.substr(0, window_bytes_);
				fragments.remove_prefix(fragment.size());
				reverse_write(s, fragment.size(), 3);
				reverse_write(s, first_frame ? frame_type_t::headers : frame_type_t::continuation);
				reverse_write(s, (fragments.empty() ? 1 << 2 : 0) |
					(first_frame ? (casted.priority ? 1 << 5 : 0) | (casted.padding ? 1 << 3 : 0) | casted.end_stream : 0), 1);
				reverse_write(s, stream_id_);
				if (casted.priority) {
					const auto& [exclusive, dependency, weight] = casted.priority.value();
					reverse_write(s, exclusive << 31 | dependency, 4);
					reverse_write(s, weight);
				}
				s.write(fragment);
			}
			co_return;
		}
		if (std::holds_alternative<data_frame>(frame)) {
			const auto casted = std::get<data_frame>(frame);
			std::string_view fragments{casted.data};
			while (!fragments.empty()) {
				if (const auto available = get_available_window()) {
					auto fragment = fragments.substr(available);
					fragments.remove_prefix(fragment.size());
					reverse_write(s, fragment.length(), 3);
					reverse_write(s, frame_type_t::data);
					reverse_write(s, casted.end_stream && fragments.empty() ? 1 : 0, 1);
					reverse_write(s, stream_id_);
					s.write(fragments);
				}
				else
					co_await std::suspend_always{};
			}
			co_return;
		}
		if (std::holds_alternative<rst_stream>(frame)) {
			auto& casted = std::get<rst_stream>(frame);
			reverse_write(s, 4, 3);
			reverse_write(s, frame_type_t::rst_stream);
			reverse_write(s, 0, 1);
			reverse_write(s, stream_id_);
			reverse_write(s, casted.error_code);
			co_return;
		}
		if (std::holds_alternative<priority_frame>(frame)) {
			auto& casted = std::get<priority_frame>(frame);
			reverse_write(s, 5, 3);
			reverse_write(s, frame_type_t::priority);
			reverse_write(s, 0, 1);
			reverse_write(s, stream_id_);
			reverse_write(s, casted.stream_dependence | (casted.exclusive ? 1 << 31 : 0), 4);
			reverse_write(s, casted.weight);
			co_return;
		}
		if (std::holds_alternative<push_promise_frame>(frame)) {
			auto& casted = std::get<push_promise_frame>(frame);
			std::string_view fragments{casted.pending_fragments};
			for (bool first_frame = true; !fragments.empty(); first_frame = false) {
				auto fragment = fragments.substr(0, window_bytes_);
				fragments.remove_prefix(fragment.size());
				reverse_write(s, fragment.size(), 3);
				reverse_write(s, first_frame ? frame_type_t::push_promise : frame_type_t::continuation);
				reverse_write(s, fragments.empty() ? 1 << 2 : 0, 1);
				reverse_write(s, stream_id_);
				reverse_write(s, casted.promised_stream_id);
				s.write(fragment);
			}
			co_return;
		}
		throw std::runtime_error("Unimplemented or invalid frame.");
	}

	void stream_handler::open(header_list_t headers, bool end_stream) {
		state_ = state_t::open;
		for (auto& p: headers)
			if (p.first == ":status")
				response_.status = std::stol(p.second);
			else
				response_.headers.emplace_back(std::move(p));
		if (end_stream) {
			pending_promise_.set_value(response_);
			state_ = state_t::remote_half_closed;
		}
	}

	void stream_handler::reserve(stream_id_t promised, header_list_t headers) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed)
			throw std::runtime_error{"Unexpected PUSH_PROMISE at closed/half-closed stream."};

		auto& promised_stream = context_.remote_reserve_stream(promised);
		response_.pushed.emplace_back(promised_stream);
		promised_stream.request_.headers = std::move(headers);
	}

	void stream_handler::notify(const std::string_view data, const bool end_stream) {
		if (state_ != state_t::open && state_ != state_t::local_half_closed)
			throw std::runtime_error{"Unexpected DATA at closed/half-closed stream."};

		response_.body += data;
		if (end_stream) {
			pending_promise_.set_value(response_);
			state_ = state_t::remote_half_closed;
		}
	}

	void stream_handler::reset() {
		pending_promise_.set_exception(std::make_exception_ptr(
			std::runtime_error{"Stream reset by peer (RST_STREAM)."}));
		state_ = state_t::remote_closed;
	}

	void stream_handler::increase_window(const std::uint32_t size) {
		window_bytes_ += size;
	}

	std::uint32_t stream_handler::get_available_window() const {
		return std::min(context_.remote_config.max_frame_size, window_bytes_);
	}

	std::future<response> stream_handler::get_future() {
		return pending_promise_.get_future();
	}

	stream_handler::state_t stream_handler::state() const {
		return state_;
	}

	void stream_handler::close(stream& s) {
		data_frame df{stream_id_};
		df.end_stream = true;
		context_.add_task(send(s, std::move(df)));
	}
}
