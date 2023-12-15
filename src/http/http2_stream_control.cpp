#include "http2/stream_control.h"

#include "utils.h"


namespace leaf::network::http2 {

	const std::runtime_error
	stream_unavailable{"This stream is reserved by remote or used by another request."};

	stream_handler::stream_handler(const uint32_t stream_id, context& context, const state_t state)
		: state_(state), context_(context), stream_id_(stream_id),
			window_bytes_(context_.remote_config.init_window_size) {
	}

	void stream_handler::send_request(stream& s, const http::request& req) {
		if (state_ != state_t::local_reserved && state_ != state_t::idle)
			throw stream_unavailable;
		request_ = req;
		auto& target = request_.request_url;

		auto copy = request_.headers;
		std::string path = target.path.empty() ? "/" : target.path;
		if (!target.query.empty())
			path = path + '?' + to_url_encoded(target.query);
		copy.emplace_front(":path", std::move(path));
		copy.emplace_front(":method", request_.method);
		copy.emplace_front(":authority", target.host);
		copy.emplace_front(":scheme", target.scheme);

		auto h_f = std::make_shared<headers_frame>(stream_id_);
		h_f->end_stream = req.body.empty();
		h_f->set_header(context_.local_packer, copy);
		context_.add_task(send(s, std::move(h_f)));

		if (!req.body.empty()) {
			auto d_f = std::make_shared<data_frame>(stream_id_);
			d_f->data = req.body;
			d_f->end_stream = true;
			context_.add_task(send(s, std::move(d_f)));
		}

		state_ = state_t::open;
	}

	task<void> stream_handler::send(stream& s, std::shared_ptr<stream_frame> frame) {
		switch (frame->type) {
			case frame_type_t::headers: {
				auto& h_f = reinterpret_cast<headers_frame&>(*frame);
				const auto begin = h_f.pending_fragments.begin(), end = h_f.pending_fragments.end();
				auto ptr = begin;
				while (ptr != end) {
					const auto frame_length = std::min<std::uint32_t>(end - ptr, window_bytes_);
					const auto ptr_begin = ptr;
					const bool first_fragment = ptr_begin == begin;
					std::advance(ptr, frame_length);
					reverse_write(s, frame_length, 3);
					reverse_write(s, first_fragment ? frame_type_t::headers : frame_type_t::continuation);
					reverse_write<uint8_t>(s,
						(ptr == end ? 1 << 2 : 0)
						| (first_fragment ? (h_f.priority.has_value() ? 1 << 5 : 0) | (h_f.padding.has_value() ? 1 << 3 : 0) | h_f.end_stream : 0));
					reverse_write(s, stream_id_);
					if (h_f.priority.has_value()) {
						const auto& [exclusive, dependency, weight] = h_f.priority.value();
						reverse_write<uint32_t>(s, exclusive << 31 | dependency);
						reverse_write(s, weight);
					}
					s.write({ptr_begin, ptr});
				}
				co_return;
			}
			case frame_type_t::data: {
				auto& d_f = reinterpret_cast<data_frame&>(*frame);
				const auto begin = d_f.data.begin(), end = d_f.data.end();
				auto ptr = begin;
				while (ptr != end) {
					if (const auto available = get_available_window()) {
						const auto begin_ptr = ptr;
						std::advance(ptr, std::min<std::uint64_t>(end - ptr, available));
						std::string_view fragments{begin_ptr, ptr};
						const bool last_fragment = ptr == end;
						reverse_write(s, fragments.length(), 3);
						reverse_write(s, frame_type_t::data);
						reverse_write<uint8_t>(s, d_f.end_stream && last_fragment ? 1 : 0);
						reverse_write(s, stream_id_);
						s.write(fragments);
					}
					else
						co_await std::suspend_always{};
				}
				co_return;
			}
			case frame_type_t::rst_stream: {
				auto& r_f = reinterpret_cast<rst_stream&>(*frame);
				reverse_write<uint32_t>(s, 4, 3);
				reverse_write(s, frame_type_t::rst_stream);
				reverse_write<uint8_t>(s, 0);
				reverse_write(s, stream_id_);
				reverse_write(s, r_f.error_code);
				co_return;
			}
			case frame_type_t::priority: {
				auto& p_f = reinterpret_cast<priority_frame&>(*frame);
				reverse_write<uint32_t>(s, 5, 3);
				reverse_write(s, frame_type_t::priority);
				reverse_write<uint8_t>(s, 0);
				reverse_write(s, stream_id_);
				reverse_write<uint32_t>(s, p_f.stream_dependence | p_f.exclusive << 31);
				reverse_write(s, p_f.weight);
				co_return;
			}
			case frame_type_t::push_promise: {
				auto& p = reinterpret_cast<push_promise_frame&>(*frame);
				const auto begin = p.pending_fragments.begin(), end = p.pending_fragments.end();
				auto ptr = begin;
				while (ptr != end) {
					const auto frame_length = std::min<std::uint32_t>(end - ptr, window_bytes_);
					const auto ptr_begin = ptr;
					const bool first_fragment = ptr_begin == begin;
					std::advance(ptr, frame_length);
					reverse_write(s, frame_length, 3);
					reverse_write(s, first_fragment ? frame_type_t::push_promise : frame_type_t::continuation);
					reverse_write<uint8_t>(s, ptr == end ? 1 << 2 : 0);
					reverse_write(s, stream_id_);
					reverse_write(s, p.promised_stream_id);
					s.write({ptr_begin, ptr});
				}
				co_return;
			}
		}
	}

	void stream_handler::handle(const stream_frame& frame) {
		switch (frame.type) {
			case frame_type_t::headers: {
				state_ = state_t::open;

				auto& h_f = reinterpret_cast<const headers_frame&>(frame);
				for (auto& p: h_f.get_headers(context_.remote_packer))
					if (p.first == ":status")
						response_.status = std::stol(p.second);
					else
						response_.headers.emplace_back(std::move(p));
				if (h_f.end_stream) {
					pending_promise_.set_value(response_);
					state_ = state_t::remote_half_closed;
				}
				break;
			}
			case frame_type_t::push_promise: {
				if (state_ != state_t::open && state_ != state_t::local_half_closed)
					throw std::runtime_error{"Unexpected PUSH_PROMISE at closed/half-closed stream."};

				auto& hb_f = reinterpret_cast<const push_promise_frame&>(frame);
				auto& promised_stream = context_.remote_reserve_stream(hb_f.promised_stream_id);
				response_.pushed.emplace_back(promised_stream);
				promised_stream.request_.headers = hb_f.get_headers(context_.remote_packer);
				break;
			}
			case frame_type_t::data: {
				if (state_ != state_t::open && state_ != state_t::local_half_closed)
					throw std::runtime_error{"Unexpected DATA at closed/half-closed stream."};

				auto& d_f = reinterpret_cast<const data_frame&>(frame);
				response_.body += d_f.data;
				if (d_f.end_stream) {
					pending_promise_.set_value(response_);
					state_ = state_t::remote_half_closed;
				}
				break;
			}
			case frame_type_t::rst_stream: {
				auto& r_f = reinterpret_cast<const rst_stream&>(frame);
				pending_promise_.set_exception(std::make_exception_ptr(
					std::runtime_error{"Stream reset by peer (RST_STREAM)."}));
				state_ = state_t::remote_closed;
				break;
			}
			case frame_type_t::window_update: {
				auto& wu_f = reinterpret_cast<const window_update_frame&>(frame);
				window_bytes_ += wu_f.window_size_increment;
				break;
			}
		}
	}

	uint32_t stream_handler::get_available_window() {
		return std::min(context_.remote_config.max_frame_size, window_bytes_);
	}

	std::future<response> stream_handler::get_future() {
		return pending_promise_.get_future();
	}

	stream_handler::state_t stream_handler::state() const {
		return state_;
	}

	void stream_handler::close(stream& s) {
		auto df = std::make_shared<data_frame>(stream_id_);
		df->end_stream = true;
		context_.add_task(send(s, std::move(df)));
	}
}
