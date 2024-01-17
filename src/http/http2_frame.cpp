#include "http2/frame.h"
#include "http2/context.h"
#include "utils.h"

#include <format>

namespace leaf::network::http2 {

	frame parse_frame(stream& source) {
		std::optional<frame> pending;
		while (true) {
			auto header = source.read(9);
			auto h_ptr = header.begin();

			uint32_t content_length;
			frame_type_t frame_type;
			uint8_t flags;
			stream_id_t stream_id;

			reverse_read<3>(h_ptr, content_length);
			reverse_read(h_ptr, frame_type);
			reverse_read(h_ptr, flags);
			reverse_read(h_ptr, stream_id);

			const auto content = source.read(content_length);
			switch (frame_type) {
				case frame_type_t::settings: {
					if (pending)
						throw std::runtime_error{"Unexpected SETTINGS frame."};
					settings_frame s_f;
					s_f.ack = flags & 1;
					if (stream_id)
						throw std::runtime_error{"SETTINGS frame must not associate with a stream"};
					auto ptr = content.begin();
					if (s_f.ack && ptr != content.end())
						throw std::runtime_error{"SETTINGS frame with ACK flag must contains no settings."};
					while (ptr != content.end()) {
						auto& [s, v] = s_f.values.emplace_back();
						reverse_read(ptr, s);
						reverse_read(ptr, v);
					}
					return s_f;
				}
				case frame_type_t::data: {
					if (pending)
						throw std::runtime_error{"Unexpected DATA frame."};
					if (!stream_id)
						throw std::runtime_error{"DATA frame must associate with a stream"};
					data_frame d_f{stream_id};
					const bool padded = flags & 1 << 3;
					d_f.end_stream = flags & 1;
					auto ptr = content.begin(), end = content.end();
					if (padded) {
						uint8_t pl;
						reverse_read(ptr, pl);
						end -= pl;
					}
					d_f.data = {ptr, end};
					return d_f;
				}
				case frame_type_t::window_update: {
					if (pending)
						throw std::runtime_error{"Unexpected WINDOW_UPDATE frame."};
					if (content_length != 4)
						throw std::runtime_error("RST_STREAM frame size must always be 4.");
					window_update_frame wu_f{stream_id};
					auto ptr = content.begin();
					reverse_read(ptr, wu_f.window_size_increment);
					return wu_f;
				}
				case frame_type_t::rst_stream: {
					if (content_length != 4)
						throw std::runtime_error("RST_STREAM frame size must always be 4.");
					auto ptr = content.begin();
					if (!stream_id)
						throw std::runtime_error("RST_STREAM frame must associate with a stream.");
					rst_stream r_f{stream_id};
					reverse_read(ptr, r_f.error_code);
					return r_f;
				}
				case frame_type_t::headers: {
					if (pending)
						throw std::runtime_error("Unexpected HEADERS frame.");
					if (!stream_id)
						throw std::runtime_error("HEADERS frame must associate with a stream.");
					headers_frame frame{stream_id};
					const bool has_priority = flags & 1 << 5, has_padding = flags & 1 << 3, last_frame = flags & 1 << 2;
					frame.end_stream = flags & 1;
					auto ptr = content.begin(), end = content.end();
					if (has_padding) {
						std::uint8_t pad_length;
						reverse_read(ptr, pad_length);
						end -= pad_length;
					}
					if (has_priority) {
						std::uint32_t dependency;
						std::uint8_t weight;
						reverse_read(ptr, dependency);
						reverse_read(ptr, weight);
					}
					frame.add_fragment({ptr, end}, last_frame);
					if (last_frame)
						return frame;
					pending = std::move(frame);
					break;
				}
				case frame_type_t::push_promise: {
					if (pending)
						throw std::runtime_error("Unexpected PUSH_PROMISE frame.");
					if (!stream_id)
						throw std::runtime_error("PUSH_PROMISE frame must associate with a stream.");
					push_promise_frame push_promise_f{stream_id};
					auto ptr = content.begin(), end = content.end();
					if (flags & 1 << 3) {
						uint8_t padding_length;
						reverse_read(ptr, padding_length);
						end -= padding_length;
					}
					reverse_read(ptr, push_promise_f.promised_stream_id);
					push_promise_f.add_fragment({ptr, end}, flags & 1 << 2);
					return push_promise_f;
				}
				case frame_type_t::continuation: {
					if (!pending)
						throw std::runtime_error("Unexpected CONTINUATION frame.");
					headers_based_frame* frame = nullptr;
					if (std::holds_alternative<headers_frame>(*pending))
						frame = &std::get<headers_frame>(*pending);
					else if (std::holds_alternative<push_promise_frame>(*pending))
						frame = &std::get<push_promise_frame>(*pending);
					if (!frame)
						throw std::runtime_error("Unexpected CONTINUATION frame.");
					const bool last_frame = flags & 1 << 2;
					frame->add_fragment(content, last_frame);
					if (last_frame)
						return *pending;
					break;
				}
				case frame_type_t::go_away: {
					if (stream_id)
						throw std::runtime_error("GOAWAY frame must not be associated with a stream.");
					go_away g_frame;
					auto ptr = content.begin();
					reverse_read(ptr, g_frame.last_stream_id);
					reverse_read(ptr, g_frame.error_code);
					g_frame.additional_data = {ptr, content.end()};
					return g_frame;
				}
				default:
					throw std::runtime_error("Unimplemented frame");
			}
		}
	}

	stream_frame::stream_frame(const uint32_t stream_id)
		: stream_id(stream_id) {
	}

	data_frame::data_frame(const uint32_t stream_id)
		: stream_frame(stream_id) {
	}

	headers_based_frame::headers_based_frame(const uint32_t stream_id)
		: stream_frame(stream_id) {
	}

	void headers_based_frame::add_fragment(const std::string_view source, const bool last_frame) {
		if (conclude_)
			throw std::runtime_error("Invalid operation: This frame has concluded.");
		pending_fragments += source;
		if (last_frame)
			conclude_ = true;
	}

	header_list_t headers_based_frame::get_headers(header_packer& decoder) const {
		return decoder.decode(pending_fragments);
	}

	void headers_based_frame::set_header(header_packer& encoder, const header_list_t& list) {
		pending_fragments = encoder.encode(list);
		conclude_ = true;
	}

	headers_frame::headers_frame(const stream_id_t stream_id)
		: headers_based_frame(stream_id) {
	}

	priority_frame::priority_frame(const stream_id_t stream_id)
		: stream_frame(stream_id) {
	}

	rst_stream::rst_stream(const stream_id_t stream_id)
		: stream_frame(stream_id) {
	}

	settings_frame::settings_frame()
		: ack(true) {
	}

	settings_frame::settings_frame(setting_values_t values)
		: ack(false), values(std::move(values)) {
	}

	push_promise_frame::push_promise_frame(const stream_id_t stream_id)
		: headers_based_frame(stream_id) {
	}

	go_away::go_away(const uint32_t last_stream_id, const error_t e, const std::string_view additional_data)
		: last_stream_id(last_stream_id),
		error_code(e), additional_data(additional_data) {
	}

	window_update_frame::window_update_frame(const uint32_t stream_id)
		: stream_frame(stream_id) {
	}

}

std::format_context::iterator
std::formatter<leaf::network::http2::frame>::format(const leaf::network::http2::frame& f, format_context& context) const {
	using namespace leaf::network::http2;
	if (std::holds_alternative<data_frame>(f)) {
		auto& casted = std::get<data_frame>(f);
		auto it = std::format_to(context.out(), "DATA [{}]\n\tLength: {}", casted.stream_id, casted.data.length());
		if (casted.end_stream)
			it = std::ranges::copy("\n\t+ END_STREAM", it).out;
		return it;
	}
	if (std::holds_alternative<headers_frame>(f)) {
		auto& casted = std::get<headers_frame>(f);
		auto it = std::format_to(context.out(), "HEADERS [{}]", casted.stream_id);
		if (casted.priority)
			it = std::ranges::copy("\n\t+ PRIORITY", it).out;
		if (casted.end_stream)
			it = std::ranges::copy("\n\t+ END_STREAM", it).out;
		return it;
	}
	if (std::holds_alternative<priority_frame>(f)) {
		auto& casted = std::get<priority_frame>(f);
		return std::format_to(context.out(), "PRIORITY [{}]", casted.stream_id);
	}
	if (std::holds_alternative<rst_stream>(f)) {
		auto& casted = std::get<rst_stream>(f);
		return std::format_to(context.out(), "RST_STREAM [{}]\n\tError: {}", casted.stream_id, casted.error_code);
	}
	if (std::holds_alternative<settings_frame>(f)) {
		auto& casted = std::get<settings_frame>(f);
		auto it = std::ranges::copy("SETTINGS"sv, context.out()).out;
		if (casted.ack)
			it = std::ranges::copy("\n\t+ ACK", it).out;
		else if (casted.values.empty())
			it = std::ranges::copy("\n\t(empty)", it).out;
		else for (auto& [set, v]: casted.values)
			it = std::format_to(it, "\n\t{}: {}", set, v);
		return it;
	}
	if (std::holds_alternative<push_promise_frame>(f)) {
		auto& casted = std::get<push_promise_frame>(f);
		return std::format_to(context.out(), "PUSH_PROMISE [{}]\n\tPromised stream id: {}",
			casted.stream_id, casted.promised_stream_id);
	}
	if (std::holds_alternative<ping_frame>(f)) {
		return std::ranges::copy("PING"sv, context.out()).out;
	}
	if (std::holds_alternative<go_away>(f)) {
		auto& casted = std::get<go_away>(f);
		auto it = std::format_to(context.out(), "GOAWAY\n\tLast stream id: {}\n\tError: {}",
			casted.last_stream_id, casted.error_code);
		if (!casted.additional_data.empty())
			it = std::format_to(it, "Additional: {}\n", casted.additional_data);
		return it;
	}
	if (std::holds_alternative<window_update_frame>(f)) {
		auto& casted = std::get<window_update_frame>(f);
		return std::format_to(context.out(), "WINDOW_UPDATE [{}]\n\tIncrement: {}",
			casted.stream_id, casted.window_size_increment);
	}
	throw std::runtime_error("Unimplemented formatter");
}
