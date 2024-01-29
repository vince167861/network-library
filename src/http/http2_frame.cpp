#include "http2/frame.h"
#include "utils.h"

#include <format>

namespace leaf::network::http2 {

	frame parse_frame(stream& source) {
		std::optional<frame> pending;
		while (true) {
			auto header = source.read(9);
			auto h_ptr = header.begin();

			const auto content_length = read<std::uint32_t>(std::endian::big, h_ptr, 3);
			const auto frame_type = read<frame_type_t>(std::endian::big, h_ptr);
			const auto flags = read<std::uint8_t>(std::endian::big, h_ptr);
			const auto stream_id = read<stream_id_t>(std::endian::big, h_ptr);

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
						read(std::endian::big, s, ptr);
						read(std::endian::big, v, ptr);
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
					if (padded)
						std::advance(end, - read<std::uint8_t>(std::endian::big, ptr));
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
					read(std::endian::big, wu_f.window_size_increment, ptr);
					return wu_f;
				}
				case frame_type_t::rst_stream: {
					if (content_length != 4)
						throw std::runtime_error("RST_STREAM frame size must always be 4.");
					auto ptr = content.begin();
					if (!stream_id)
						throw std::runtime_error("RST_STREAM frame must associate with a stream.");
					rst_stream r_f{stream_id};
					read(std::endian::big, r_f.error_code, ptr);
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
					if (has_padding)
						std::advance(end, -read<std::uint8_t>(std::endian::big, ptr));
					if (has_priority) {
						const auto dependency = read<std::uint32_t>(std::endian::big, ptr);
						const auto weight = read<std::uint8_t>(std::endian::big, ptr);
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
					if (flags & 1 << 3)
						std::advance(end, -read<std::uint8_t>(std::endian::big, ptr));
					read(std::endian::big, push_promise_f.promised_stream_id, ptr);
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
					read(std::endian::big, g_frame.last_stream_id, ptr);
					read(std::endian::big, g_frame.error_code, ptr);
					g_frame.additional_data = {ptr, content.end()};
					return g_frame;
				}
				default:
					throw std::runtime_error{"invalid frame: unimplemented or peer does not support HTTP/2"};
			}
		}
	}

	stream_frame::stream_frame(const uint32_t stream_id)
		: stream_id(stream_id) {
	}

	data_frame::data_frame(const uint32_t stream_id, const bool end_stream)
		: stream_frame(stream_id), end_stream(end_stream) {
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

	http::http_fields headers_based_frame::get_headers(header_packer& decoder) const {
		return decoder.decode(pending_fragments);
	}

	void headers_based_frame::set_header(header_packer& encoder, const http::http_fields& list) {
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
