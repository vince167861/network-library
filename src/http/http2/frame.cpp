#include "http2/frame.h"
#include "http2/state.h"
#include "internal/utils.h"
#include <format>

namespace leaf::network::http2 {

	std::expected<std::pair<frame_type_t, std::unique_ptr<basic_frame>>, frame_parsing_error> parse_frame(istream& __s) {
		std::optional<std::pair<frame_type_t, std::unique_ptr<basic_frame>>> __pending;
		while (true) {
			const auto __h = __s.read(9);
			auto __hit = __h.begin();
			const auto __l = read<std::uint32_t>(std::endian::big, __hit, 3);
			const auto __t = read<frame_type_t>(std::endian::big, __hit);
			const auto __f = read<frame_flags>(std::endian::big, __hit);
			const auto __id = read<stream_id_t>(std::endian::big, __hit);
			const auto __c = __s.read(__l);
			switch (__t) {
				case frame_type_t::settings: {
					if (__pending)
						throw connection_error(error_t::protocol_error, "unexpected SETTINGS");
					if (__id)
						throw connection_error(error_t::protocol_error, "SETTINGS must not associate a stream");
					if (__f.ack) {
						if (!__c.empty())
							throw connection_error(error_t::frame_size_error, "SETTINGS + ACK must be empty.");
						return {{__t, std::make_unique<settings>()}};
					}
					setting_values_t __vs;
					auto it = __c.begin(), end = __c.end();
					while (it != end) {
						auto& [__s, __v] = __vs.emplace_back();
						read(std::endian::big, __s, it);
						read(std::endian::big, __v, it);
					}
					return {{__t, std::make_unique<settings>(std::move(__vs))}};
				}
				case frame_type_t::data: {
					if (__pending)
						throw connection_error(error_t::protocol_error, "unexpected DATA");
					if (!__id)
						throw connection_error(error_t::protocol_error, "DATA must associate a stream");
					auto __frame = std::make_unique<data>(__id, __f.end_stream);
					auto it = __c.begin(), end = __c.end();
					if (__f.padded)
						std::advance(end, -read<std::uint8_t>(std::endian::big, it));
					__frame->content = {it, end};
					return {{__t, std::move(__frame)}};
				}
				case frame_type_t::window_update: {
					if (__pending)
						throw connection_error(error_t::protocol_error, "unexpected WINDOW_UPDATE");
					if (__l != 4)
						throw connection_error(error_t::frame_size_error, "WINDOW_UPDATE length is always 4");
					auto __frame = std::make_unique<window_update>(__id);
					auto it = __c.begin();
					read(std::endian::big, __frame->window_size_increment, it);
					return {{__t, std::move(__frame)}};
				}
				case frame_type_t::rst_stream: {
					if (__l != 4)
						throw connection_error(error_t::frame_size_error, "RST_STREAM length is always 4");
					if (!__id)
						throw connection_error(error_t::protocol_error, "RST_STREAM must associate a stream");
					auto it = __c.begin();
					auto __frame = std::make_unique<rst_stream>(__id);
					read(std::endian::big, __frame->error_code, it);
					return {{__t, std::move(__frame)}};
				}
				case frame_type_t::headers: {
					if (__pending)
						throw connection_error(error_t::protocol_error, "unexpected HEADERS");
					if (!__id)
						throw connection_error(error_t::protocol_error, "HEADERS must associate a stream");
					auto __frame = std::make_unique<headers>(__id, __f.end_stream);
					auto it = __c.begin(), end = __c.end();
					if (__f.padded)
						std::advance(end, -read<std::uint8_t>(std::endian::big, it));
					if (__f.has_priority)
						read(std::endian::big, __frame->priority.emplace(), it);
					__frame->add_fragment({it, end}, __f.end_headers);
					if (__f.end_headers)
						return {{__t, std::move(__frame)}};
					__pending.emplace(__t, std::move(__frame));
					break;
				}
				case frame_type_t::push_promise: {
					if (__pending)
						throw connection_error(error_t::protocol_error, "unexpected PUSH_PROMISE");
					if (!__id)
						throw connection_error(error_t::protocol_error, "PUSH_PROMISE must associate a stream");
					auto __frame = std::make_unique<push_promise>(__id);
					auto it = __c.begin(), end = __c.end();
					if (__f.padded)
						std::advance(end, -read<std::uint8_t>(std::endian::big, it));
					read(std::endian::big, __frame->promised_stream_id, it);
					__frame->add_fragment({it, end}, __f.end_headers);
					if (__f.end_headers)
						return {{__t, std::move(__frame)}};
					__pending.emplace(__t, std::move(__frame));
					break;
				}
				case frame_type_t::continuation: {
					if (!__pending)
						throw connection_error(error_t::protocol_error, "unexpected CONTINUATION");
					auto& __frame = reinterpret_cast<headers_holder&>(*__pending);
					__frame.add_fragment(__c, __f.end_headers);
					if (__f.end_headers)
						return std::move(*__pending);
					break;
				}
				case frame_type_t::go_away: {
					if (__id)
						throw connection_error(error_t::protocol_error, "GOAWAY must not associate a stream");
					auto __frame = std::make_unique<go_away>();
					auto it = __c.begin();
					read(std::endian::big, __frame->last_stream_id, it);
					read(std::endian::big, __frame->error_code, it);
					__frame->additional_data = {it, __c.end()};
					return {{__t, std::move(__frame)}};
				}
				default:
					return std::unexpected(frame_parsing_error::unknown_frame);
			}
		}
	}

	stream_frame::stream_frame(const uint32_t stream_id)
		: stream_id(stream_id) {
	}

	data::data(const uint32_t stream_id, const bool end_stream)
		: stream_frame(stream_id), end_stream(end_stream) {
	}

	frame_generator data::generator(ostream& __s, stream_state& __h) const {
		byte_string_view fragments(content);
		while (!fragments.empty()) {
			if (const auto available = __h.available_window()) {
				const auto fragment = fragments.substr(0, available);
				fragments.remove_prefix(fragment.size());
				write(std::endian::big, __s, fragment.length(), 3);
				write(std::endian::big, __s, frame_type_t::data);
				write(std::endian::big, __s, end_stream && fragments.empty() ? 1 : 0, 1);
				write(std::endian::big, __s, stream_id);
				__s.write(fragments);
			} else
				co_await std::suspend_always();
		}
		co_return;
	}

	std::format_context::iterator data::format(std::format_context::iterator it) const {
		it = std::format_to(it, "DATA [{}]\n\tLength: {}", stream_id, content.length());
		if (end_stream)
			it = std::ranges::copy("\n\t+ END_STREAM", it).out;
		return it;
	}

	headers_holder::headers_holder(const uint32_t stream_id)
		: stream_frame(stream_id) {
	}

	void headers_holder::add_fragment(const byte_string_view source, const bool last_frame) {
		if (conclude_)
			throw std::runtime_error("Invalid operation: This frame has concluded.");
		fragments += source;
		if (last_frame)
			conclude_ = true;
	}

	http::http_fields headers_holder::get_headers(header_packer& decoder) const {
		return decoder.decode(fragments);
	}

	void headers_holder::set_header(header_packer& encoder, const http::http_fields& list) {
		fragments = encoder.encode(list);
		conclude_ = true;
	}

	headers::headers(const stream_id_t stream_id, const bool __es)
		: headers_holder(stream_id), end_stream(__es) {
	}

	frame_generator headers::generator(ostream& __s, stream_state& __h) const {
		const auto __copy(*this);
		co_await std::suspend_always();
		byte_string_view __pending(__copy.fragments);
		for (bool first_frame = true; !__pending.empty(); first_frame = false) {
			const auto __f = __pending.substr(0, __h.available_window());
			__pending.remove_prefix(__f.size());
			frame_flags __flags;
			__flags.end_headers = __pending.empty();
			if (first_frame) {
				__flags.has_priority = __copy.priority.has_value();
				__flags.padded = __copy.padding.has_value();
				__flags.end_stream = __copy.end_stream;
			}
			write(std::endian::big, __s, __f.size(), 3);
			write(std::endian::big, __s, first_frame ? frame_type_t::headers : frame_type_t::continuation);
			write(std::endian::big, __s, __flags);
			write(std::endian::big, __s, __copy.stream_id);
			if (__copy.priority)
				write(std::endian::big, __s, __copy.priority.value());
			__s.write(__f);
		}
		co_return;
	}

	std::format_context::iterator headers::format(std::format_context::iterator it) const {
		it = std::format_to(it, "HEADERS [{}]", stream_id);
		if (priority)
			it = std::ranges::copy("\n\t+ PRIORITY", it).out;
		if (end_stream)
			it = std::ranges::copy("\n\t+ END_STREAM", it).out;
		return it;
	}

	priority::priority(const stream_id_t stream_id)
		: stream_frame(stream_id) {
	}

	frame_generator priority::generator(ostream& __s, stream_state& __h) const {
		const auto __copy(*this);
		co_await std::suspend_always();
		write(std::endian::big, __s, 5, 3);
		write(std::endian::big, __s, frame_type_t::priority);
		write(std::endian::big, __s, 0, 1);
		write(std::endian::big, __s, __copy.stream_id);
		write(std::endian::big, __s, __copy.values);
		co_return;
	}

	std::format_context::iterator priority::format(std::format_context::iterator it) const {
		return std::format_to(it, "PRIORITY [{}]", stream_id);
	}

	rst_stream::rst_stream(const stream_id_t stream_id)
		: stream_frame(stream_id) {
	}

	frame_generator rst_stream::generator(ostream& __s, stream_state& __h) const {
		const auto __copy(*this);
		co_await std::suspend_always();
		write(std::endian::big, __s, 4, 3);
		write(std::endian::big, __s, frame_type_t::rst_stream);
		write(std::endian::big, __s, 0, 1);
		write(std::endian::big, __s, __copy.stream_id);
		write(std::endian::big, __s, __copy.error_code);
		co_return;
	}

	std::format_context::iterator rst_stream::format(std::format_context::iterator it) const {
		return std::format_to(it, "RST_STREAM [{}]\n\tError: {}", stream_id, error_code);
	}

	settings::settings()
		: ack(true) {
	}

	settings::settings(setting_values_t values)
		: ack(false), values(std::move(values)) {
	}

	void settings::generator(ostream& __s, connection_state& __state) const {
		write(std::endian::big, __s, values.size() * 6, 3);
		write(std::endian::big, __s, frame_type_t::settings);
		write(std::endian::big, __s, ack ? 1 : 0, 1);
		write(std::endian::big, __s, 0, 4);
		for (auto& [s, v]: values) {
			write(std::endian::big, __s, s);
			write(std::endian::big, __s, v);
		}
	}

	std::format_context::iterator settings::format(std::format_context::iterator it) const {
		it = std::ranges::copy("SETTINGS", it).out;
		if (ack)
			it = std::ranges::copy("\n\t+ ACK", it).out;
		else if (values.empty())
			it = std::ranges::copy("\n\t(empty)", it).out;
		else for (auto& [set, v]: values)
			it = std::format_to(it, "\n\t{}: {}", set, v);
		return it;
	}

	push_promise::push_promise(const stream_id_t stream_id)
		: headers_holder(stream_id) {
	}

	frame_generator push_promise::generator(ostream& __s, stream_state& __h) const {
		const auto __copy(*this);
		co_await std::suspend_always();
		byte_string_view __fragment(__copy.fragments);
		for (bool first_frame = true; !__fragment.empty(); first_frame = false) {
			auto fragment = __fragment.substr(0, __h.available_window());
			__fragment.remove_prefix(fragment.size());
			write(std::endian::big, __s, fragment.size(), 3);
			write(std::endian::big, __s, first_frame ? frame_type_t::push_promise : frame_type_t::continuation);
			write(std::endian::big, __s, __fragment.empty() ? 1 << 2 : 0, 1);
			write(std::endian::big, __s, __copy.stream_id);
			write(std::endian::big, __s, __copy.promised_stream_id);
			__s.write(fragment);
		}
		co_return;
	}

	std::format_context::iterator push_promise::format(std::format_context::iterator it) const {
		return std::format_to(it, "PUSH_PROMISE [{}]\n\tPromised stream id: {}", stream_id, promised_stream_id);
	}

	void ping::generator(ostream& __s, connection_state& __state) const {
		write(std::endian::big, __s, 8, 3);
		write(std::endian::big, __s, frame_type_t::ping);
		write(std::endian::big, __s, ack ? 1 : 0, 1);
		write(std::endian::big, __s, 0, 4);
		write(std::endian::big, __s, data);
	}

	std::format_context::iterator ping::format(std::format_context::iterator it) const {
		return std::ranges::copy("PING", it).out;
	}

	go_away::go_away(const uint32_t last_stream_id, const error_t e, const std::string_view additional_data)
		: last_stream_id(last_stream_id), error_code(e), additional_data(additional_data) {
	}

	void go_away::generator(ostream& __s, connection_state& __state) const {
		write(std::endian::big, __s, 8 + additional_data.length(), 3);
		write(std::endian::big, __s, frame_type_t::go_away);
		write(std::endian::big, __s, 0, 1);
		write(std::endian::big, __s, 0, 4);
		write(std::endian::big, __s, last_stream_id);
		write(std::endian::big, __s, error_code);
		__s.write(reinterpret_cast<const byte_string&>(additional_data));
	}

	std::format_context::iterator go_away::format(std::format_context::iterator it) const {
		it = std::format_to(it, "GOAWAY\n\tlast stream id: {}\n\terror: {}", last_stream_id, error_code);
		if (!additional_data.empty())
			it = std::format_to(it, "\n\tadditional: {}", additional_data);
		return it;
	}

	window_update::window_update(const stream_id_t __id)
		: stream_frame(__id) {
	}

	void window_update::generator(ostream& __s, connection_state& __state) const {
		if (!stream_id)
			throw std::runtime_error("this WINDOW_UPDATE does not associate a stream; sending in streams is disabled");
		write(std::endian::big, __s, 8, 3);
		write(std::endian::big, __s, frame_type_t::window_update);
		write(std::endian::big, __s, 0, 1);
		write(std::endian::big, __s, stream_id);
		write(std::endian::big, __s, window_size_increment);
	}

	frame_generator window_update::generator(ostream& __s, stream_state& __state) const {
		if (stream_id)
			throw std::runtime_error("this WINDOW_UPDATE is restricted to a stream; sending in connections is disabled");
		const auto __copy(*this);
		co_await std::suspend_always();
		write(std::endian::big, __s, 8, 3);
		write(std::endian::big, __s, frame_type_t::window_update);
		write(std::endian::big, __s, 0, 1);
		write(std::endian::big, __s, 0, 4);
		write(std::endian::big, __s, __copy.window_size_increment);
		co_return;
	}

	std::format_context::iterator window_update::format(std::format_context::iterator it) const {
		return std::format_to(it, "WINDOW_UPDATE [{}]\n\tincrement: {}", stream_id, window_size_increment);
	}
}
