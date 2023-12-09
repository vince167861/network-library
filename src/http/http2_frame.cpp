#include "http2/frame.h"

#include "http2/context.h"
#include "utils.h"

namespace leaf::network::http2 {

	frame::frame(const frame_type_t t)
		: type(t) {
	}

	std::shared_ptr<frame> frame::parse(stream& source) {
		std::shared_ptr<frame> frame;
		while (!frame || !frame->valid()) {
			auto header = source.read(9);
			auto h_ptr = header.begin();

			uint32_t content_length;
			frame_type_t frame_type;
			uint8_t flags;
			uint32_t stream_id;

			reverse_read<3>(h_ptr, content_length);
			reverse_read(h_ptr, frame_type);
			reverse_read(h_ptr, flags);
			reverse_read(h_ptr, stream_id);

			const auto content = source.read(content_length);
			switch (frame_type) {
				case frame_type_t::settings: {
					if (frame)
						throw std::runtime_error{"Unexpected SETTINGS frame."};
					const auto s_f = std::make_shared<settings_frame>();
					s_f->ack = flags & 1;
					if (stream_id)
						throw std::runtime_error{"SETTINGS frame must not associate with a stream"};
					auto ptr = content.begin();
					if (s_f->ack && ptr != content.end())
						throw std::runtime_error{"SETTINGS frame with ACK flag must contains no settings."};
					while (ptr != content.end()) {
						auto& [s, v] = s_f->values.emplace_back();
						reverse_read(ptr, s);
						reverse_read(ptr, v);
					}
					frame = s_f;
					break;
				}
				case frame_type_t::data: {
					if (frame)
						throw std::runtime_error{"Unexpected DATA frame."};
					if (!stream_id)
						throw std::runtime_error{"DATA frame must associate with a stream"};
					const auto d_f = std::make_shared<data_frame>(stream_id);
					const bool padded = flags & 1 << 3;
					d_f->end_stream = flags & 1;
					auto ptr = content.begin(), end = content.end();
					if (padded) {
						uint8_t pl;
						reverse_read(ptr, pl);
						end -= pl;
					}
					d_f->data = {ptr, end};
					frame = d_f;
					break;
				}
				case frame_type_t::window_update: {
					if (frame)
						throw std::runtime_error{"Unexpected WINDOW_UPDATE frame."};
					if (content_length != 4)
						throw std::runtime_error("RST_STREAM frame size must always be 4.");
					const auto wu_f = std::make_shared<window_update_frame>(stream_id);
					auto ptr = content.begin();
					reverse_read(ptr, wu_f->window_size_increment);
					frame = wu_f;
					break;
				}
				case frame_type_t::rst_stream: {
					if (content_length != 4)
						throw std::runtime_error("RST_STREAM frame size must always be 4.");
					auto ptr = content.begin();
					if (!stream_id)
						throw std::runtime_error("RST_STREAM frame must associate with a stream.");
					const auto r_f = std::make_shared<rst_stream>(stream_id);
					reverse_read(ptr, r_f->error_code);
					frame = r_f;
					break;
				}
				case frame_type_t::headers: {
					if (frame)
						throw std::runtime_error("Unexpected HEADERS frame.");
					if (!stream_id)
						throw std::runtime_error("HEADERS frame must associate with a stream.");
					const auto headers_f = std::make_shared<headers_frame>(stream_id);
					const bool
							has_priority = flags & 1 << 5, has_padding = flags & 1 << 3;
					headers_f->end_stream = flags & 1;
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
					headers_f->add_fragment({ptr, end}, flags & 1 << 2);
					frame = headers_f;
					break;
				}
				case frame_type_t::push_promise: {
					if (frame)
						throw std::runtime_error("Unexpected PUSH_PROMISE frame.");
					if (!stream_id)
						throw std::runtime_error("PUSH_PROMISE frame must associate with a stream.");
					const auto push_promise_f = std::make_shared<push_promise_frame>(stream_id);
					auto ptr = content.begin(), end = content.end();
					if (flags & 1 << 3) {
						uint8_t padding_length;
						reverse_read(ptr, padding_length);
						end -= padding_length;
					}
					reverse_read(ptr, push_promise_f->promised_stream_id);
					push_promise_f->add_fragment({ptr, end}, flags & 1 << 2);
					frame = push_promise_f;
					break;
				}
				case frame_type_t::continuation: {
					const auto hb_f = std::dynamic_pointer_cast<headers_based_frame>(frame);
					if (!frame)
						throw std::runtime_error("Unexpected CONTINUATION frame.");
					hb_f->add_fragment(content, flags & 1 << 2);
					break;
				}
				case frame_type_t::go_away: {
					if (stream_id)
						throw std::runtime_error("GOAWAY frame must not associate with a stream.");
					const auto g_frame = std::make_shared<go_away_frame>();
					auto ptr = content.begin();
					reverse_read(ptr, g_frame->last_stream_id);
					reverse_read(ptr, g_frame->error_code);
					g_frame->additional_data = {ptr, content.end()};
					frame = g_frame;
					break;
				}
				default:
					throw std::runtime_error("Unimplemented frame");
			}
		}
		return frame;
	}

	std::ostream& operator<<(std::ostream& s, const frame& f) {
		f.print(s);
		return s;
	}

	stream_frame::stream_frame(const uint32_t stream_id)
		: stream_id(stream_id) {
	}

	data_frame::data_frame(const uint32_t stream_id)
		: frame(frame_type_t::data), stream_frame(stream_id) {
	}

	void data_frame::print(std::ostream& s) const {
		s << "DATA [" << stream_id << "]\n\tLength: " << data.length() << '\n';
		if (end_stream)
			s << "\t+ END_STREAM\n";
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

	headers_frame::headers_frame(const uint32_t stream_id)
		: frame(frame_type_t::headers), headers_based_frame(stream_id) {
	}

	void headers_frame::print(std::ostream& s) const {
		s << "HEADERS [" << stream_id << "]\n";
		if (priority.has_value())
			s << "\t+ PRIORITY\n";
		if (end_stream)
			s << "\t+ END_STREAM\n";
	}

	priority_frame::priority_frame(const uint32_t stream_id)
		: frame(frame_type_t::priority), stream_frame(stream_id) {
	}

	void priority_frame::print(std::ostream& s) const {
		s << "PRIORITY [" << stream_id << "]\n";
	}

	rst_stream::rst_stream(const uint32_t stream_id)
		: frame(frame_type_t::rst_stream), stream_frame(stream_id) {
	}

	void rst_stream::print(std::ostream& s) const {
		s << "RST_STREAM [" << stream_id << "]\n\tError: " << error_code << '\n';
	}

	void settings_frame::print(std::ostream& s) const {
		s << "SETTINGS\n";
		if (ack)
			s << "\t+ ACK\n";
		else if (values.empty())
			s << "\t(empty)\n";
		else for (auto& [set, v]: values)
			s << '\t' << static_cast<uint16_t>(set) << ": " << v << '\n';
	}

	settings_frame::settings_frame()
			: frame(frame_type_t::settings), ack(true) {
	}

	settings_frame::settings_frame(setting_values_t values)
		: frame(frame_type_t::settings), ack(false), values(std::move(values)) {
	}

	push_promise_frame::push_promise_frame(const uint32_t stream_id)
		: frame(frame_type_t::push_promise), headers_based_frame(stream_id) {
	}

	void push_promise_frame::print(std::ostream& s) const {
		s << "PUSH_PROMISE [" << stream_id << "]\n\tPromised stream id: " << promised_stream_id << '\n';
	}

	void ping_frame::print(std::ostream&) const {
	}

	go_away_frame::go_away_frame()
		: frame(frame_type_t::go_away) {
	}

	go_away_frame::go_away_frame(const uint32_t last_stream_id, const error_t e, const std::string_view additional_data)
		: frame(frame_type_t::go_away), last_stream_id(last_stream_id),
		error_code(e), additional_data(additional_data) {
	}

	void go_away_frame::print(std::ostream& s) const {
		s << "GOAWAY\n\tLast stream id: " << last_stream_id << "\n\tError: " << error_code << '\n';
		if (!additional_data.empty())
			s << "\tAdditional data: " << additional_data << '\n';
	}

	window_update_frame::window_update_frame(const uint32_t stream_id)
		: frame(frame_type_t::window_update), stream_frame(stream_id) {
	}

	void window_update_frame::print(std::ostream& s) const {
		s << "WINDOW_UPDATE [" << stream_id << "]\n\tIncrement: " << window_size_increment << '\n';
	}

}
