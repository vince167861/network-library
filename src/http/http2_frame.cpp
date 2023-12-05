#include "http2/frame.h"

#include "http2/context.h"
#include "utils.h"

namespace leaf::network::http2 {

	frame::frame(const frame_type_t t)
		: type(t) {
	}

	std::shared_ptr<frame> frame::parse(stream& source) {
		auto header = source.read(4);
		auto ptr = header.begin();
		uint32_t content_length;
		frame_type_t frame_type;
		reverse_read<3>(ptr, content_length);
		reverse_read(ptr, frame_type);

		const auto content = source.read(5 + content_length);
		switch (frame_type) {
			case frame_type_t::settings:
				return std::make_shared<settings_frame>(content);
			case frame_type_t::data:
				return std::make_shared<data_frame>(content);
			case frame_type_t::window_update:
				return std::make_shared<window_update_frame>(content);
			case frame_type_t::rst_stream:
				return std::make_shared<rst_stream>(content);
			case frame_type_t::push_promise:
				return std::make_shared<push_promise_frame>(content);
			case frame_type_t::continuation:
				return std::make_shared<continuation_frame>(content);
			case frame_type_t::headers:
				return std::make_shared<headers_frame>(content);
			default:
				throw std::exception{};
		}
	}

	std::ostream& operator<<(std::ostream& s, const frame& f) {
		f.print(s);
		return s;
	}

	data_frame::data_frame(const uint32_t stream_id)
		: frame(frame_type_t::data), stream_id(stream_id) {
	}

	data_frame::data_frame(const std::string_view source) // NOLINT(*-pro-type-member-init)
			: frame(frame_type_t::data) {
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		const bool padded = flags & 1 << 3;
		end_stream = flags & 1;
		reverse_read(ptr, stream_id);
		auto end = source.end();
		if (padded) {
			uint8_t pl;
			reverse_read(ptr, pl);
			padding = pl;
			std::advance(end, -pl);
		}
		data = {ptr, end};
	}

	void data_frame::send(stream& out) const {
		reverse_write(out, data.length(), 3);
		reverse_write(out, frame_type_t::data);
		reverse_write<uint8_t>(out, end_stream);
		reverse_write(out, stream_id);
		out.write(data);
	}

	void data_frame::print(std::ostream& s) const {
		s << "DATA on stream " << stream_id << "\n\tLength: " << data.length() << '\n';
	}

	headers_info_frame::headers_info_frame(const frame_type_t t, const uint32_t stream_id)
		: frame(t), stream_id(stream_id) {
	}

	headers_frame::headers_frame(const uint32_t stream_id)
		: headers_info_frame(frame_type_t::headers, stream_id) {
	}

	headers_frame::headers_frame(const std::string_view source) // NOLINT(*-pro-type-member-init)
		: headers_info_frame(frame_type_t::headers, 0) {
		uint8_t pad_length = 0;
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		const bool has_priority = flags & 1 << 5, has_padding = flags & 1 << 3;
		end_headers = flags & 1 << 2, end_stream = flags & 1;
		reverse_read(ptr, stream_id);
		if (has_padding) {
			reverse_read(ptr, pad_length);
			padding = pad_length;
		}
		if (has_priority) {
			uint32_t dependency;
			uint8_t weight;
			reverse_read(ptr, dependency);
			reverse_read(ptr, weight);
			priority.emplace(dependency & 1 << 31, dependency, weight);
		}
		field_block_fragments = {ptr, std::next(source.end(), -pad_length)};
	}

	void headers_frame::send(stream& out) const {
		reverse_write(out, field_block_fragments.length(), 3);
		reverse_write(out, frame_type_t::headers);
		reverse_write<uint8_t>(out,
			(priority.has_value() ? 1 << 5 : 0)
			| (padding.has_value() ? 1 << 3 : 0)
			| end_headers << 2
			| end_stream);
		reverse_write(out, stream_id);
		if (priority.has_value()) {
			const auto& [exclusive, dependency, weight] = priority.value();
			reverse_write<uint32_t>(out, exclusive << 31 | dependency);
			reverse_write(out, weight);
		}
		out.write(field_block_fragments);
	}

	void headers_frame::print(std::ostream& s) const {
		s << "HEADERS on stream " << stream_id << "\n";
	}

	priority_frame::priority_frame(const uint32_t stream_id)
		: frame(frame_type_t::priority), stream_id(stream_id) {
	}

	void priority_frame::send(stream& out) const {
		reverse_write<uint32_t>(out, 5, 3);
		reverse_write(out, frame_type_t::priority);
		reverse_write<uint8_t>(out, 0);
		reverse_write(out, stream_id);
		reverse_write<uint32_t>(out, stream_dependence | exclusive << 31);
		reverse_write(out, weight);
	}

	void priority_frame::print(std::ostream& s) const {
		s << "Priority on stream " << stream_id << '\n';
	}

	rst_stream::rst_stream(const std::string_view source) // NOLINT(*-pro-type-member-init)
		: frame(frame_type_t::rst_stream) {
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		reverse_read(ptr, stream_id);
		reverse_read(ptr, error_code);
	}

	rst_stream::rst_stream(const uint32_t stream_id, const error_t err)
		: frame(frame_type_t::rst_stream), stream_id(stream_id), error_code(err) {
	}

	void rst_stream::send(stream& out) const {
		reverse_write<uint32_t>(out, 4, 3);
		reverse_write(out, frame_type_t::rst_stream);
		reverse_write<uint8_t>(out, 0);
		reverse_write(out, stream_id);
		reverse_write(out, error_code);
	}

	void rst_stream::print(std::ostream& s) const {
		s << "Reset Stream @ " << stream_id
			<< "\n\tError: " << error_code << '\n';
	}

	void settings_frame::send(stream& out) const {
		std::string data;
		for (auto& [s, v]: values) {
			reverse_write(data, s);
			reverse_write(data, v);
		}
		reverse_write<uint32_t>(out, data.size(), 3);
		reverse_write(out, frame_type_t::settings);
		reverse_write<uint8_t>(out, ack ? 1 : 0);
		reverse_write<uint32_t>(out, 0);
		out.write(data);
	}

	void settings_frame::print(std::ostream& s) const {
		s << "SETTINGS\n";
		if (ack)
			s << "\t(ACK)\n";
		else if (values.empty())
			s << "\t(empty)\n";
		else for (auto& [set, v]: values)
			s << '\t' << static_cast<uint16_t>(set) << ": " << v << '\n';
	}

	settings_frame::settings_frame()
			: frame(frame_type_t::settings), ack(true) {
	}

	settings_frame::settings_frame(const std::string_view source)
			: frame(frame_type_t::settings) {
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		ack = flags & 1;
		uint32_t stream_id;
		reverse_read(ptr, stream_id);
		if (stream_id || ack && ptr != source.end())
			throw std::exception{};
		while (ptr != source.end()) {
			settings_t s;
			uint32_t v;
			reverse_read(ptr, s);
			reverse_read(ptr, v);
			values.emplace_back(s, v);
		}
	}

	settings_frame::settings_frame(std::list<std::pair<settings_t, uint32_t>> values)
		: frame(frame_type_t::settings), ack(false), values(std::move(values)) {
	}

	push_promise_frame::push_promise_frame(const std::string_view source) // NOLINT(*-pro-type-member-init)
		: frame(frame_type_t::push_promise) {
		uint8_t padding_length = 0;
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		reverse_read(ptr, stream_id);
		if (flags & 1 << 3)
			reverse_read(ptr, padding_length);
		reverse_read(ptr, promised_stream_id);
		field_block_fragments = {ptr, std::next(source.end(), -padding_length)};
	}

	void push_promise_frame::send(stream& out) const {
		reverse_write(out, field_block_fragments.length(), 3);
		reverse_write(out, frame_type_t::push_promise);
		reverse_write<uint8_t>(out, 0);
		reverse_write(out, stream_id);
		reverse_write(out, promised_stream_id);
		out.write(field_block_fragments);
	}

	void push_promise_frame::print(std::ostream& s) const {
		s << "Push Promise @ " << stream_id << "\n\tNew stream ID: " << promised_stream_id << '\n';
	}

	void ping_frame::send(stream& out) const {
		reverse_write<uint32_t>(out, 8, 3);
		reverse_write(out, frame_type_t::ping);
		reverse_write<uint8_t>(out, ack ? 1 : 0);
		reverse_write<uint32_t>(out, 0);
		reverse_write(out, data);
	}

	void ping_frame::print(std::ostream&) const {
	}

	void go_away_frame::send(stream& out) const {
		reverse_write(out, 8 + additional_data.length(), 3);
		reverse_write(out, frame_type_t::go_away);
		reverse_write<uint8_t>(out, 0);
		reverse_write<uint32_t>(out, 0);
		reverse_write(out, last_stream_id);
		reverse_write(out, error_code);
		out.write(additional_data);
	}

	window_update_frame::window_update_frame(const std::string_view source) // NOLINT(*-pro-type-member-init)
		: frame(frame_type_t::window_update) {
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		reverse_read(ptr, stream_id);
		reverse_read(ptr, window_size_increment);
	}

	void window_update_frame::send(stream& out) const {
		reverse_write(out, 4, 3);
		reverse_write(out, frame_type_t::window_update);
		reverse_write<uint8_t>(out, 0);
		reverse_write(out, stream_id);
		reverse_write(out, window_size_increment);
	}

	void window_update_frame::print(std::ostream& s) const {
		s << "WINDOW_UPDATE on stream " << stream_id << "\n\tIncrement: " << window_size_increment << '\n';
	}

	continuation_frame::continuation_frame(const uint32_t stream_id)
		: headers_info_frame(frame_type_t::continuation, stream_id) {
	}

	continuation_frame::continuation_frame(const std::string_view source) // NOLINT(*-pro-type-member-init)
		: headers_info_frame(frame_type_t::continuation, 0) {
		auto ptr = source.begin();
		uint8_t flags;
		reverse_read(ptr, flags);
		end_headers = flags & 1 << 2;
		reverse_read(ptr, stream_id);
		field_block_fragments = {ptr, source.end()};
	}

	void continuation_frame::send(stream& out) const {
		reverse_write(out, field_block_fragments.length(), 3);
		reverse_write(out, frame_type_t::continuation);
		reverse_write<uint8_t>(out, end_headers << 2);
		reverse_write(out, stream_id);
		out.write(field_block_fragments);
	}

	void continuation_frame::print(std::ostream& s) const {
		s << "Continuation on stream " << stream_id << '\n';
		if (end_headers)
			s << "\t+ END_HEADERS\n";
	}
}
