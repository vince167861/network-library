#include "http1_1/common.h"

constexpr auto
	literal_transfer_encoding = "transfer-encoding",
	literal_content_length = "content-length",
	literal_chunked = "chunked";

namespace network::http {

	std::expected<std::string, message_body_parse_error>
	read_message_content(stream_endpoint& __s, const fields& __f, const message_type __t) {
		if (__f.contains(literal_transfer_encoding)) {
			if (__f.at(literal_transfer_encoding).contains(literal_chunked)) {
				std::string __r;
				while (true) {
					const auto chunk_head = __s.read_line();
					if (!chunk_head.ends_with('\r') || __s.read() != '\n')
						return std::unexpected{message_body_parse_error::invalid_chunk_line_folding};
					const auto __c = std::find(chunk_head.begin(), chunk_head.end() - 1, ';').base();
					std::size_t chunk_len;
					if (std::from_chars(chunk_head.data(), __c, chunk_len, 16).ptr != __c)
						return std::unexpected{message_body_parse_error::invalid_chunk_size};
					if (chunk_len > 0) {
						const auto chunk_data = __s.read(chunk_len);
						__r.append(reinterpret_cast<const std::string&>(chunk_data));
					}
					if (__s.read(2) != reinterpret_cast<const std::uint8_t*>("\r\n"))
						return std::unexpected{message_body_parse_error::invalid_chunk_line_folding};
					if (chunk_len == 0)
						break;
				}
				return __r;
			}
			// other transfer encodings are not implemented
			if (__t == message_type::request)
				return std::unexpected{message_body_parse_error::cannot_determine_length};
		} else if (__f.contains(literal_content_length)) {
			auto& len = __f.at(literal_content_length);
			const auto __b = len.data(), __e = __b + len.size();
			std::size_t content_length;
			if (std::from_chars(__b, __e, content_length).ptr != __e)
				return std::unexpected{message_body_parse_error::invalid_content_length};
			const auto content = __s.read(content_length);
			return reinterpret_cast<const std::string&>(content);
		}
		switch (__t) {
			case message_type::request:
				return {};
			case message_type::response: {
				std::string __r;
				while (__s.connected()) {
					const auto b_str = __s.read(1024);
					__r.append(b_str.begin(), b_str.end());
				}
				return __r;
			}
			default:
				throw std::runtime_error("unexpected message_type");
		}
	}
}
