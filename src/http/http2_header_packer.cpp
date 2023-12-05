#include "http2/header_packer.h"

#include "utils.h"

#include <ranges>

namespace leaf::network::http2 {

	const std::list<std::pair<std::string, std::string>>
	static_header_pairs {
		{"", ""},
		{":authority", ""},
		{":method", "GET"},
		{":method", "POST"},
		{":path", "/"},
		{":path", "/index.html"},
		{":scheme", "http"},
		{":scheme", "https"},
		{":status", "200"},
		{":status", "204"},
		{":status", "206"},
		{":status", "304"},
		{":status", "400"},
		{":status", "404"},
		{":status", "500"},
		{"accept-charset", ""},
		{"accept-encoding", "gzip, deflate"},
		{"accept-language", ""},
		{"accept-ranges", ""},
		{"accept", ""},
		{"access-control-allow-origin", ""},
		{"age", ""},
		{"allow", ""},
		{"authorization", ""},
		{"cache-control", ""},
		{"content-disposition", ""},
		{"content-encoding", ""},
		{"content-language", ""},
		{"content-length", ""},
		{"content-location", ""},
		{"content-range", ""},
		{"content-type", ""},
		{"cookie", ""},
		{"date", ""},
		{"etag", ""},
		{"expect", ""},
		{"expires", ""},
		{"from", ""},
		{"host", ""},
		{"if-match", ""},
		{"if-modified-since", ""},
		{"if-none-match", ""},
		{"if-range", ""},
		{"if-unmodified-since", ""},
		{"last-modified", ""},
		{"link", ""},
		{"location", ""},
		{"max-forwards", ""},
		{"proxy-authenticate", ""},
		{"proxy-authorization", ""},
		{"range", ""},
		{"referer", ""},
		{"refresh", ""},
		{"retry-after", ""},
		{"server", ""},
		{"set-cookie", ""},
		{"strict-transport-security", ""},
		{"transfer-encoding", ""},
		{"user-agent", ""},
		{"vary", ""},
		{"via", ""},
		{"www-authenticate", ""},
	};

	void write_integer(std::string& dest, const uint8_t prefix_size, const uint8_t prefix_value, const uint64_t value) {
		if (prefix_size > 8 or prefix_size < 1)
			throw std::exception{};
		if (value < 1 << prefix_size)
			dest.push_back(static_cast<char>(prefix_value << prefix_size | value));
		else {
			dest.push_back(static_cast<char>(prefix_value << prefix_size | ~0 >> 8 - prefix_size));
			constexpr std::size_t bytes = sizeof value * 8 / 7;
			for (std::size_t i = 0; i < bytes; ++i) {
				const bool last = value >> 7 * (i + 1) == 0;
				dest.push_back(static_cast<char>(value >> 7 * i | (last ? 0 : 1 << 7)));
				if (last) break;
			}
		}
	}

	void read_integer(std::string_view::const_iterator& ptr, const uint8_t prefix_size, uint8_t& prefix_value, uint64_t& value) {
		value = 0;
		uint8_t prefix = *ptr++, mask = ~(~0 << prefix_size);
		prefix_value = prefix >> prefix_size;
		if ((prefix & mask) == mask)
			for (uint8_t i = 0;;) {
				value += *ptr << 7 * i;
				if ((*ptr++ & 1 << 7) == 0)
					break;
			}
		else
			value = prefix & mask;
	}

	void header_packer::shrink_() {
		if (dynamic_header_pairs.size() > dynamic_table_size_)
			dynamic_header_pairs.resize(dynamic_table_size_);
	}

	void header_packer::emplace_front_(std::string name, std::string value) {
		dynamic_header_pairs.emplace_front(std::move(name), std::move(value));
		shrink_();
	}

	std::string header_packer::encode(const header_list_t& headers) {
		std::string ret;
		for (auto& pair: headers) {
			auto& [name, value] = pair;
			uint64_t index = 0;
			if (auto iter = std::ranges::find(static_header_pairs, pair); iter != static_header_pairs.end())
				index = std::distance(static_header_pairs.begin(), iter);
			else if (auto iter = std::ranges::find(dynamic_header_pairs, pair); iter != dynamic_header_pairs.end())
				index = std::distance(dynamic_header_pairs.begin(), iter) + 62;
			if (index) {
				write_integer(ret, 7, 1, index);
				continue;
			}
			auto&& static_keys = std::views::keys(static_header_pairs);
			auto&& dynamic_keys = std::views::keys(dynamic_header_pairs);
			if (auto iter = std::ranges::find(static_keys, pair.first); iter != static_keys.end())
				index = std::distance(static_keys.begin(), iter);
			else if (auto iter = std::ranges::find(dynamic_keys, pair.first); iter != dynamic_keys.end())
				index = std::distance(dynamic_keys.begin(), iter) + 62;
			write_integer(ret, 6, 1, index);
			if (!index) {
				write_integer(ret, 7, 0, name.size());
				ret += name;
			}
			write_integer(ret, 7, 0, value.size());
			ret += value;
			emplace_front_(name, value);
		}
		return ret;
	}

	header_list_t header_packer::decode(const std::string_view source) {
		header_list_t members;
		uint8_t unused;
		uint64_t value;
		auto ptr = source.begin();
		if (const uint8_t header = *ptr; header & 1 << 7) {
			read_integer(ptr, 7, unused, value);
			std::pair<std::string, std::string> pair;
			if (value < 62)
				pair = *std::next(static_header_pairs.begin(), value);
			else
				pair = *std::next(dynamic_header_pairs.begin(), value - 62);
			members.push_back(std::move(pair));
		} else if (header & 1 << 5) {
			read_integer(ptr, 5, unused, value);
			dynamic_table_size_ = value;
			shrink_();
		} else {
			if (header & 1 << 6)
				read_integer(ptr, 6, unused, value);
			else
				read_integer(ptr, 4, unused, value);
			/* TODO: never-indexed(0001) and without-indexed(0000) is processed identically */
			std::string name;
			if (value == 0) {
				read_integer(ptr, 7, unused, value);
				auto begin = ptr;
				std::advance(ptr, value);
				name = {begin, ptr};
			} else if (value < 62)
				name = std::next(static_header_pairs.begin(), value)->first;
			else
				name = std::next(dynamic_header_pairs.begin(), value - 62)->first;
			read_integer(ptr, 7, unused, value);
			const auto begin = ptr;
			std::advance(ptr, value);
			members.emplace_back(std::move(name), std::string{begin, ptr});
		}
		return members;
	}
}
