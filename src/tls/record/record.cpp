#include "tls-record/record.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	record::record(const content_type_t type, opt_cipher cipher)
		: type(type), cipher_(cipher) {
	}

	record record::extract(istream& __s, traffic_secret_manager& cipher) {
		const auto header = __s.read(sizeof(content_type_t) + sizeof(protocol_version_t) + sizeof(std::uint16_t));
		auto it = header.begin();
		auto type = read<content_type_t>(std::endian::big, it);
		const auto version = read<protocol_version_t>(std::endian::big, it);
		const auto length = read<std::uint16_t>(std::endian::big, it);
		bool encrypted = false;

		auto fragment = __s.read(length);
		if (content_type_t::application_data == type) {
			auto plain_fragment = cipher.decrypt(header, fragment);
			const auto pos = plain_fragment.find_last_not_of(static_cast<std::uint8_t>(0));
			type = static_cast<content_type_t>(plain_fragment[pos]);
			plain_fragment.erase(pos);
			fragment = std::move(plain_fragment);
			encrypted = true;
		}
		record record(type, encrypted ? cipher : opt_cipher{});
		if (content_type_t::change_cipher_spec == type && std::ranges::equal(fragment, "\1"))
			throw alert::unexpected_message();
		record.version = version;
		record.messages = std::move(fragment);
		return record;
	}

	record record::construct(const content_type_t type, opt_cipher cipher, const message& message) {
		record record{type, cipher};
		record.messages = message;
		return record;
	}

	record::operator byte_string() const {
		byte_string str;
		for (auto it = messages.begin(), end = messages.end(); it != end; ) {
			const std::uint16_t length = std::min<std::ptrdiff_t>(std::distance(it, end), 1 << 14);
			byte_string record;
			write(std::endian::big, record, cipher_ ? content_type_t::application_data : type);
			write(std::endian::big, record, version);
			byte_string plain_text{it, std::next(it, length)};
			if (cipher_) {
				write(std::endian::big, plain_text, type);
				write(std::endian::big, record, plain_text.size() + 16, 2);
				record += cipher_.value().get().encrypt(record, plain_text);
			} else {
				write(std::endian::big, record, length, 2);
				record.append(it, std::next(it, length));
			}
			str += record;
			std::advance(it, length);
		}
		return str;
	}

}

std::format_context::iterator
std::formatter<leaf::network::tls::record>::format(const leaf::network::tls::record& record, format_context& ctx) const {
	return std::format_to(ctx.out(), "record [{}, payload size = {}]", record.type, record.messages.size());
}
