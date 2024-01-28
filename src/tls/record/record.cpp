#include "tls-record/record.h"

#include "tls-handshake/handshake.h"
#include "tls-context/context.h"
#include "tls-record/alert.h"

#include "utils.h"
#include <utility>
#include <algorithm>

namespace leaf::network::tls {

	record::record(const content_type_t type, const bool encrypted, context& context)
		: context_(context), type(type), encrypted(encrypted) {
	}

	std::string record::to_bytestring(std::endian) const {
		std::string str;
		for (auto it = messages.begin(), end = messages.end(); it != end; ) {
			const std::uint16_t length = std::min<std::ptrdiff_t>(std::distance(it, end), 1 << 14);
			std::string record;
			reverse_write(record, encrypted ? content_type_t::application_data : type);
			reverse_write(record, legacy_record_version);
			std::string plain_text{it, std::next(it, length)};
			if (encrypted) {
				reverse_write(plain_text, type);
				reverse_write(record, plain_text.size() + 16, 2);
				record += context_.encrypt(record, plain_text);
			} else {
				reverse_write(record, length, 2);
				record.append(it, std::next(it, length));
			}
			str += record;
			std::advance(it, length);
		}
		return str;
	}

	record record::extract(context& context) {
		const auto header = context.client_.read(
			sizeof(content_type_t) + sizeof(protocol_version_t) + sizeof(std::uint16_t));
		auto ptr = header.begin();
		content_type_t type;
		protocol_version_t version;
		std::uint16_t length;
		reverse_read(ptr, type);
		reverse_read(ptr, version);
		reverse_read(ptr, length);
		bool encrypted = false;

		auto fragment = context.client_.read(length);
		if (content_type_t::application_data == type) {
			auto plain_fragment = context.decrypt(header, fragment);
			const auto pos = plain_fragment.find_last_not_of('\0');
			type = static_cast<content_type_t>(plain_fragment[pos]);
			plain_fragment.erase(pos);
			fragment = std::move(plain_fragment);
			encrypted = true;
		}
		record record{type, encrypted, context};
		if (content_type_t::change_cipher_spec == type && fragment != "\1")
			throw alert::unexpected_message();
		record.messages = std::move(fragment);
		return record;
	}

	record record::construct(const content_type_t type,
		const bool encrypted, const message& message, context& context) {
		record record{type, encrypted, context};
		record.messages = message.to_bytestring();
		return record;
	}

}

std::format_context::iterator
std::formatter<leaf::network::tls::record>::format(const leaf::network::tls::record& record, format_context& ctx) const {
	return std::format_to(ctx.out(), "record [{}, payload size = {}]", record.type, record.messages.size());
}
