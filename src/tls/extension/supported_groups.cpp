#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	supported_groups::supported_groups(const std::set<named_group_t>& groups)
			: named_group_list{groups.begin(), groups.end()} {
	}

	supported_groups::supported_groups(const byte_string_view __f) {
		auto ptr = __f.begin();
		const auto end = std::next(ptr, read<std::uint16_t>(std::endian::big, ptr));
		if (end > __f.end())
			throw alert::decode_error("SupportedGroups.[size]");
		while (ptr < end)
			named_group_list.push_back(read<named_group_t>(std::endian::big, ptr));
	}

	void supported_groups::format(std::format_context::iterator& it, const std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("supported_groups:", it).out;
		if (named_group_list.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto g: named_group_list) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", g);
		}
	}

	supported_groups::operator byte_string() const {
		byte_string data;
		write(std::endian::big, data, named_group_list.size() * sizeof(named_group_t), 2);
		for (auto g: named_group_list)
			write(std::endian::big, data, g);
		byte_string out;
		write(std::endian::big, out, ext_type_t::supported_groups);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}
}
