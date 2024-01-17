#include "http2/response.h"

std::format_context::iterator
std::formatter<leaf::network::http2::response>::format(
	const leaf::network::http2::response& response, std::format_context& context) const {
	auto it = std::format_to(context.out(), "Response ({})", response.status);
	if (response.headers.empty())
		it = std::ranges::copy("\n\t(No header)", it).out;
	else for (auto& [key, value]: response.headers)
		it = std::format_to(it, "\n\t{}: {}", key, value);
	return std::format_to(it, "\n{}", response.body);
}
