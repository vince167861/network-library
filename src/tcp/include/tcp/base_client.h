#pragma once

#include "basic_client.h"

#include <format>

namespace leaf::network::tcp {


	class api_failed final: public std::exception {
		std::string info;

	public:
		const char* what() const noexcept override {
			return info.c_str();
		}

		api_failed(const std::string_view func_name, const int result, const std::string_view desc = "") {
			info = std::format("{}: {}", func_name, result);
			if (!desc.empty())
				info += std::format(": {}", desc);
		}
	};

	class base_client: public client {
	};


	class connection_closed_error final: public std::exception {
	};

}
