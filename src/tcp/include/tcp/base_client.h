#pragma once

#include "shared/client.h"

namespace leaf::network::tcp {


	class api_failed final: public std::exception {
		std::string info;

	public:
		const char* what() const noexcept override {
			return info.c_str();
		}

		api_failed(const std::string_view func_name, const int result, const std::string_view desc = "") {
			info = func_name;
			info += ": ";
			info += std::to_string(result);
			if (!desc.empty()) {
				info += ": ";
				info += desc;
			}
		}
	};

	class base_client: public client {
	};


	class connection_closed_error final: public std::exception {
	};

}
