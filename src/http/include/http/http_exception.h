#pragma once
#include <exception>

namespace leaf {

	class http_field_parse_error: public std::exception {
	public:
		const char* what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override {
			return "Invalid HTTP fields";
		}
	};


	class http_response_parse_error: public std::exception {
	public:
		const char* what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override {
			return "Invalid HTTP response received from server";
		}
	};

}
