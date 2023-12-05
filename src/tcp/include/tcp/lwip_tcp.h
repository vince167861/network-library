#pragma once

#include "base_client.h"

#include <lwip/sockets.h>
#include <lwip/netdb.h>

namespace leaf::network::tcp {


	class api_failed: public std::exception {
		std::string info;

	public:
		const char* what() const noexcept override {
			return info.c_str();
		}

		api_failed(const std::string_view func_name, const int result) {
			info = func_name;
			info += std::to_string(result);
		}
	};


	class client: public base_client {

		bool connected_ = false;

		int socket_ = ~0;

	public:
		client() = default;

		bool connect(std::string_view host, uint16_t port) override {
			addrinfo addr_hint { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP };
			addrinfo* result_addr = nullptr;
			{
				const std::string host_copy(host);
				const auto port_string = std::to_string(port);

				if (const int result = getaddrinfo(host_copy.c_str(), port_string.c_str(), &addr_hint, &result_addr); result)
					throw api_failed{"getaddrinfo", result};
			}

			for (auto ptr = result_addr; ptr; ptr = ptr->ai_next) {
				socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
				if (socket_ < 0)
					continue;
				if (const int result = ::connect(socket_, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)); result) {
					close();
					continue;
				}
				break;
			}
			freeaddrinfo(result_addr);
			return connected_ = socket_ >= 0;
		}

		bool connected() const override {
			return connected_;
		}

		std::string read(std::size_t size) override {
			if (!connected_)
				throw connection_closed_error{};
			std::string read_data;
			while (read_data.size() < size) {
				char buffer[50];
				auto count = recv(socket_, buffer, std::min<int>(size - read_data.length(), 50), 0);
				if (count < 0) {
					switch (const int error_no = errno) {
						case 106:
							connected_ = false;
						throw connection_closed_error{};
						default:
							throw api_failed{"recv", error_no};
					}
				}
				if (count == 0) {
					connected_ = false;
					break;
				}
				read_data.append(buffer, count);
			}
			return read_data;
		}

		std::size_t write(std::string_view buffer) override {
			if (!connected_)
				return 0;
			auto const result = send(socket_, buffer.data(), buffer.size(), 0);
			if (result < 0) {
				close();
				throw api_failed{"send", errno};
			}
			return result;
		}

		bool finish() override {
			return connected_ && shutdown(socket_, SHUT_WR) < 0;
		}

		void close() override {
			::closesocket(socket_);
			socket_ = ~0;
			connected_ = false;
		}

		std::size_t available() override {
			unsigned long avail = 0;
			if (const auto result = ioctl(socket_, FIONREAD, &avail); result)
				throw api_failed{"ioctl(., FIONREAD, .)", errno};
			return avail;
		}
	};
}
