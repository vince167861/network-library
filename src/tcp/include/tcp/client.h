#pragma once

#include "basic_client.h"

#include <stdexcept>
#include <string>
#include <format>

#ifdef PLATFORM_Linux

#include <netdb.h>
#include <sys/ioctl.h>

#elifdef PLATFORM_Generic

#include <lwip/sockets.h>
#include <lwip/netdb.h>

#endif

#ifdef PLATFORM_Windows

#include <ws2tcpip.h>
#define socket_t SOCKET
#define invalid_socket INVALID_SOCKET
#define last_error WSAGetLastError()
#define error_conn_aborted WSAECONNABORTED
#define error_conn_reset WSAECONNRESET
#define error_conn_refused WSAECONNREFUSED
#define ioctl ioctlsocket
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH

#else

#define socket_t int
#define invalid_socket -1
#define last_error errno
#define error_conn_aborted ECONNABORTED
#define error_conn_reset ECONNRESET
#define error_conn_refused ECONNREFUSED

#endif

namespace leaf::network::tcp {

	const std::runtime_error closed{"Connection closed."};

	class client: public network::client {

		static std::size_t instances;

		bool connected_ = false;

		socket_t socket_ = invalid_socket;

		[[noreturn]] void handle_error_(std::string_view function) {
			switch (const int error_no = last_error) {
				case error_conn_aborted:
					connected_ = false;
					throw closed;
				case error_conn_reset:
					connected_ = false;
					throw std::runtime_error{"Connection reset."};
				case error_conn_refused:
					connected_ = false;
					throw std::runtime_error{"Connection refused."};
				default:
					throw std::runtime_error{std::format("{} gives error {}", function, error_no)};
			}
		}

	public:
		client() {
			++instances;
#ifdef PLATFORM_Windows
			WSAData data;
		if (WSAStartup(MAKEWORD(2, 2), &data))
			handle_error_("WSAStartup(0x0202)");
#endif
		}

		bool connect(std::string_view host, std::uint16_t port) override {
			addrinfo
					addr_hint{.ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP},
					* result_addr = nullptr;
			{
				const std::string host_copy(host);
				const auto port_string = std::to_string(port);

				if (const int result = getaddrinfo(host_copy.c_str(), port_string.c_str(), &addr_hint, &result_addr))
					handle_error_("getaddrinfo");
			}

			for (auto ptr = result_addr; ptr; ptr = ptr->ai_next) {
				socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
				if (socket_ < 0)
					continue;
				if (const int result = ::connect(socket_, ptr->ai_addr, ptr->ai_addrlen); result) {
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
				throw closed;
			std::string read_data;
			while (read_data.size() < size) {
				char buffer[1024];
				const auto count = recv(socket_, buffer, std::min<int>(size - read_data.size(), 1024), 0);
				if (count < 0)
					handle_error_("recv");
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
				throw closed;
			const auto result = send(socket_, buffer.data(), buffer.size(), 0);
			if (result < 0)
				handle_error_("send");
			return result;
		}

		std::size_t available() override {
			unsigned long avail = 0;
			if (const auto result = ioctl(socket_, FIONREAD, &avail); result < 0)
				handle_error_("ioctl(FIONREAD)");
			return avail;
		}

		bool finish() override {
			return connected_ && shutdown(socket_, SHUT_WR) < 0;
		}

		void close() override {
			shutdown(socket_, SHUT_RDWR);
			socket_ = invalid_socket;
			connected_ = false;
		}

		~client() {
			--instances;
#ifdef PLATFORM_Windows
			if (!instances)
			WSACleanup();
#endif
		}
	};

	std::size_t client::instances = 0;
}
