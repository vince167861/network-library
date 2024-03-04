#pragma once
#include "stream_endpoint.h"
#include <stdexcept>
#include <format>

#ifdef PLATFORM_Linux

#include <netdb.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
#define closesocket close

#endif

namespace network::tcp {

#ifdef PLATFORM_Windows
	class wsa_control {
		static inline std::size_t wsa_instances = 0;

	public:
		static void acquire() {
			if (!wsa_instances++) {
				WSAData data;
				if (WSAStartup(MAKEWORD(2, 2), &data))
					throw std::runtime_error{"WSAStartup(0x0202)"};
			}
		}

		static void release() {
			if (!--wsa_instances)
				WSACleanup();
		}
	};
#endif


	struct endpoint: virtual stream_endpoint {

		endpoint(socket_t socket = invalid_socket)
			: socket_(socket) {
#ifdef PLATFORM_Windows
			wsa_control::acquire();
#endif
		}

		bool connected() const override {
			return socket_ != invalid_socket;
		}

		std::uint8_t read() override {
			if (socket_ == invalid_socket)
				throw std::runtime_error("tcp not established");
			char c;
			const auto count = recv(socket_, &c, 1, 0);
			if (count < 0)
				handle_error_("recv");
			if (count == 0) {
				close();
				throw std::runtime_error("tcp closed");
			}
			return c;
		}

		byte_string read(std::size_t size) override {
			if (socket_ == invalid_socket)
				throw std::runtime_error("tcp not established");
			byte_string read_data;
			while (read_data.size() < size) {
				std::uint8_t buffer[1024];
				const auto count = recv(socket_, reinterpret_cast<char*>(buffer), std::min<int>(size - read_data.size(), 1024), 0);
				if (count < 0)
					handle_error_("recv");
				if (count == 0) {
					close();
					break;
				}
				read_data.append(buffer, count);
			}
			return read_data;
		}

		void write(const byte_string_view buffer) override {
			if (socket_ == invalid_socket)
				throw std::runtime_error("tcp not established");
			const auto result = send(socket_, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);
			if (result < 0)
				handle_error_("send");
			if (result == 0 && !buffer.empty())
				close();
		}

		void write(const std::uint8_t octet) override {
			write({&octet, 1});
		}

		void finish() override {
			if (socket_ == invalid_socket)
				throw std::runtime_error("tcp not established");
			if (shutdown(socket_, SHUT_WR))
				handle_error_("shutdown(write)");
		}

		void close() override {
			if (socket_ != invalid_socket) {
				shutdown(socket_, SHUT_RDWR);
				::closesocket(socket_);
				socket_ = invalid_socket;
			}
		}

		~endpoint() override {
			::closesocket(socket_);
#ifdef PLATFORM_Windows
			wsa_control::release();
#endif
		}

	protected:
		socket_t socket_;

		[[noreturn]] void handle_error_(std::string_view function) {
			switch (const int error_no = last_error) {
				case error_conn_aborted:
					close();
				throw std::runtime_error("tcp closed");
				case error_conn_reset:
					close();
				throw std::runtime_error("tcp connection reset");
				case error_conn_refused:
					close();
				throw std::runtime_error("tcp connection refused");
				default:
					throw std::runtime_error(std::format("{} gives error {}", function, error_no));
			}
		}
	};
}
