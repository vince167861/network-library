#pragma once

#include <coroutine>
#include <future>

namespace leaf {

	template<class T>
	struct task_promise;

	template<class T>
	using task_handle_t = std::coroutine_handle<task_promise<T>>;

	template<class T>
	struct task_promise: std::promise<T> {

		template<class V>
		void return_value(V&& v) {
			this->set_value(std::forward<V&&>(v));
		}

		auto get_return_object() {
			return task_handle_t<T>::from_promise(*this);
		}

		std::suspend_always initial_suspend() {
			return {};
		}

		std::suspend_always final_suspend() noexcept {
			return {};
		}

		void unhandled_exception() {
			this->set_exception(std::make_exception_ptr(std::exception{}));
		}
	};

	template<>
	struct task_promise<void>: std::promise<void> {

		void return_void() {
			this->set_value();
		}

		auto get_return_object() {
			return task_handle_t<void>::from_promise(*this);
		}

		std::suspend_always initial_suspend() {
			return {};
		}

		std::suspend_always final_suspend() noexcept {
			return {};
		}

		void unhandled_exception() {
			this->set_exception(std::make_exception_ptr(std::exception{}));
		}
	};


	template<class T>
	struct task: task_handle_t<T> {
		using promise_type = task_promise<T>;

		task(std::coroutine_handle<promise_type> handle)
			: task_handle_t<T>(handle) {
		}

		auto get_future() const {
			return this->promise().get_future();
		}
	};
}
