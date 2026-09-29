#pragma once

#include <string>
#include <utility>

namespace st {

struct Error {
    std::string message;
    explicit operator bool() const { return !message.empty(); }
};

inline Error Ok() { return {}; }
inline Error Fail(std::string message) { return Error{std::move(message)}; }

template <typename T>
struct Result {
    T value{};
    Error error;
    explicit operator bool() const { return !error; }
    T* operator->() { return &value; }
    const T* operator->() const { return &value; }
    static Result ok(T value) { return Result{std::move(value), {}}; }
    static Result fail(std::string message) {
        Result result;
        result.error.message = std::move(message);
        return result;
    }
};

}  // namespace st
