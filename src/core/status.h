#pragma once

#include "error.h"

#include <nlohmann/json.hpp>

#include <string>

namespace st {

struct Status {
    std::string state = "unknown";
    std::string detail;
    std::string updated_utc;
    int policy_version = 0;
    std::string update_error;
    unsigned long engine_pid = 0;

    nlohmann::json ToJson() const;
    static Result<Status> FromJson(const nlohmann::json& value);
};

Error WriteStatus(const Status& status);
Result<Status> ReadStatus();
bool StatusIsStale(const Status& status);

}  // namespace st
