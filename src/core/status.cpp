#include "status.h"

#include "constants.h"
#include "json_io.h"
#include "paths.h"
#include "util.h"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace st {

nlohmann::json Status::ToJson() const {
    nlohmann::json json = {{"state", state},
                           {"detail", detail},
                           {"updated_utc", updated_utc},
                           {"policy_version", policy_version},
                           {"update_error", update_error}};
    if (engine_pid) {
        json["engine_pid"] = engine_pid;
    } else {
        json["engine_pid"] = nullptr;
    }
    return json;
}

Result<Status> Status::FromJson(const nlohmann::json& value) {
    try {
        Status status;
        status.state = value.value("state", "unknown");
        status.detail = value.value("detail", "");
        status.updated_utc = value.value("updated_utc", "");
        status.policy_version = value.value("policy_version", 0);
        status.update_error = value.value("update_error", "");
        if (!value["engine_pid"].is_null()) {
            status.engine_pid = value.value("engine_pid", 0ul);
        }
        return Result<Status>::ok(std::move(status));
    } catch (const std::exception& ex) {
        return Result<Status>::fail(std::string("Invalid status: ") + ex.what());
    }
}

Error WriteStatus(const Status& status) { return WriteJsonAtomic(StatusPath(), status.ToJson()); }

Result<Status> ReadStatus() {
    auto json = ReadJsonFile(StatusPath());
    if (!json) {
        return Result<Status>::fail(json.error.message);
    }
    return Status::FromJson(json.value);
}

bool StatusIsStale(const Status& status) {
    if (status.updated_utc.empty()) {
        return true;
    }
    std::tm tm{};
    std::istringstream in(status.updated_utc);
    in >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (in.fail()) {
        return true;
    }
#ifdef _WIN32
    const auto utc = _mkgmtime(&tm);
#else
    const auto utc = timegm(&tm);
#endif
    const auto now = std::time(nullptr);
    return now - utc > kStatusStaleSeconds;
}

}  // namespace st
