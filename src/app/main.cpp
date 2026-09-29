#include "app/commands.h"

#include "core/utf.h"
#include "core/util.h"

#include <algorithm>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

std::vector<std::string> ArgsFromCommandLine() {
    std::vector<std::string> args;
#ifdef _WIN32
    int argc = 0;
    LPWSTR* argvw = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 0; i < argc; ++i) {
        args.push_back(st::WideToUtf8(argvw[i]));
    }
    LocalFree(argvw);
#endif
    return args;
}

#ifdef _WIN32
void EnsureConsole() {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }
    FILE* stream = nullptr;
#ifdef _MSC_VER
    freopen_s(&stream, "CONOUT$", "w", stdout);
    freopen_s(&stream, "CONOUT$", "w", stderr);
    freopen_s(&stream, "CONIN$", "r", stdin);
#else
    stream = freopen("CONOUT$", "w", stdout);
    stream = freopen("CONOUT$", "w", stderr);
    stream = freopen("CONIN$", "r", stdin);
#endif
}
#endif

int Dispatch(std::vector<std::string> args) {
    std::string verb;
    bool resume = false;
    std::string control;
    std::vector<char*> argv;
    std::vector<std::string> storage = args;
    for (auto& s : storage) {
        argv.push_back(s.data());
    }
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--install") {
            verb = "install";
        } else if (args[i] == "--resume") {
            resume = true;
        } else if (args[i] == "--uninstall") {
            verb = "uninstall";
        } else if (args[i] == "--update") {
            verb = "update";
        } else if (args[i] == "--diagnose") {
            verb = "diagnose";
        } else if (args[i] == "--diagnose-startup") {
            verb = "startup";
        } else if (args[i] == "--self-test") {
            verb = "selftest";
        } else if (args[i] == "--control" && i + 1 < args.size()) {
            verb = "control";
            control = args[++i];
        } else if (args[i] == "--gui") {
            verb = "gui";
        }
    }
    if (verb == "install") {
        return st::RunInstall(resume);
    }
    if (verb == "uninstall") {
        return st::RunUninstall();
    }
    if (verb == "update") {
        return st::RunUpdate();
    }
    if (verb == "diagnose") {
        return st::RunDiagnose();
    }
    if (verb == "startup") {
        return st::RunStartupProbe();
    }
    if (verb == "selftest") {
#ifdef _WIN32
        EnsureConsole();
#endif
        return st::RunSelfTest(static_cast<int>(argv.size()), argv.data());
    }
    if (verb == "control") {
        return st::RunControl(control);
    }
#ifdef _WIN32
    if (!st::IsAdministrator()) {
        st::ElevateAndRerun(L"");
        return 0;
    }
    return st::RunGui();
#else
    return st::RunSelfTest(static_cast<int>(argv.size()), argv.data());
#endif
}

}  // namespace

#ifdef _WIN32

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    return Dispatch(ArgsFromCommandLine());
}

#else

int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return Dispatch(args);
}

#endif
