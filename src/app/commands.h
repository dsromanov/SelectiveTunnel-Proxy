#pragma once

#include <string>

namespace st {

int RunSelfTest(int argc, char** argv);
int RunInstall(bool resume);
int RunUninstall();
int RunUpdate();
int RunDiagnose();
int RunStartupProbe();
int RunControl(const std::string& action);
int RunGui();
bool ElevateAndRerun(const std::wstring& args);

}  // namespace st
