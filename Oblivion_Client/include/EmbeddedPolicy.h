#pragma once

namespace OblivionEye {
// Fallback policy minimal embed (UTF-8). Lowercase entries as loader expects.
static const char* kEmbeddedPolicy = R"POLICY(
[process]
cheatengine.exe

[module]
dbghelp.dll

[driver]
dbk32.sys

[overlay_title]
cheat engine

[overlay_class]
discordoverlay

[publisher]
microsoft corporation
gravity co., ltd.

[prolog]
kernel32.dll VirtualProtect 8
ntdll.dll NtOpenProcess 8

[chunk_whitelist]
)POLICY";
}
