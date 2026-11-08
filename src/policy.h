#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

namespace policy {
inline std::wstring lower(std::wstring s) {
    for (auto& c : s) {
        if (c >= L'A' && c <= L'Z') c += 32;
        else if (c >= L'А' && c <= L'Я') c += 32;
        else if (c == L'Ё') c = L'ё';
    }
    return s;
}
inline bool equal(const std::wstring& a, const std::wstring& b) { return lower(a) == lower(b); }
inline bool contains(const std::wstring& text, const std::wstring& part) {
    return lower(text).find(lower(part)) != std::wstring::npos;
}
// Accept only ordinary absolute drive paths. Never accept devices, UNC, ADS,
// relative components, or Win32 aliases with trailing spaces/dots.
inline std::wstring normalize(std::wstring s) {
    std::replace(s.begin(), s.end(), L'/', L'\\');
    if (s.size() < 3 || s.size() > 32000 || s[1] != L':' || s[2] != L'\\') return {};
    if (!((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z'))) return {};
    if (s[0] >= L'a' && s[0] <= L'z') s[0] -= 32;
    while (s.size() > 3 && s.back() == L'\\') s.pop_back();
    if (s.size() == 3) return s;
    size_t start = 3;
    for (size_t i = 3; i <= s.size(); ++i) {
        if (i < s.size() && (s[i] == 0 || s[i] == L':' || s[i] == L'"' || s[i] == L'*' || s[i] == L'?' || s[i] < 32)) return {};
        if (i == s.size() || s[i] == L'\\') {
            auto c = s.substr(start, i - start);
            if (c.empty() || c == L"." || c == L".." || c.back() == L'.' || c.back() == L' ') return {};
            start = i + 1;
        }
    }
    return s;
}
inline bool onC(const std::wstring& p) { auto n = normalize(p); return n.size() >= 3 && n[0] == L'C'; }
inline bool within(const std::wstring& p, const std::wstring& parent) {
    auto a = lower(normalize(p)), b = lower(normalize(parent));
    if (a.empty() || b.empty() || a.size() <= b.size()) return false;
    if (b.back() != L'\\') b += L'\\';
    return a.size() > b.size() && a.compare(0, b.size(), b) == 0;
}
inline bool atOrWithin(const std::wstring& p, const std::wstring& parent) {
    auto a = normalize(p), b = normalize(parent);
    return !a.empty() && !b.empty() && (equal(a, b) || within(a, b));
}
inline bool protectedName(const std::wstring& p) {
    for (auto word : {L"steam", L"discord", L"chrome", L"saved games", L"userdata", L"my games"})
        if (contains(p, word)) return true;
    return false;
}
struct Identity {
    uint32_t volume = 0, indexHigh = 0, indexLow = 0, attributes = 0, links = 0;
    uint64_t size = 0, created = 0, modified = 0;
};
inline bool oldRegular(const Identity& i, uint64_t cutoff) {
    // DIRECTORY, REPARSE_POINT, SYSTEM, READONLY, OFFLINE, DEVICE.
    constexpr uint32_t forbidden = 0x10 | 0x400 | 0x4 | 0x1 | 0x1000 | 0x40;
    return !(i.attributes & forbidden) && i.links == 1 && i.created != 0 && i.modified != 0 &&
           i.created < cutoff && i.modified < cutoff;
}
inline bool mayDelete(const std::wstring& path, const std::wstring& root, const std::wstring& finalPath,
                      const Identity& before, const Identity& now, uint32_t systemVolume, uint64_t cutoff) {
    auto n = normalize(path), f = normalize(finalPath), r = normalize(root);
    return onC(n) && onC(r) && within(n, r) && equal(n, f) && !protectedName(n) &&
           oldRegular(now, cutoff) && now.volume == systemVolume && before.volume == now.volume &&
           before.indexHigh == now.indexHigh && before.indexLow == now.indexLow && before.size == now.size &&
           before.created == now.created && before.modified == now.modified;
}
struct App {
    std::wstring id, name, version, publisher, location, command, key, parent, releaseType;
    std::wstring reason, executable, arguments;
    uint64_t size = 0;
    uint32_t hive = 0, view = 0;
    bool system = false;
};
inline std::wstring appReason(const App& a, const std::wstring& windowsDir) {
    if (a.name.empty()) return L"Нет названия";
    if (protectedName(a.name)) return L"Steam, Discord или Chrome — сохранить";
    if (contains(a.key, L"Steam App ") || contains(a.command, L"steam://") || contains(a.command, L"steam.exe") ||
        contains(a.location, L"\\steamapps")) return L"Игра или компонент Steam — сохранить";
    if (a.system || !a.parent.empty() || !a.releaseType.empty()) return L"Системный или зависимый компонент";
    for (auto word : {L"microsoft", L"nvidia", L"advanced micro devices", L"intel", L"realtek", L"qualcomm", L"broadcom",
                      L"synaptics", L"mediatek", L"asustek", L"lenovo", L"hewlett", L"dell", L"logitech", L"razer", L"corsair"})
        if (contains(a.publisher, word)) return L"Издатель системного ПО или оборудования — сохранить";
    if (equal(a.publisher, L"AMD")) return L"Драйвер или компонент AMD";
    for (auto word : {L"driver", L"драйвер", L"redistributable", L"visual c++", L"directx", L".net", L"runtime", L"framework",
                      L"webview", L"physx", L"openal", L"vulkan", L"gaming services", L"anti-cheat", L"anticheat", L"easyanticheat",
                      L"battleye", L"rockstar", L"ubisoft", L"ea app", L"epic games", L"windows", L"update", L"service", L"служб"})
        if (contains(a.name, word)) return L"Общий компонент, драйвер, игровая служба или лаунчер";
    auto p = normalize(a.location);
    if (p.empty()) return L"Путь установки неизвестен — только ручная проверка";
    if (!onC(p)) return L"Установлено вне C: — сохранить";
    if (p.size() <= 3 || atOrWithin(p, windowsDir) || contains(p, L"\\common files") ||
        equal(p, L"C:\\Program Files") || equal(p, L"C:\\Program Files (x86)") || equal(p, L"C:\\ProgramData") || equal(p, L"C:\\Users"))
        return L"Общая или системная папка — сохранить";
    if (protectedName(p)) return L"Папка сохраняемой программы";
    if (a.command.empty()) return L"Нет штатной команды удаления";
    return {};
}
inline bool nonCArgument(const std::wstring& s) {
    if (s.find(L"\\\\") != std::wstring::npos) return true;
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        wchar_t c = lower(s.substr(i, 1))[0];
        if (c >= L'a' && c <= L'z' && c != L'c' && s[i + 1] == L':' && (s[i + 2] == L'\\' || s[i + 2] == L'/')) return true;
    }
    return false;
}
}
