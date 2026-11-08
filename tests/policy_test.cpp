#include "../src/policy.h"
#include <cassert>
#include <iostream>
using namespace policy;
int main() {
    assert(normalize(L"c:/Users/A/Temp/") == L"C:\\Users\\A\\Temp");
    for (auto p : {L"C:", L"C:foo", L"\\\\server\\share", L"\\\\?\\C:\\Temp\\a", L"C:\\Temp\\..\\Windows", L"C:\\Temp\\a:stream", L"C:\\Temp\\name.", L"C:\\Temp\\name "}) assert(normalize(p).empty());
    assert(!within(L"C:\\TempOther\\a", L"C:\\Temp"));
    assert(!within(L"C:\\Temp", L"C:\\Temp"));
    assert(within(L"C:\\Temp\\子\\a.bin", L"c:\\temp"));
    Identity a; a.volume=55; a.indexLow=19; a.links=1; a.created=10; a.modified=20; a.size=123;
    auto can = [&](Identity b, std::wstring path=L"C:\\Temp\\a", std::wstring resolved=L"C:\\Temp\\a", std::wstring root=L"C:\\Temp") {
        return mayDelete(path, root, resolved, a, b, 55, 100);
    };
    assert(can(a));
    assert(!can(a,L"D:\\Temp\\a",L"D:\\Temp\\a",L"D:\\Temp"));
    assert(!can(a,L"C:\\Temp\\a",L"D:\\Temp\\a"));
    assert(!can(a,L"C:\\TempExtra\\a",L"C:\\TempExtra\\a"));
    assert(!can(a,L"C:\\Temp\\Chrome\\a",L"C:\\Temp\\Chrome\\a"));
    for (uint32_t attr : {0x10u,0x400u,0x4u,0x1u,0x1000u,0x40u}) {auto b=a;b.attributes=attr;assert(!can(b));}
    {auto b=a;b.links=2;assert(!can(b));}
    {auto b=a;b.volume++;assert(!can(b));}
    {auto b=a;b.indexLow++;assert(!can(b));}
    {auto b=a;b.size++;assert(!can(b));}
    {auto b=a;b.created=101;assert(!can(b));}
    {auto b=a;b.modified=101;assert(!can(b));}
    {auto b=a;b.created=0;assert(!can(b));}
    App app; app.name=L"Example Editor";app.location=L"C:\\Program Files\\Example";app.command=L"\"C:\\Program Files\\Example\\uninstall.exe\"";
    assert(appReason(app,L"C:\\Windows").empty());
    for (auto name : {L"Steam", L"Discord PTB", L"Google Chrome", L"Visual C++ Redistributable", L"Intel Driver", L"ДРАЙВЕР ЗВУКА", L"EasyAntiCheat", L"Rockstar Games Launcher"}) {
        auto b=app;b.name=name;assert(!appReason(b,L"C:\\Windows").empty());
    }
    for(auto p:{L"D:\\Apps\\Example",L"C:\\Windows\\System32",L"C:\\Program Files",L"C:\\Apps\\..\\Windows",L""}){auto b=app;b.location=p;assert(!appReason(b,L"C:\\Windows").empty());}
    {auto b=app;b.key=L"Steam App 123";assert(!appReason(b,L"C:\\Windows").empty());}
    {auto b=app;b.publisher=L"Microsoft Corporation";assert(!appReason(b,L"C:\\Windows").empty());}
    {auto b=app;b.system=true;assert(!appReason(b,L"C:\\Windows").empty());}
    assert(nonCArgument(L"/data=D:\\Games"));
    assert(nonCArgument(L"/data=\\\\server\\share"));
    assert(!nonCArgument(L"/uninstall /dir=\"C:\\Program Files\\Example\""));
    std::cout << "PASS: path boundaries, aliases, D: redirection, identities, attributes, hard links, ages, protected apps, uninstall arguments\n";
}
