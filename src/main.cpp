#ifndef UNICODE
#define UNICODE 1
#endif
#ifndef _UNICODE
#define _UNICODE 1
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <objbase.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <memory>
#include "policy.h"
#include "scan_math.h"
#include <queue>

using std::wstring;
using policy::App;
constexpr UINT WM_PROGRESS = WM_APP + 1, WM_FINISHED = WM_APP + 2;
constexpr int ID_SCAN=100, ID_ACTION=101, ID_STOP=102, ID_TABS=103, ID_LIST=104, ID_ADMIN=105, ID_HELP=106;
constexpr uint64_t WEEK = 7ULL * 24 * 60 * 60 * 10000000;
constexpr size_t MAX_ENTRIES = 300000;
struct FileCandidate { wstring path, root; policy::Identity info; size_t group=0; };
struct Group { wstring name, root, note; uint64_t bytes=0, count=0; };
struct Model {
    std::mutex mutex;
    std::atomic<bool> busy{false}, cancel{false};
    std::vector<Group> groups;
    std::vector<FileCandidate> files;
    std::vector<App> apps;
    wstring log, status=L"Готово к сканированию", windows, local;
    uint32_t volume=0;
    bool scanned=false;
} model;
HWND windowHandle=nullptr, heading=nullptr, subtitle=nullptr, keepLabel=nullptr, tabs=nullptr, list=nullptr;
HWND scanButton=nullptr, actionButton=nullptr, stopButton=nullptr, adminButton=nullptr, helpButton=nullptr;
HWND statusLabel=nullptr, hintLabel=nullptr, logEdit=nullptr;
HFONT normalFont=nullptr, titleFont=nullptr;
std::thread worker;
int activeTab=3;
void status(const wstring&);
void logLine(const wstring&);
bool inspect(const wstring&,policy::Identity&,bool);
struct LargeEntry {wstring path;uint64_t bytes;bool folder;bool complete=true;};
std::vector<LargeEntry> largeEntries;
bool inspectAnalysis(const wstring& p);
void analyzeLarge(){
    status(L"Анализ C: — подготовка…");
    {std::lock_guard<std::mutex> lock(model.mutex);largeEntries.clear();}
    std::vector<wstring> dirs{L"C:\\"};
    std::vector<scanmath::Total> totals{{size_t(-1),0,false}};
    auto bigger=[](const LargeEntry&a,const LargeEntry&b){return a.bytes>b.bytes;};
    std::priority_queue<LargeEntry,std::vector<LargeEntry>,decltype(bigger)> files(bigger),folders(bigger);
    auto keep=[](auto& heap,LargeEntry entry){heap.push(std::move(entry));if(heap.size()>1500)heap.pop();};
    size_t visited=0,denied=0,links=0,limited=0,processed=0;
    ULONGLONG started=GetTickCount64(),last=0;
    for(size_t index=0;index<dirs.size()&&!model.cancel;++index){
        const wstring parent=dirs[index];++processed;
        if(!inspectAnalysis(parent)){++denied;continue;}
        WIN32_FIND_DATAW data{};
        wstring pattern=L"\\\\?\\"+parent+(parent.back()==L'\\'?L"":L"\\")+L"*";
        HANDLE find=FindFirstFileExW(pattern.c_str(),FindExInfoBasic,&data,FindExSearchNameMatch,nullptr,FIND_FIRST_EX_LARGE_FETCH);
        if(find==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_PARAMETER)
            find=FindFirstFileExW(pattern.c_str(),FindExInfoBasic,&data,FindExSearchNameMatch,nullptr,0);
        if(find==INVALID_HANDLE_VALUE){DWORD e=GetLastError();if(e==ERROR_FILE_NOT_FOUND)totals[index].complete=true;else ++denied;continue;}
        totals[index].complete=true;
        for(;;){
            if(model.cancel){totals[index].complete=false;break;}
            wstring name=data.cFileName;
            if(name!=L"."&&name!=L".."){
                ++visited;
                if(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){++links;totals[index].complete=false;}
                else {
                    wstring path=parent+(parent.back()==L'\\'?L"":L"\\")+name;
                    if(path.size()>31900){++limited;totals[index].complete=false;}
                    else if(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
                        if(dirs.size()<500000){dirs.push_back(path);totals.push_back({index,0,false});}
                        else{++limited;totals[index].complete=false;}
                    }else{
                        uint64_t bytes=(uint64_t(data.nFileSizeHigh)<<32)|data.nFileSizeLow;
                        totals[index].bytes+=bytes;
                        if(bytes>=100ULL*1024*1024)keep(files,{path,bytes,false,true});
                    }
                }
            }
            ULONGLONG tick=GetTickCount64();
            if(tick-last>=250){last=tick;status(L"Проверено: "+std::to_wstring(visited)+L" · папок: "+std::to_wstring(processed)+L" · "+std::to_wstring((tick-started)/1000)+L" с · "+parent);}
            if(!FindNextFileW(find,&data)){DWORD e=GetLastError();if(e!=ERROR_NO_MORE_FILES){++denied;totals[index].complete=false;}break;}
        }
        FindClose(find);
    }
    scanmath::aggregate(totals);
    for(size_t i=0;i<dirs.size();++i)if(totals[i].bytes>=100ULL*1024*1024||(!totals[i].complete&&i==0))
        keep(folders,{dirs[i],totals[i].bytes,true,totals[i].complete});
    std::vector<LargeEntry> top;
    while(!files.empty()){top.push_back(files.top());files.pop();}
    while(!folders.empty()){top.push_back(folders.top());folders.pop();}
    std::sort(top.begin(),top.end(),bigger);
    {std::lock_guard<std::mutex> lock(model.mutex);largeEntries=std::move(top);}
    wstring summary=L"Объектов: "+std::to_wstring(visited)+L"; недоступных папок: "+std::to_wstring(denied)+L"; ссылок пропущено: "+std::to_wstring(links)+L"; ограничений: "+std::to_wstring(limited);
    logLine(summary+L". Ничего не удалено. Размеры логические, hard links могут учитываться повторно.");
    status((model.cancel?wstring(L"Остановлено. "):wstring(L"Готово. "))+summary);
}
bool rebuilding=false;

struct Handle {
    HANDLE h=INVALID_HANDLE_VALUE;
    Handle()=default; explicit Handle(HANDLE x):h(x){}
    ~Handle(){ if(h!=INVALID_HANDLE_VALUE && h!=nullptr) CloseHandle(h); }
    Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
    bool valid() const {return h!=INVALID_HANDLE_VALUE && h!=nullptr;}
};
uint64_t ticks(const FILETIME& t){return (uint64_t(t.dwHighDateTime)<<32)|t.dwLowDateTime;}
uint64_t nowTicks(){FILETIME t;GetSystemTimeAsFileTime(&t);return ticks(t);}
wstring sizeText(uint64_t n){
    std::wostringstream s; double value=double(n); const wchar_t* units[]={L"Б",L"КБ",L"МБ",L"ГБ",L"ТБ"}; int i=0;
    while(value>=1024 && i<4){value/=1024;++i;} s<<std::fixed<<std::setprecision(i?1:0)<<value<<L" "<<units[i];return s.str();
}
wstring errorText(DWORD code=GetLastError()){
    wchar_t* message=nullptr;FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,code,0,reinterpret_cast<wchar_t*>(&message),0,nullptr);
    wstring s=message?message:L"Ошибка Windows";if(message)LocalFree(message);
    while(!s.empty()&&(s.back()==L'\r'||s.back()==L'\n'))s.pop_back();return s+L" ("+std::to_wstring(code)+L")";
}
void logLine(const wstring& s){
    SYSTEMTIME t;GetLocalTime(&t);wchar_t stamp[32];swprintf(stamp,32,L"%02u:%02u:%02u  ",t.wHour,t.wMinute,t.wSecond);
    {std::lock_guard<std::mutex> lock(model.mutex);model.log+=stamp+s+L"\r\n";if(model.log.size()>300000)model.log.erase(0,model.log.find(L'\n',50000)+1);}
    PostMessageW(windowHandle,WM_PROGRESS,0,0);
}
void status(const wstring& s){{std::lock_guard<std::mutex> lock(model.mutex);model.status=s;}PostMessageW(windowHandle,WM_PROGRESS,0,0);}
wstring longPath(const wstring& p){return L"\\\\?\\"+p;}
wstring finalPath(HANDLE h){
    std::vector<wchar_t> b(32768);DWORD n=GetFinalPathNameByHandleW(h,b.data(),DWORD(b.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(!n||n>=b.size())return {};wstring p(b.data(),n);if(p.compare(0,4,L"\\\\?\\")==0)p.erase(0,4);return policy::normalize(p);
}
bool identity(HANDLE h,policy::Identity& out){
    BY_HANDLE_FILE_INFORMATION i{};if(!GetFileInformationByHandle(h,&i))return false;
    out.volume=i.dwVolumeSerialNumber;out.indexHigh=i.nFileIndexHigh;out.indexLow=i.nFileIndexLow;out.attributes=i.dwFileAttributes;
    out.links=i.nNumberOfLinks;out.size=(uint64_t(i.nFileSizeHigh)<<32)|i.nFileSizeLow;out.created=ticks(i.ftCreationTime);out.modified=ticks(i.ftLastWriteTime);return true;
}
// Every parent is checked. An opened file's resolved path and volume are checked
// again immediately before a handle-based deletion, never a path-based delete.
bool plainPath(const wstring& raw){
    wstring p=policy::normalize(raw);if(!policy::onC(p))return false;
    for(size_t i=2;i<=p.size();++i){
        if(i!=p.size()&&p[i]!=L'\\')continue;
        wstring part=i==2?p.substr(0,3):p.substr(0,i);
        DWORD a=GetFileAttributesW(longPath(part).c_str());
        if(a==INVALID_FILE_ATTRIBUTES || (a&FILE_ATTRIBUTE_REPARSE_POINT))return false;
    }
    return true;
}
struct ParentLocks {
    std::vector<HANDLE> handles;
    ~ParentLocks(){for(auto h:handles)CloseHandle(h);}
    bool acquire(const wstring& raw){
        const wstring p=policy::normalize(raw);if(!policy::onC(p))return false;
        // No FILE_SHARE_DELETE: keep every ancestor in place until the verified
        // file handle is closed. A busy or un-lockable directory is skipped.
        for(size_t i=2;i<p.size();++i){
            if(p[i]!=L'\\')continue;wstring parent=i==2?p.substr(0,3):p.substr(0,i);
            HANDLE h=CreateFileW(longPath(parent).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);
            if(h==INVALID_HANDLE_VALUE)return false;handles.push_back(h);policy::Identity info;
            if(!identity(h,info)||info.volume!=model.volume||!(info.attributes&FILE_ATTRIBUTE_DIRECTORY)||
               (info.attributes&FILE_ATTRIBUTE_REPARSE_POINT)||!policy::equal(finalPath(h),parent))return false;
        }
        return true;
    }
};
bool inspect(const wstring& p, policy::Identity& out, bool directory){
    if(!plainPath(p))return false;
    Handle h(CreateFileW(longPath(p).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
    if(!h.valid()||!identity(h.h,out))return false;
    if(out.volume!=model.volume || (out.attributes&FILE_ATTRIBUTE_REPARSE_POINT))return false;
    if(directory != bool(out.attributes&FILE_ATTRIBUTE_DIRECTORY))return false;
    return policy::equal(finalPath(h.h),policy::normalize(p));
}
bool inspectAnalysis(const wstring& raw){
    const wstring p=policy::normalize(raw);if(!policy::onC(p))return false;
    Handle h(CreateFileW(longPath(p).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
    policy::Identity info;
    return h.valid()&&identity(h.h,info)&&info.volume==model.volume&&(info.attributes&FILE_ATTRIBUTE_DIRECTORY)&&!(info.attributes&FILE_ATTRIBUTE_REPARSE_POINT)&&policy::equal(finalPath(h.h),p);
}
wstring knownFolder(REFKNOWNFOLDERID id){
    PWSTR p=nullptr;wstring s;if(SUCCEEDED(SHGetKnownFolderPath(id,KF_FLAG_DONT_VERIFY,nullptr,&p))&&p){s=p;CoTaskMemFree(p);}return policy::normalize(s);
}
wstring expanded(const wstring& s){
    DWORD n=ExpandEnvironmentStringsW(s.c_str(),nullptr,0);if(!n||n>32768)return {};
    std::vector<wchar_t> b(n);if(!ExpandEnvironmentStringsW(s.c_str(),b.data(),n))return {};return b.data();
}
wstring regString(HKEY key,const wchar_t* name){
    DWORD type=0,n=0;if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&n)!=ERROR_SUCCESS || n>65534 || (type!=REG_SZ&&type!=REG_EXPAND_SZ))return {};
    std::vector<wchar_t> b(n/2+2,0);if(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(b.data()),&n)!=ERROR_SUCCESS)return {};
    wstring s=b.data();return type==REG_EXPAND_SZ?expanded(s):s;
}
DWORD regNumber(HKEY key,const wchar_t* name){DWORD n=4,type=0,value=0;return RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(&value),&n)==ERROR_SUCCESS&&type==REG_DWORD?value:0;}
wstring trim(wstring s){while(!s.empty()&&iswspace(s.front()))s.erase(s.begin());while(!s.empty()&&iswspace(s.back()))s.pop_back();return s;}
wstring trimQuotes(wstring s){s=trim(s);if(s.size()>=2&&s.front()==L'"'&&s.back()==L'"')s=s.substr(1,s.size()-2);return s;}
bool isGuid(const wstring& s){
    if(s.size()!=38||s.front()!=L'{'||s.back()!=L'}')return false;
    for(size_t i=1;i<37;++i){if(i==9||i==14||i==19||i==24){if(s[i]!=L'-')return false;}else if(!iswxdigit(s[i]))return false;}return true;
}
wstring prepareUninstaller(App& a){
    wstring cmd=trim(expanded(a.command));if(cmd.empty())return L"Команда удаления не определена";
    int count=0;LPWSTR* args=CommandLineToArgvW(cmd.c_str(),&count);if(!args||count<1){if(args)LocalFree(args);return L"Команда удаления не распознана";}
    std::vector<wstring> av;for(int i=0;i<count;++i)av.emplace_back(args[i]);LocalFree(args);
    wstring first=av[0],base=first.substr(first.find_last_of(L"\\/")==wstring::npos?0:first.find_last_of(L"\\/")+1);
    wchar_t systemDir[32768];UINT n=GetSystemDirectoryW(systemDir,32768);if(!n||n>=32768)return L"Системная папка не определена";
    wstring msi=wstring(systemDir)+L"\\msiexec.exe";
    if(policy::equal(base,L"msiexec.exe") || policy::equal(base,L"msiexec")){
        if(first.find(L':')!=wstring::npos&&!policy::equal(policy::normalize(first),msi))return L"Необычный путь Windows Installer";
        wstring guid;
        for(size_t i=1;i<av.size();++i){
            auto arg=policy::lower(av[i]);
            if(arg==L"/i"||arg==L"/x"){if(i+1>=av.size()||!isGuid(av[i+1]))return L"MSI: нет кода продукта";guid=av[++i];}
            else if(arg.size()>2&&(arg.substr(0,2)==L"/i"||arg.substr(0,2)==L"/x")&&isGuid(av[i].substr(2)))guid=av[i].substr(2);
            else if(arg!=L"/quiet"&&arg!=L"/passive"&&arg!=L"/qn"&&arg!=L"/qb"&&arg!=L"/norestart")return L"Необычные параметры Windows Installer";
        }
        if(!isGuid(guid))return L"MSI: код продукта не определен";
        a.executable=msi;a.arguments=L"/x "+guid+L" /passive /norestart";
    }else{
        a.executable=policy::normalize(first);
        if(!policy::onC(a.executable)||a.executable.size()<4||!policy::equal(a.executable.substr(a.executable.size()-4),L".exe"))return L"Необычный или неизвестный деинсталлятор";
        if(policy::atOrWithin(a.executable,model.windows))return L"Системную команду автоматически не запускаем";
        for(auto blocked:{L"cmd.exe",L"powershell.exe",L"pwsh.exe",L"rundll32.exe",L"regsvr32.exe",L"mshta.exe",L"wscript.exe",L"cscript.exe",L"reg.exe",L"regedit.exe",L"sc.exe",L"dism.exe",L"diskpart.exe"})
            if(policy::equal(base,blocked))return L"Сценарная или системная команда — ручная проверка";
        size_t tail=0;
        if(cmd.front()==L'"'){tail=cmd.find(L'"',1);if(tail==wstring::npos)return L"Неверные кавычки в команде";++tail;}
        else{tail=cmd.find_first_of(L" \t");if(tail==wstring::npos)tail=cmd.size();}
        a.arguments=trim(cmd.substr(tail));
        if(policy::nonCArgument(a.arguments))return L"В параметрах удаления есть другой диск или сеть";
    }
    policy::Identity exeInfo;
    if(!inspect(a.executable,exeInfo,false))return L"Файл деинсталлятора недоступен или перенаправлен";
    return {};
}
bool readApp(uint32_t hive,uint32_t view,const wstring& keyName,App& a){
    HKEY h=nullptr;wstring key=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+keyName;
    HKEY root=hive==0?HKEY_LOCAL_MACHINE:HKEY_CURRENT_USER;
    if(RegOpenKeyExW(root,key.c_str(),0,KEY_READ|view,&h)!=ERROR_SUCCESS)return false;
    a={};a.hive=hive;a.view=view;a.key=keyName;a.id=std::to_wstring(hive)+L":"+std::to_wstring(view)+L":"+keyName;
    a.name=regString(h,L"DisplayName");a.version=regString(h,L"DisplayVersion");a.publisher=regString(h,L"Publisher");
    a.location=policy::normalize(trimQuotes(expanded(regString(h,L"InstallLocation"))));
    a.command=regString(h,L"UninstallString");a.parent=regString(h,L"ParentKeyName");a.releaseType=regString(h,L"ReleaseType");
    a.system=regNumber(h,L"SystemComponent")==1;a.size=uint64_t(regNumber(h,L"EstimatedSize"))*1024;RegCloseKey(h);
    if(a.name.empty())return false;
    a.reason=policy::appReason(a,model.windows);
    if(a.reason.empty()){
        policy::Identity loc;
        if(!inspect(a.location,loc,true))a.reason=L"Папка установки недоступна или перенаправлена";
        else a.reason=prepareUninstaller(a);
    }
    return true;
}
std::vector<App> readApps(){
    std::vector<App> result;
    for(uint32_t hive:{0u,1u})for(uint32_t view:{uint32_t(KEY_WOW64_64KEY),uint32_t(KEY_WOW64_32KEY)}){
        HKEY parent=nullptr;HKEY root=hive==0?HKEY_LOCAL_MACHINE:HKEY_CURRENT_USER;
        if(RegOpenKeyExW(root,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",0,KEY_READ|view,&parent)!=ERROR_SUCCESS)continue;
        for(DWORD i=0;!model.cancel;++i){
            wchar_t name[16384];DWORD n=16384;LONG code=RegEnumKeyExW(parent,i,name,&n,nullptr,nullptr,nullptr,nullptr);
            if(code==ERROR_NO_MORE_ITEMS)break;if(code!=ERROR_SUCCESS)continue;
            App a;if(readApp(hive,view,name,a)){
                bool duplicate=false;for(const auto& b:result)if(policy::equal(a.name,b.name)&&policy::equal(a.location,b.location)&&a.command==b.command&&a.version==b.version){duplicate=true;break;}
                if(!duplicate)result.push_back(std::move(a));
            }
        }
        RegCloseKey(parent);
    }
    std::sort(result.begin(),result.end(),[](const App&a,const App&b){if(a.reason.empty()!=b.reason.empty())return a.reason.empty();if(a.size!=b.size)return a.size>b.size;return a.name<b.name;});return result;
}
bool protectedPath(const wstring& p,const std::vector<wstring>& installed){
    if(policy::protectedName(p))return true;
    for(const auto& i:installed)if(policy::atOrWithin(p,i))return true;
    return false;
}
void scanFiles(std::vector<Group>& groups,std::vector<FileCandidate>& files,const std::vector<App>& apps){
    std::vector<wstring> installed;for(const auto&a:apps)if(policy::onC(a.location))installed.push_back(a.location);
    wchar_t self[32768];DWORD n=GetModuleFileNameW(nullptr,self,32768);if(n&&n<32768){wstring p=self;auto at=p.find_last_of(L'\\');if(at!=wstring::npos)installed.push_back(p.substr(0,at));}
    const uint64_t cutoff=nowTicks()-WEEK;size_t seen=0;
    for(size_t gi=0;gi<groups.size();++gi){
        auto& group=groups[gi];policy::Identity rootInfo;
        if(!inspect(group.root,rootInfo,true)){group.note=L"Недоступна, отсутствует или перенаправлена — пропущена";continue;}
        if(protectedPath(group.root,installed)){group.note=L"В этой папке расположена программа — пропущена";continue;}
        std::vector<std::pair<wstring,int>> pending{{group.root,0}};size_t skipped=0;
        while(!pending.empty()&&!model.cancel&&seen<MAX_ENTRIES){
            auto current=std::move(pending.back());pending.pop_back();
            policy::Identity dir;if(!inspect(current.first,dir,true)||protectedPath(current.first,installed)){++skipped;continue;}
            WIN32_FIND_DATAW data{};HANDLE find=FindFirstFileW((longPath(current.first)+L"\\*").c_str(),&data);
            if(find==INVALID_HANDLE_VALUE){++skipped;continue;}
            do{
                if(model.cancel||seen>=MAX_ENTRIES)break;
                wstring name=data.cFileName;if(name==L"."||name==L"..")continue;++seen;
                wstring p=policy::normalize(current.first+L"\\"+name);
                if(p.empty()||!policy::within(p,group.root)||protectedPath(p,installed)||(data.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_OFFLINE))){++skipped;continue;}
                if(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){if(current.second<40)pending.emplace_back(p,current.second+1);else ++skipped;continue;}
                policy::Identity info;
                if(inspect(p,info,false)&&policy::oldRegular(info,cutoff)){
                    files.push_back({p,group.root,info,gi});group.bytes+=info.size;++group.count;
                }else ++skipped;
                if(seen%300==0)status(L"Сканирование C: · проверено объектов: "+std::to_wstring(seen));
            }while(FindNextFileW(find,&data));FindClose(find);
        }
        group.note=L"Только обычные файлы старше 7 дней; пропущено: "+std::to_wstring(skipped);
        if(seen>=MAX_ENTRIES)group.note+=L". Достигнут лимит сканирования";
    }
}
void scanAll(){
    status(L"Проверка установленных программ…");auto apps=readApps();std::vector<Group> groups;std::vector<FileCandidate> files;
    if(policy::onC(model.local))groups.push_back({L"Временные файлы пользователя",model.local+L"\\Temp",L""});
    groups.push_back({L"Временные файлы Windows",model.windows+L"\\Temp",L""});
    if(policy::onC(model.local))groups.push_back({L"Старые отчеты об ошибках",model.local+L"\\Microsoft\\Windows\\WER",L""});
    scanFiles(groups,files,apps);uint64_t bytes=0;for(const auto& g:groups)bytes+=g.bytes;
    bool canceled=model.cancel;
    {std::lock_guard<std::mutex> lock(model.mutex);model.groups=std::move(groups);model.files=std::move(files);model.apps=std::move(apps);model.scanned=!canceled;}
    logLine(canceled?L"Сканирование остановлено. Для очистки нужно пересканировать.":L"Сканирование завершено. Найдено старых временных файлов на "+sizeText(bytes));
    status(canceled?L"Сканирование остановлено":L"Можно очистить до "+sizeText(bytes)+L" · сначала проверь список");
}
bool deleteVerified(const FileCandidate& f,wstring& reason){
    if(!policy::onC(f.path)||!policy::within(f.path,f.root)||!plainPath(f.path)){reason=L"Путь изменился или перенаправлен";return false;}
    ParentLocks parents;if(!parents.acquire(f.path)){reason=L"Папка занята, изменена или перенаправлена";return false;}
    Handle h(CreateFileW(longPath(f.path).c_str(),DELETE|FILE_READ_ATTRIBUTES,0,nullptr,OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
    if(!h.valid()){reason=L"Занят, недоступен или уже удален";return false;}
    policy::Identity current;
    if(!identity(h.h,current)||!policy::mayDelete(f.path,f.root,finalPath(h.h),f.info,current,model.volume,nowTicks()-WEEK)){
        reason=L"Файл изменился или не прошел проверку";return false;
    }
    FILE_DISPOSITION_INFO disposition{};disposition.DeleteFile=TRUE;
    if(!SetFileInformationByHandle(h.h,FileDispositionInfo,&disposition,sizeof(disposition))){reason=errorText();return false;}
    return true;
}
void cleanFiles(std::vector<size_t> chosen){
    std::vector<FileCandidate> targets;
    {std::lock_guard<std::mutex> lock(model.mutex);for(const auto& f:model.files)if(std::find(chosen.begin(),chosen.end(),f.group)!=chosen.end())targets.push_back(f);}
    size_t removed=0,skipped=0;uint64_t bytes=0;
    logLine(L"Очистка выбранных временных файлов. Каталоги, ссылки и другие диски не удаляются.");
    for(size_t i=0;i<targets.size()&&!model.cancel;++i){
        wstring reason;
        if(deleteVerified(targets[i],reason)){++removed;bytes+=targets[i].info.size;}
        else{++skipped;if(skipped<=40)logLine(L"Пропуск: "+targets[i].path+L" — "+reason);}
        if(i%100==0)status(L"Очистка · "+std::to_wstring(i+1)+L" / "+std::to_wstring(targets.size()));
    }
    {std::lock_guard<std::mutex> lock(model.mutex);model.scanned=false;model.files.clear();for(auto& g:model.groups){g.bytes=0;g.count=0;g.note=L"После очистки нужно пересканировать";}}
    logLine(L"Удалено файлов: "+std::to_wstring(removed)+L"; сумма их размеров: "+sizeText(bytes)+L"; пропущено: "+std::to_wstring(skipped)+L".");
    status((model.cancel?L"Остановлено. ":L"Готово. ")+wstring(L"Удалено: ")+sizeText(bytes)+L". Для нового списка нажми «Сканировать».");
}
bool runUninstaller(const App& a,DWORD& exitCode,wstring& error){
    SHELLEXECUTEINFOW sei{};sei.cbSize=sizeof(sei);sei.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;
    sei.hwnd=windowHandle;sei.lpVerb=L"open";sei.lpFile=a.executable.c_str();sei.lpParameters=a.arguments.c_str();sei.nShow=SW_SHOWNORMAL;
    if(!ShellExecuteExW(&sei)){error=errorText();return false;}
    Handle process(sei.hProcess);if(!process.valid()){error=L"Windows не вернула процесс. Проверь открывшееся окно.";return false;}
    while(WaitForSingleObject(process.h,500)==WAIT_TIMEOUT){if(model.cancel)status(L"Дождись завершения текущего деинсталлятора. Следующие не запустятся.");}
    if(!GetExitCodeProcess(process.h,&exitCode)){error=errorText();return false;}return true;
}
void uninstallApps(std::vector<App> selected){
    for(const auto& original:selected){
        if(model.cancel)break;
        App current;
        if(!readApp(original.hive,original.view,original.key,current)){logLine(L"Пропуск: запись «"+original.name+L"» уже отсутствует");continue;}
        if(!current.reason.empty()||current.name!=original.name||current.location!=original.location||current.command!=original.command||current.version!=original.version){
            logLine(L"Пропуск: «"+original.name+L"» изменилась или защищена");continue;
        }
        status(L"Удаление: "+current.name+L". Проверь окно деинсталлятора.");logLine(L"Запущен штатный деинсталлятор: "+current.name);
        DWORD code=0;wstring error;
        if(!runUninstaller(current,code,error)){logLine(L"Не завершено: "+error);model.cancel=true;break;}
        logLine(L"Деинсталлятор «"+current.name+L"» завершился с кодом "+std::to_wstring(code));
        if(code==1602){logLine(L"Удаление отменено пользователем. Очередь остановлена.");model.cancel=true;break;}
        if(code==1641||code==3010){logLine(L"Деинсталлятор сообщает о необходимости перезапуска. Очередь остановлена.");model.cancel=true;break;}
        if(code!=0){logLine(L"Ненулевой код завершения. Очередь остановлена для проверки.");model.cancel=true;break;}
        App remaining;
        if(readApp(original.hive,original.view,original.key,remaining)){
            logLine(L"Запись приложения остается. Возможно, открыто отдельное окно удаления. Заверши его и пересканируй; очередь остановлена.");model.cancel=true;break;
        }
    }
    auto apps=readApps();
    {std::lock_guard<std::mutex> lock(model.mutex);if(!model.cancel)model.apps=std::move(apps);model.scanned=false;}
    status(L"Очередь завершена. Проверь журнал и нажми «Сканировать».");
}
template<class F> void startWork(F job){
    if(model.busy.exchange(true))return;
    if(worker.joinable())worker.join();model.cancel=false;
    worker=std::thread([job]{
        HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
        try{job();}catch(...){
            {std::lock_guard<std::mutex> lock(model.mutex);model.scanned=false;}
            logLine(L"Операция прервана из-за внутренней ошибки. Автоматическое продолжение отключено.");status(L"Ошибка — проверь журнал");
        }
        if(SUCCEEDED(hr))CoUninitialize();model.busy=false;PostMessageW(windowHandle,WM_FINISHED,0,0);
    });PostMessageW(windowHandle,WM_PROGRESS,0,0);
}

int dpi=96;
int px(int n){return MulDiv(n,dpi,96);}
HWND control(const wchar_t* cls,const wchar_t* title,DWORD style,int id){
    HWND h=CreateWindowExW(0,cls,title,WS_CHILD|WS_VISIBLE|style,0,0,1,1,windowHandle,reinterpret_cast<HMENU>(intptr_t(id)),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(normalFont),TRUE);return h;
}
void column(int index,const wchar_t* name,int width){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;c.pszText=const_cast<wchar_t*>(name);c.cx=px(width);c.iSubItem=index;ListView_InsertColumn(list,index,&c);}
void cell(int row,int col,const wstring& s){ListView_SetItemText(list,row,col,const_cast<wchar_t*>(s.c_str()));}
void row(int index,const wstring& text){LVITEMW i{};i.mask=LVIF_TEXT;i.iItem=index;i.pszText=const_cast<wchar_t*>(text.c_str());ListView_InsertItem(list,&i);}
void refreshButtons(){
    bool busy=model.busy;bool scanned;{std::lock_guard<std::mutex> lock(model.mutex);scanned=model.scanned;}
    EnableWindow(scanButton,!busy);EnableWindow(stopButton,busy);EnableWindow(adminButton,!busy&&!IsUserAnAdmin());
    bool selected=false;int count=ListView_GetItemCount(list);for(int i=0;i<count;++i)if(ListView_GetCheckState(list,i)){selected=true;break;}
    EnableWindow(actionButton,!busy&&scanned&&selected&&activeTab<2);
    SetWindowTextW(actionButton,activeTab==1?L"Удалить выбранные программы":L"Очистить выбранное");
}
void showProgress(){
    wstring text,log;{std::lock_guard<std::mutex> lock(model.mutex);text=model.status;if(activeTab==2)log=model.log;}
    SetWindowTextW(statusLabel,text.c_str());if(activeTab==2){SetWindowTextW(logEdit,log.c_str());SendMessageW(logEdit,EM_SETSEL,log.size(),log.size());SendMessageW(logEdit,EM_SCROLLCARET,0,0);}
    refreshButtons();
}
void renderList(){
    rebuilding=true;SendMessageW(list,WM_SETREDRAW,FALSE,0);ListView_DeleteAllItems(list);while(ListView_DeleteColumn(list,0)){}
    ShowWindow(logEdit,activeTab==2?SW_SHOW:SW_HIDE);ShowWindow(list,activeTab==2?SW_HIDE:SW_SHOW);
    ShowWindow(actionButton,activeTab>=2?SW_HIDE:SW_SHOW);
    ListView_SetExtendedListViewStyle(list,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|(activeTab<2?LVS_EX_CHECKBOXES:0));
    if(activeTab==0){
        std::vector<Group> groups;bool scanned;{std::lock_guard<std::mutex> lock(model.mutex);groups=model.groups;scanned=model.scanned;}
        column(0,L"Категория",245);column(1,L"Размер",90);column(2,L"Файлов",75);column(3,L"Папка на C:",330);column(4,L"Проверка",420);
        for(size_t i=0;i<groups.size();++i){row(int(i),groups[i].name);cell(int(i),1,sizeText(groups[i].bytes));cell(int(i),2,std::to_wstring(groups[i].count));cell(int(i),3,groups[i].root);cell(int(i),4,groups[i].note);if(scanned&&groups[i].count)ListView_SetCheckState(list,int(i),TRUE);}
        SetWindowTextW(hintLabel,L"Автоочистка: только временные файлы старше 7 дней. Документы, загрузки, профили и сохранения не входят в очистку.");
    }else if(activeTab==1){
        std::vector<App> apps;{std::lock_guard<std::mutex> lock(model.mutex);apps=model.apps;}
        column(0,L"Программа",260);column(1,L"Размер*",100);column(2,L"Решение",380);column(3,L"Папка установки",360);column(4,L"Издатель",220);
        for(size_t i=0;i<apps.size();++i){row(int(i),apps[i].name);cell(int(i),1,apps[i].size?sizeText(apps[i].size):L"—");cell(int(i),2,apps[i].reason.empty()?L"Проверь назначение; можно выбрать вручную":apps[i].reason);cell(int(i),3,apps[i].location.empty()?L"Не указана":apps[i].location);cell(int(i),4,apps[i].publisher);}
        SetWindowTextW(hintLabel,L"Выбери только ненужные приложения. Серые строки исключены. *Размер — оценка установщика. Store и portable могут отсутствовать.");
    }else if(activeTab==3){
        std::vector<LargeEntry> entries;{std::lock_guard<std::mutex> lock(model.mutex);entries=largeEntries;}
        column(0,L"Размер",120);column(1,L"Тип",100);column(2,L"Полный путь",760);column(3,L"Полнота",180);
        for(size_t i=0;i<entries.size();++i){row(int(i),sizeText(entries[i].bytes));cell(int(i),1,entries[i].folder?L"Папка":L"Файл");cell(int(i),2,entries[i].path);cell(int(i),3,entries[i].complete?L"В пределах обхода":L"Неполный размер");}
        SetWindowTextW(hintLabel,L"Топ до 1500 файлов и 1500 папок от 100 МБ. Включая скрытые AppData / Roaming / Local. Размеры папок вложенные — не складывай их.");
    }else SetWindowTextW(hintLabel,L"Журнал действий этого запуска. Чтобы скопировать: щелкни журнал, нажми Ctrl+A, затем Ctrl+C.");
    SendMessageW(list,WM_SETREDRAW,TRUE,0);InvalidateRect(list,nullptr,TRUE);rebuilding=false;showProgress();
}
void layout(){
    RECT r;GetClientRect(windowHandle,&r);int w=r.right,h=r.bottom,m=px(22);
    MoveWindow(heading,m,px(16),w-2*m,px(37),TRUE);MoveWindow(subtitle,m,px(55),w-2*m,px(24),TRUE);
    MoveWindow(keepLabel,m,px(86),w-2*m,px(25),TRUE);MoveWindow(tabs,m,px(126),w-2*m,px(34),TRUE);
    MoveWindow(hintLabel,m,px(170),w-2*m,px(42),TRUE);
    MoveWindow(list,m,px(220),w-2*m,std::max(px(150),h-px(325)),TRUE);
    MoveWindow(logEdit,m,px(220),w-2*m,std::max(px(150),h-px(325)),TRUE);
    int y=h-px(86);
    MoveWindow(scanButton,m,y,px(130),px(36),TRUE);MoveWindow(actionButton,m+px(142),y,px(265),px(36),TRUE);
    MoveWindow(stopButton,m+px(419),y,px(110),px(36),TRUE);MoveWindow(adminButton,w-m-px(283),y,px(185),px(36),TRUE);
    MoveWindow(helpButton,w-m-px(86),y,px(86),px(36),TRUE);MoveWindow(statusLabel,m,h-px(39),w-2*m,px(28),TRUE);
}
struct Confirmation {wstring title,text;};
INT_PTR CALLBACK confirmProc(HWND h,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_INITDIALOG){
        auto* data=reinterpret_cast<Confirmation*>(lp);SetWindowTextW(h,data->title.c_str());RECT r;GetClientRect(h,&r);
        HWND e=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",data->text.c_str(),WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,12,12,r.right-24,r.bottom-65,h,nullptr,GetModuleHandleW(nullptr),nullptr);
        HWND yes=CreateWindowW(L"BUTTON",L"Удалить выбранное",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,r.right-338,r.bottom-42,190,30,h,reinterpret_cast<HMENU>(IDOK),GetModuleHandleW(nullptr),nullptr);
        HWND no=CreateWindowW(L"BUTTON",L"Отмена",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,r.right-138,r.bottom-42,126,30,h,reinterpret_cast<HMENU>(IDCANCEL),GetModuleHandleW(nullptr),nullptr);
        for(HWND c:{e,yes,no})SendMessageW(c,WM_SETFONT,reinterpret_cast<WPARAM>(normalFont),TRUE);
        SendMessageW(h,DM_SETDEFID,IDCANCEL,0);SetFocus(no);return FALSE;
    }
    if(msg==WM_COMMAND&&(LOWORD(wp)==IDOK||LOWORD(wp)==IDCANCEL)){EndDialog(h,LOWORD(wp));return TRUE;}
    if(msg==WM_CLOSE){EndDialog(h,IDCANCEL);return TRUE;}return FALSE;
}
bool confirm(const wstring& title,const wstring& text){
    struct Template {DLGTEMPLATE t;WORD menu,cls,title;} data{};
    data.t.style=WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME|DS_CENTER;data.t.cx=430;data.t.cy=290;
    Confirmation content{title,text};return DialogBoxIndirectParamW(GetModuleHandleW(nullptr),&data.t,windowHandle,confirmProc,reinterpret_cast<LPARAM>(&content))==IDOK;
}
void doAction(){
    if(model.busy)return;bool scanned;{std::lock_guard<std::mutex> lock(model.mutex);scanned=model.scanned;}if(!scanned)return;
    if(activeTab==0){
        std::vector<size_t> chosen;uint64_t count=0,bytes=0;wstring roots;
        {std::lock_guard<std::mutex> lock(model.mutex);for(size_t i=0;i<model.groups.size();++i)if(ListView_GetCheckState(list,int(i))&&model.groups[i].count){chosen.push_back(i);count+=model.groups[i].count;bytes+=model.groups[i].bytes;roots+=L"• "+model.groups[i].root+L"\r\n";}}
        if(chosen.empty())return;
        wstring text=L"Удалить до "+std::to_wstring(count)+L" старых временных файлов ("+sizeText(bytes)+L")?\r\n\r\n"+roots+
            L"\r\nФайлы удаляются без корзины. Перед удалением каждый файл проверяется снова. Занятые, измененные файлы и ссылки будут пропущены.\r\n\r\nДокументы, загрузки, профили программ, сохранения и D: в эту очистку не входят.";
        if(confirm(L"Очистка C: — проверка списка",text))startWork([chosen]{cleanFiles(chosen);});
    }else if(activeTab==1){
        std::vector<App> selected;wstring names;
        {std::lock_guard<std::mutex> lock(model.mutex);for(size_t i=0;i<model.apps.size();++i)if(ListView_GetCheckState(list,int(i))&&model.apps[i].reason.empty()){selected.push_back(model.apps[i]);names+=L"• "+model.apps[i].name+L"\r\n  "+model.apps[i].location+L"\r\n";}}
        if(selected.empty())return;
        wstring text=L"Удалить выбранные программы: "+std::to_wstring(selected.size())+L"?\r\n\r\n"+names+
            L"\r\nБудут запущены штатные деинсталляторы по очереди. Некоторые потребуют ответить в их окне или разрешить UAC.\r\n\r\nНазвания и пути не гарантируют, что приложение никому не нужно. Удаление может затронуть его настройки и общие данные, в том числе на других дисках: деинсталляторы не изолированы от D:. Не удаляй программы, нужные играм.\r\n\r\nЕсли запись приложения остается или произошла ошибка, очередь остановится для проверки.";
        if(confirm(L"Подтверждение удаления программ",text))startWork([selected]{uninstallApps(selected);});
    }
}
void showHelp(){
    MessageBoxW(windowHandle,
        L"1. Дождись сканирования и нажми «Очистить выбранное»: удаляются только старые временные файлы на C:.\n\n"
        L"2. На вкладке «Программы» вручную отметь ненужные приложения. После одного подтверждения их штатные деинсталляторы запускаются по очереди. Некоторые показывают свои окна.\n\n"
        L"Windows, распознанные драйверы, Steam, Discord, Chrome, игры и приложения вне C: исключены. Это консервативные подсказки, а не полное определение всех зависимостей.\n\n"
        L"Документы, загрузки и сохранения не удаляются автоматически. Нет универсального способа стереть всё остальное без проверки. Для доступа к Windows\\Temp можно перезапустить программу от администратора.\n\n"
        L"Программа не выходит в интернет, не ставит автозапуск, не меняет права файлов и не чистит реестр. Закрытие окна завершает программу. Windows 11 x64; версия 1.0.",
        L"Как пользоваться",MB_OK|MB_ICONINFORMATION);
}
LRESULT CALLBACK wndProc(HWND h,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:{
        windowHandle=h;
        normalFont=CreateFontW(-px(16),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        titleFont=CreateFontW(-px(30),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        heading=control(L"STATIC",L"Очистка C:",SS_LEFT,0);SendMessageW(heading,WM_SETFONT,reinterpret_cast<WPARAM>(titleFont),TRUE);
        subtitle=control(L"STATIC",L"Windows 11 · анализ места на C:, включая AppData",SS_LEFT,0);
        keepLabel=control(L"STATIC",L"Сохраняем: Windows · драйверы · Steam · Discord · Chrome · игры на D:",SS_LEFT,0);
        tabs=control(WC_TABCONTROLW,L"",WS_TABSTOP,ID_TABS);
        for(int i=0;i<4;++i){const wchar_t* titles[]={L"Очистка файлов",L"Программы",L"Журнал",L"Крупные файлы и папки"};TCITEMW item{};item.mask=TCIF_TEXT;item.pszText=const_cast<wchar_t*>(titles[i]);TabCtrl_InsertItem(tabs,i,&item);}
        TabCtrl_SetCurSel(tabs,3);
        hintLabel=control(L"STATIC",L"Сканирование ничего не удаляет.",SS_LEFT,0);
        list=control(WC_LISTVIEWW,L"",WS_TABSTOP|LVS_REPORT|LVS_SHOWSELALWAYS,ID_LIST);
        ListView_SetExtendedListViewStyle(list,LVS_EX_FULLROWSELECT|LVS_EX_CHECKBOXES|LVS_EX_DOUBLEBUFFER);
        logEdit=control(L"EDIT",L"",WS_TABSTOP|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|ES_AUTOHSCROLL,0);
        scanButton=control(L"BUTTON",L"Сканировать",WS_TABSTOP|BS_PUSHBUTTON,ID_SCAN);
        actionButton=control(L"BUTTON",L"Очистить выбранное",WS_TABSTOP|BS_PUSHBUTTON,ID_ACTION);
        stopButton=control(L"BUTTON",L"Остановить",WS_TABSTOP|BS_PUSHBUTTON,ID_STOP);
        adminButton=control(L"BUTTON",L"От администратора",WS_TABSTOP|BS_PUSHBUTTON,ID_ADMIN);
        helpButton=control(L"BUTTON",L"Справка",WS_TABSTOP|BS_PUSHBUTTON,ID_HELP);
        statusLabel=control(L"STATIC",L"Подготовка…",SS_LEFT,0);renderList();return 0;
    }
    case WM_SIZE:layout();return 0;
    case WM_GETMINMAXINFO:{auto* info=reinterpret_cast<MINMAXINFO*>(lp);info->ptMinTrackSize.x=px(1000);info->ptMinTrackSize.y=px(650);return 0;}
    case WM_COMMAND:
        switch(LOWORD(wp)){
        case ID_SCAN:if(activeTab==3)startWork([]{analyzeLarge();});else startWork([]{scanAll();});break;
        case ID_ACTION:doAction();break;
        case ID_STOP:model.cancel=true;status(L"Остановка после текущего файла или деинсталлятора…");break;
        case ID_HELP:showHelp();break;
        case ID_ADMIN:{
            if(model.busy)break;wchar_t self[32768];DWORD n=GetModuleFileNameW(nullptr,self,32768);if(!n||n>=32768)break;
            auto result=reinterpret_cast<INT_PTR>(ShellExecuteW(h,L"runas",self,nullptr,nullptr,SW_SHOWNORMAL));
            if(result>32)PostMessageW(h,WM_CLOSE,0,0);else MessageBoxW(h,L"Перезапуск не выполнен. Можно продолжить без повышения прав.",L"Очистка C:",MB_OK|MB_ICONINFORMATION);break;
        }}return 0;
    case WM_NOTIFY:{
        auto* hdr=reinterpret_cast<NMHDR*>(lp);
        if(hdr->hwndFrom==tabs&&hdr->code==TCN_SELCHANGE){activeTab=TabCtrl_GetCurSel(tabs);renderList();return 0;}
        if(hdr->hwndFrom==list&&!rebuilding){
            if(hdr->code==NM_DBLCLK&&activeTab==3){
                auto* click=reinterpret_cast<NMITEMACTIVATE*>(lp);wstring path;
                {std::lock_guard<std::mutex> lock(model.mutex);if(click->iItem>=0&&size_t(click->iItem)<largeEntries.size())path=largeEntries[size_t(click->iItem)].path;}
                if(!path.empty()){wstring exe=model.windows+L"\\explorer.exe";wstring args=L"/select,\""+path+L"\"";ShellExecuteW(h,L"open",exe.c_str(),args.c_str(),nullptr,SW_SHOWNORMAL);}return 0;
            }

            if(hdr->code==LVN_ITEMCHANGING){
                auto* change=reinterpret_cast<NMLISTVIEW*>(lp);
                if(change->iItem>=0&&(change->uChanged&LVIF_STATE)&&((change->uNewState&LVIS_STATEIMAGEMASK)==INDEXTOSTATEIMAGEMASK(2))){
                    std::lock_guard<std::mutex> lock(model.mutex);size_t i=size_t(change->iItem);
                    if(activeTab==1&&(i>=model.apps.size()||!model.apps[i].reason.empty()))return TRUE;
                    if(activeTab==0&&(i>=model.groups.size()||model.groups[i].count==0||!model.scanned))return TRUE;
                }
            }
            if(hdr->code==LVN_ITEMCHANGED){refreshButtons();return 0;}
            if(hdr->code==NM_CUSTOMDRAW&&activeTab==1){
                auto* draw=reinterpret_cast<NMLVCUSTOMDRAW*>(lp);if(draw->nmcd.dwDrawStage==CDDS_PREPAINT)return CDRF_NOTIFYITEMDRAW;
                if(draw->nmcd.dwDrawStage==CDDS_ITEMPREPAINT){std::lock_guard<std::mutex> lock(model.mutex);size_t i=draw->nmcd.dwItemSpec;if(i<model.apps.size()&&!model.apps[i].reason.empty())draw->clrText=RGB(112,119,129);return CDRF_DODEFAULT;}
            }
        }break;
    }
    case WM_PROGRESS:showProgress();return 0;
    case WM_FINISHED:renderList();return 0;
    case WM_CTLCOLORSTATIC:{HDC dc=reinterpret_cast<HDC>(wp);SetBkColor(dc,GetSysColor(COLOR_WINDOW));SetTextColor(dc,GetSysColor(COLOR_WINDOWTEXT));return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));}
    case WM_CLOSE:
        if(model.busy){model.cancel=true;MessageBoxW(h,L"Остановка запрошена. Дождись завершения текущего файла или деинсталлятора, затем закрой окно.",L"Операция еще выполняется",MB_OK|MB_ICONINFORMATION);return 0;}
        DestroyWindow(h);return 0;
    case WM_DESTROY:
        if(worker.joinable())worker.join();DeleteObject(normalFont);DeleteObject(titleFont);PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(h,msg,wp,lp);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show){
    HRESULT com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    wchar_t win[32768];UINT n=GetWindowsDirectoryW(win,32768);model.windows=n&&n<32768?policy::normalize(win):L"";
    if(!policy::onC(model.windows)||model.windows.size()<=3){MessageBoxW(nullptr,L"Эта программа рассчитана на Windows, установленную на C:. Ничего не удалено.",L"Очистка C:",MB_OK|MB_ICONWARNING);return 1;}
    Handle c(CreateFileW(L"\\\\?\\C:\\",FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    policy::Identity root;
    if(!c.valid()||!identity(c.h,root)||(root.attributes&FILE_ATTRIBUTE_REPARSE_POINT)||!policy::equal(finalPath(c.h),L"C:\\")){
        MessageBoxW(nullptr,L"Не удалось проверить системный диск C:. Ничего не удалено.",L"Очистка C:",MB_OK|MB_ICONERROR);return 1;
    }
    model.volume=root.volume;model.local=knownFolder(FOLDERID_LocalAppData);
    HDC dc=GetDC(nullptr);dpi=GetDeviceCaps(dc,LOGPIXELSX);ReleaseDC(nullptr,dc);if(dpi<96)dpi=96;
    INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_LISTVIEW_CLASSES|ICC_TAB_CLASSES};InitCommonControlsEx(&controls);
    WNDCLASSEXW cls{};cls.cbSize=sizeof(cls);cls.lpfnWndProc=wndProc;cls.hInstance=instance;cls.lpszClassName=L"CDriveCleanerNative";
    cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);cls.hbrBackground=GetSysColorBrush(COLOR_WINDOW);cls.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(101));cls.hIconSm=cls.hIcon;
    if(!RegisterClassExW(&cls))return 1;
    RECT screen;SystemParametersInfoW(SPI_GETWORKAREA,0,&screen,0);int width=std::min<int>(px(1180),screen.right-screen.left),height=std::min<int>(px(790),screen.bottom-screen.top);
    HWND h=CreateWindowExW(0,cls.lpszClassName,L"C: — очистка Windows 11",WS_OVERLAPPEDWINDOW,(screen.right-width)/2,(screen.bottom-height)/2,width,height,nullptr,nullptr,instance,nullptr);
    if(!h)return 1;ShowWindow(h,show);UpdateWindow(h);
    logLine(L"Версия 1.2. При запуске выполняется только сканирование; удаление требует выбора и подтверждения.");
    if(!policy::onC(model.local))logLine(L"LocalAppData находится вне C:. Пользовательские временные файлы пропущены.");
    startWork([]{analyzeLarge();});MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(h,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
    if(SUCCEEDED(com))CoUninitialize();return int(message.wParam);
}
