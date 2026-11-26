#include "apps.h"
#include "gfx.h"
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <propkey.h>
#include <propvarutil.h>
#include <dwmapi.h>
#include <appmodel.h>
#include <fstream>
#include <sstream>

AppModel g_apps;
extern Settings g_settings;

// ---------------------------------------------------------------- helpers

static std::wstring WindowClass(HWND h) {
    wchar_t c[256] = {}; GetClassNameW(h, c, 256); return c;
}

static std::wstring ProcessExe(DWORD pid) {
    std::wstring out;
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p) {
        wchar_t buf[MAX_PATH * 2]; DWORD n = ARRAYSIZE(buf);
        if (QueryFullProcessImageNameW(p, 0, buf, &n)) out.assign(buf, n);
        CloseHandle(p);
    }
    return ToLower(out);
}

static std::wstring ProcessAumid(DWORD pid) {
    std::wstring out;
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p) {
        wchar_t buf[APPLICATION_USER_MODEL_ID_MAX_LENGTH]; UINT32 n = ARRAYSIZE(buf);
        if (GetApplicationUserModelId(p, &n, buf) == ERROR_SUCCESS) out = buf;
        CloseHandle(p);
    }
    return out;
}

static std::wstring WindowAumid(HWND h) {
    std::wstring out;
    ComPtr<IPropertyStore> ps;
    if (SUCCEEDED(SHGetPropertyStoreForWindow(h, IID_PPV_ARGS(&ps)))) {
        PROPVARIANT pv; PropVariantInit(&pv);
        if (SUCCEEDED(ps->GetValue(PKEY_AppUserModel_ID, &pv)) && pv.vt == VT_LPWSTR && pv.pwszVal) out = pv.pwszVal;
        PropVariantClear(&pv);
    }
    return out;
}

static bool IsCloaked(HWND h) {
    DWORD cloaked = 0;
    DwmGetWindowAttribute(h, DWMWA_CLOAKED, &cloaked, sizeof(cloaked));
    return cloaked != 0;
}

// The same heuristic the shell uses to decide whether a window gets a taskbar button.
static bool IsTaskbarWindow(HWND h) {
    if (!IsWindowVisible(h)) return false;
    LONG_PTR ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
    HWND owner = GetWindow(h, GW_OWNER);
    if (ex & WS_EX_APPWINDOW) { /* always */ }
    else {
        if (owner) return false;
        if (ex & WS_EX_TOOLWINDOW) return false;
        if (ex & WS_EX_NOACTIVATE) return false;
    }
    if (IsCloaked(h)) return false;
    DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId()) return false;
    std::wstring cls = WindowClass(h);
    if (cls == L"Progman" || cls == L"WorkerW" || cls == L"Shell_TrayWnd" || cls == L"Shell_SecondaryTrayWnd")
        return false;
    if (GetWindowTextLengthW(h) == 0 && cls != L"CabinetWClass") return false;
    return true;
}

static std::wstring FileDescription(const std::wstring& path) {
    DWORD dummy = 0, sz = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!sz) return {};
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(path.c_str(), 0, sz, buf.data())) return {};
    struct LangCp { WORD lang, cp; } *tr = nullptr; UINT trLen = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", (void**)&tr, &trLen) || trLen < sizeof(LangCp)) return {};
    wchar_t q[128];
    swprintf_s(q, L"\\StringFileInfo\\%04x%04x\\FileDescription", tr[0].lang, tr[0].cp);
    wchar_t* val = nullptr; UINT vlen = 0;
    if (VerQueryValueW(buf.data(), q, (void**)&val, &vlen) && vlen > 1) return std::wstring(val);
    return {};
}

static std::wstring FileStem(const std::wstring& path) {
    size_t s = path.find_last_of(L"\\/");
    std::wstring n = s == std::wstring::npos ? path : path.substr(s + 1);
    size_t d = n.find_last_of(L'.');
    if (d != std::wstring::npos) n = n.substr(0, d);
    return n;
}

static bool EndsWithI(const std::wstring& s, const wchar_t* suf) {
    size_t n = wcslen(suf);
    return s.size() >= n && _wcsicmp(s.c_str() + s.size() - n, suf) == 0;
}

// A launch target that still exists (shell: URIs are checked elsewhere).
static bool FileExistsPath(const std::wstring& p) {
    if (p.empty() || p.rfind(L"shell:", 0) == 0) return false;
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static std::vector<std::wstring> PathParts(const std::wstring& path) {
    std::vector<std::wstring> out;
    size_t s = 0;
    while (s < path.size()) {
        size_t t = path.find(L'\\', s);
        if (t == std::wstring::npos) t = path.size();
        if (t > s) out.push_back(ToLower(path.substr(s, t - s)));
        s = t + 1;
    }
    return out;
}

static std::wstring DirOf(const std::wstring& path) {
    size_t s = path.find_last_of(L"\\/");
    return s == std::wstring::npos ? std::wstring() : path.substr(0, s);
}

// Number of leading folders two exe paths share. C:\Program Files (x86)\Steam\... == 3.
static int CommonDirDepth(const std::wstring& a, const std::wstring& b) {
    auto pa = PathParts(DirOf(a)), pb = PathParts(DirOf(b));
    int n = 0;
    while (n < (int)pa.size() && n < (int)pb.size() && pa[n] == pb[n]) ++n;
    return n;
}

// "Steam" is a word-prefix of "Steam Client WebHelper" (the helper process Steam's UI runs in).
static bool IsWordPrefix(const std::wstring& shortName, const std::wstring& longName) {
    if (shortName.size() < 3 || shortName.size() > longName.size()) return false;
    if (_wcsnicmp(shortName.c_str(), longName.c_str(), shortName.size()) != 0) return false;
    if (shortName.size() == longName.size()) return false;
    wchar_t n = longName[shortName.size()];
    return n == L' ' || n == L'-' || n == L'(' || n == L'.';
}

// Same program in different versioned folders: Discord's stable Discord.exe vs
// Discord\app-1.0.9269\Discord.exe. Requires the same exe name and a shared install folder.
static bool SameAppExe(const std::wstring& a, const std::wstring& b) {
    if (a.empty() || b.empty()) return false;
    if (a == b) return true;
    if (_wcsicmp(FileStem(a).c_str(), FileStem(b).c_str()) != 0) return false;
    return CommonDirDepth(a, b) >= 3;
}

static ComPtr<ID2D1Bitmap1> BitmapFromHBITMAP(HBITMAP hbm) {
    DIBSECTION ds = {};
    if (!GetObjectW(hbm, sizeof(ds), &ds) || !ds.dsBm.bmBits || ds.dsBm.bmBitsPixel != 32) {
        // not a DIB section: copy through GetDIBits
        BITMAP bm = {};
        if (!GetObjectW(hbm, sizeof(bm), &bm)) return nullptr;
        ds.dsBm = bm;
        ds.dsBmih.biHeight = -bm.bmHeight;
        std::vector<uint32_t> px(bm.bmWidth * bm.bmHeight);
        BITMAPINFO bi = {}; bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
        bi.bmiHeader.biWidth = bm.bmWidth; bi.bmiHeader.biHeight = -bm.bmHeight;
        bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
        HDC hdc = GetDC(nullptr);
        GetDIBits(hdc, hbm, 0, bm.bmHeight, px.data(), &bi, DIB_RGB_COLORS);
        ReleaseDC(nullptr, hdc);
        D2D1_BITMAP_PROPERTIES1 bp = D2D1::BitmapProperties1(D2D1_BITMAP_OPTIONS_NONE,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));
        bool anyA = false;
        for (auto p : px) if (p >> 24) { anyA = true; break; }
        if (!anyA) for (auto& p : px) p |= 0xff000000;
        ComPtr<ID2D1Bitmap1> b;
        g_gfx.dc->CreateBitmap(D2D1::SizeU(bm.bmWidth, bm.bmHeight), px.data(), bm.bmWidth * 4, bp, &b);
        return b;
    }
    int w = ds.dsBm.bmWidth, h = ds.dsBm.bmHeight;
    bool bottomUp = ds.dsBmih.biHeight > 0;
    std::vector<uint32_t> px(w * h);
    for (int y = 0; y < h; ++y) {
        const uint32_t* src = (const uint32_t*)((const BYTE*)ds.dsBm.bmBits + ds.dsBm.bmWidthBytes * (bottomUp ? (h - 1 - y) : y));
        memcpy(&px[y * w], src, w * 4);
    }
    bool anyA = false, needPremul = false;
    for (auto p : px) {
        uint32_t a = p >> 24;
        if (a) anyA = true;
        if (((p >> 16) & 255) > a || ((p >> 8) & 255) > a || (p & 255) > a) needPremul = true;
    }
    if (!anyA) for (auto& p : px) p |= 0xff000000;
    else if (needPremul) {
        for (auto& p : px) {
            uint32_t a = p >> 24;
            uint32_t r = ((p >> 16) & 255) * a / 255, g = ((p >> 8) & 255) * a / 255, b = (p & 255) * a / 255;
            p = (a << 24) | (r << 16) | (g << 8) | b;
        }
    }
    D2D1_BITMAP_PROPERTIES1 bp = D2D1::BitmapProperties1(D2D1_BITMAP_OPTIONS_NONE,
        D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));
    ComPtr<ID2D1Bitmap1> b;
    g_gfx.dc->CreateBitmap(D2D1::SizeU(w, h), px.data(), w * 4, bp, &b);
    return b;
}

static ComPtr<ID2D1Bitmap1> IconFromShellItem(IShellItem* si) {
    ComPtr<IShellItemImageFactory> f;
    if (FAILED(si->QueryInterface(IID_PPV_ARGS(&f)))) return nullptr;
    HBITMAP hbm = nullptr;
    if (FAILED(f->GetImage({ 256, 256 }, SIIGBF_ICONONLY | SIIGBF_BIGGERSIZEOK, &hbm)) || !hbm) return nullptr;
    auto b = BitmapFromHBITMAP(hbm);
    DeleteObject(hbm);
    return b;
}

// HICON -> premultiplied D2D bitmap at the icon's native size (handles alpha and mask-only icons).
static ComPtr<ID2D1Bitmap1> IconFromHICON(HICON hi) {
    if (!hi) return nullptr;
    ICONINFO ii = {};
    if (!GetIconInfo(hi, &ii)) return nullptr;
    ComPtr<ID2D1Bitmap1> result;
    BITMAP bm = {};
    if (ii.hbmColor && GetObjectW(ii.hbmColor, sizeof(bm), &bm) && bm.bmWidth > 0) {
        int w = bm.bmWidth, h = bm.bmHeight;
        BITMAPINFO bi = {}; bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
        bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
        std::vector<uint32_t> px(w * h), mask(w * h);
        HDC hdc = GetDC(nullptr);
        GetDIBits(hdc, ii.hbmColor, 0, h, px.data(), &bi, DIB_RGB_COLORS);
        bool anyA = false;
        for (auto p : px) if (p >> 24) { anyA = true; break; }
        if (!anyA && ii.hbmMask) {
            GetDIBits(hdc, ii.hbmMask, 0, h, mask.data(), &bi, DIB_RGB_COLORS);
            for (int i = 0; i < w * h; ++i) px[i] = (px[i] & 0xffffff) | ((mask[i] & 0xffffff) ? 0 : 0xff000000u);
        }
        ReleaseDC(nullptr, hdc);
        for (auto& p : px) {
            uint32_t a = p >> 24;
            uint32_t r = ((p >> 16) & 255) * a / 255, g = ((p >> 8) & 255) * a / 255, b = (p & 255) * a / 255;
            p = (a << 24) | (r << 16) | (g << 8) | b;
        }
        D2D1_BITMAP_PROPERTIES1 bp = D2D1::BitmapProperties1(D2D1_BITMAP_OPTIONS_NONE,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));
        g_gfx.dc->CreateBitmap(D2D1::SizeU(w, h), px.data(), w * 4, bp, &result);
    }
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask) DeleteObject(ii.hbmMask);
    return result;
}

// Largest icon in a PE/ico file (what the taskbar uses); avoids the shell's "small icon in a frame" thumbnails.
static ComPtr<ID2D1Bitmap1> IconFromFile(const std::wstring& path, int index) {
    if (path.empty()) return nullptr;
    wchar_t expanded[MAX_PATH * 2];
    ExpandEnvironmentStringsW(path.c_str(), expanded, ARRAYSIZE(expanded));
    HICON hi = nullptr; UINT id = 0;
    if (PrivateExtractIconsW(expanded, index, 256, 256, &hi, &id, 1, LR_DEFAULTCOLOR) != 1 || !hi) return nullptr;
    auto b = IconFromHICON(hi);
    DestroyIcon(hi);
    return b;
}

static ComPtr<IShellItem> AppsFolderItem(const std::wstring& aumid, std::wstring* nameOut) {
    if (aumid.empty()) return nullptr;
    ComPtr<IShellItem> si;
    if (FAILED(SHCreateItemInKnownFolder(FOLDERID_AppsFolder, KF_FLAG_DONT_VERIFY, aumid.c_str(), IID_PPV_ARGS(&si))))
        return nullptr;
    PWSTR dn = nullptr;
    std::wstring name;
    if (SUCCEEDED(si->GetDisplayName(SIGDN_NORMALDISPLAY, &dn))) { name = dn; CoTaskMemFree(dn); }
    if (name.empty() || name == aumid) return nullptr;   // not a real Start-menu entry
    if (nameOut) *nameOut = name;
    return si;
}

// ---------------------------------------------------------------- model

std::shared_ptr<AppItem> AppModel::NewItem() {
    auto a = std::make_shared<AppItem>();
    a->id = nextId++;
    return a;
}

static bool LinkIconLocation(const std::wstring& lnk, std::wstring& path, int& index) {
    ComPtr<IShellLinkW> sl;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&sl)))) return false;
    ComPtr<IPersistFile> pf; sl.As(&pf);
    if (FAILED(pf->Load(lnk.c_str(), STGM_READ))) return false;
    wchar_t p[MAX_PATH * 2] = {};
    if (FAILED(sl->GetIconLocation(p, ARRAYSIZE(p), &index)) || !p[0]) return false;
    path = p;
    return true;
}

void AppModel::LoadIconAndName(AppItem& a, HWND sample) {
    std::wstring nm;
    bool packaged = a.exe.empty() || a.exe.find(L"\\windowsapps\\") != std::wstring::npos;
    if (!packaged) {
        std::wstring ip; int ii = 0;
        if (EndsWithI(a.launch, L".lnk") && LinkIconLocation(a.launch, ip, ii)) a.icon = IconFromFile(ip, ii);
        if (!a.icon) a.icon = IconFromFile(a.exe, 0);
    }
    if (!a.icon && !a.aumid.empty()) {
        if (auto si = AppsFolderItem(a.aumid, &nm)) {
            a.icon = IconFromShellItem(si.Get());
            if (a.name.empty()) a.name = nm;
        }
    }
    if (!a.icon && EndsWithI(a.launch, L".lnk")) {
        ComPtr<IShellItem> si;
        if (SUCCEEDED(SHCreateItemFromParsingName(a.launch.c_str(), nullptr, IID_PPV_ARGS(&si)))) a.icon = IconFromShellItem(si.Get());
    }
    if (!a.icon && !a.exe.empty()) {
        ComPtr<IShellItem> si;
        if (SUCCEEDED(SHCreateItemFromParsingName(a.exe.c_str(), nullptr, IID_PPV_ARGS(&si)))) a.icon = IconFromShellItem(si.Get());
    }
    if (!a.icon && sample) {
        HICON hi = nullptr;
        DWORD_PTR res = 0;
        if (SendMessageTimeoutW(sample, WM_GETICON, ICON_BIG, 0, SMTO_ABORTIFHUNG, 100, &res) && res) hi = (HICON)res;
        if (!hi) hi = (HICON)GetClassLongPtrW(sample, GCLP_HICON);
        a.icon = IconFromHICON(hi);
    }
    if (a.name.empty() && !a.exe.empty()) {
        a.name = FileDescription(a.exe);
        if (a.name.empty()) a.name = FileStem(a.exe);
    }
    if (a.name.empty() && sample) {
        wchar_t t[256] = {}; GetWindowTextW(sample, t, 256); a.name = t;
    }
}

void AppModel::ReloadIcons() {
    for (auto& a : items) {
        a->icon.Reset();
        LoadIconAndName(*a, a->windows.empty() ? nullptr : a->windows.front());
    }
    structureVersion++;
}

bool g_demoMode = false;

void AppModel::Init() {
    LoadPins();
    MigratePins();
    Refresh();
}

int AppModel::PinnedCount() const {
    int n = 0; for (auto& a : items) if (a->pinned) ++n; return n;
}

void AppModel::LoadPins() {
    std::wstring path = AppDataDir() + L"\\pins.txt";
    std::ifstream f(path);
    if (!f) {
        ImportTaskbarPins();
        SavePins();
        g_settings.pinsVersion = 3;
        g_settings.Save();
        return;
    }
    std::string line;
    while (std::getline(f, line)) {
        std::wstring w = FromUtf8(line);
        std::vector<std::wstring> parts;
        size_t s = 0, t;
        while ((t = w.find(L'\t', s)) != std::wstring::npos) { parts.push_back(w.substr(s, t - s)); s = t + 1; }
        parts.push_back(w.substr(s));
        if (parts.size() < 4) continue;
        auto a = NewItem();
        a->pinned = true;
        a->name = parts[0]; a->aumid = parts[1]; a->exe = ToLower(parts[2]); a->launch = parts[3];
        LoadIconAndName(*a, nullptr);
        items.push_back(a);
    }
    // Discord/Steam and other self-updating apps: a pin saved with a versioned exe path stops
    // working after one update. Point it back at the Start Menu shortcut / AppsFolder entry.
    bool repaired = false;
    for (auto& a : items) if (RepairPin(*a)) repaired = true;
    if (repaired) SavePins();
    structureVersion++;
}

void AppModel::SavePins() {
    std::ofstream f(AppDataDir() + L"\\pins.txt", std::ios::trunc);
    for (auto& a : items) {
        if (!a->pinned) continue;
        f << ToUtf8(a->name + L"\t" + a->aumid + L"\t" + a->exe + L"\t" + a->launch) << "\n";
    }
}

static bool ReadShortcut(const std::wstring& lnk, std::wstring& exe, std::wstring& aumid) {
    ComPtr<IShellLinkW> sl;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&sl)))) return false;
    ComPtr<IPersistFile> pf; sl.As(&pf);
    if (FAILED(pf->Load(lnk.c_str(), STGM_READ))) return false;
    wchar_t target[MAX_PATH * 2] = {};
    if (SUCCEEDED(sl->GetPath(target, ARRAYSIZE(target), nullptr, 0)) && target[0]) {
        wchar_t expanded[MAX_PATH * 2];
        ExpandEnvironmentStringsW(target, expanded, ARRAYSIZE(expanded));
        exe = ToLower(expanded);
    }
    if (exe.empty()) {
        // Shell links that have no target but an icon (File Explorer) still need an exe for
        // matching their own windows.
        wchar_t icon[MAX_PATH * 2] = {}; int index = 0;
        if (SUCCEEDED(sl->GetIconLocation(icon, ARRAYSIZE(icon), &index)) && icon[0]) {
            wchar_t expanded[MAX_PATH * 2];
            ExpandEnvironmentStringsW(icon, expanded, ARRAYSIZE(expanded));
            if (EndsWithI(expanded, L".exe")) exe = ToLower(expanded);
        }
    }
    ComPtr<IPropertyStore> ps;
    if (SUCCEEDED(sl.As(&ps))) {
        PROPVARIANT pv; PropVariantInit(&pv);
        if (SUCCEEDED(ps->GetValue(PKEY_AppUserModel_ID, &pv)) && pv.vt == VT_LPWSTR && pv.pwszVal) aumid = pv.pwszVal;
        PropVariantClear(&pv);
    }
    return true;
}

// ---------------------------------------------------------------- launch target repair
// Start Menu shortcuts and the shell's AppsFolder are the stable way to start an app: Discord
// and Steam change their own exe path on every update, so a pin that captured the exe path once
// stops launching (Discord) or launches an internal helper instead of the client (Steam).

struct ShellEntry {
    std::wstring name;      // display name, e.g. "Steam"
    std::wstring aumid;     // real AppUserModelID when the entry has one
    std::wstring exe;       // filesystem target (lowercase)
    std::wstring launch;    // .lnk path or shell:AppsFolder\...
};

static void EnumerateShortcutDir(std::vector<ShellEntry>& out, const std::wstring& dir, bool recurse) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"*.lnk").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            ShellEntry e;
            e.launch = dir + fd.cFileName;
            e.name = FileStem(e.launch);
            ReadShortcut(e.launch, e.exe, e.aumid);
            out.push_back(std::move(e));
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (!recurse) return;
    HANDLE d = FindFirstFileW((dir + L"*").c_str(), &fd);
    if (d == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        EnumerateShortcutDir(out, dir + fd.cFileName + L"\\", true);
    } while (FindNextFileW(d, &fd));
    FindClose(d);
}

static const std::vector<ShellEntry>& StartMenuEntries() {
    static std::vector<ShellEntry> entries;
    static bool loaded = false;
    if (loaded) return entries;
    loaded = true;
    PWSTR p = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Programs, 0, nullptr, &p)) && p) {
        EnumerateShortcutDir(entries, std::wstring(p) + L"\\", true);
        CoTaskMemFree(p);
    }
    p = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_CommonPrograms, 0, nullptr, &p)) && p) {
        EnumerateShortcutDir(entries, std::wstring(p) + L"\\", true);
        CoTaskMemFree(p);
    }
    p = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &p)) && p) {
        std::wstring base = std::wstring(p) + L"\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\";
        CoTaskMemFree(p);
        EnumerateShortcutDir(entries, base + L"TaskBar\\", false);
        // apps with their own AppUserModelID (Steam) are pinned here, not in the TaskBar folder
        WIN32_FIND_DATAW fd;
        std::wstring imp = base + L"ImplicitAppShortcuts\\";
        HANDLE d = FindFirstFileW((imp + L"*").c_str(), &fd);
        if (d != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
                EnumerateShortcutDir(entries, imp + fd.cFileName + L"\\", false);
            } while (FindNextFileW(d, &fd));
            FindClose(d);
        }
    }
    return entries;
}

static const std::vector<ShellEntry>& AppsFolderEntries() {
    static std::vector<ShellEntry> entries;
    static bool loaded = false;
    if (loaded) return entries;
    loaded = true;
    ComPtr<IShellItem> folder;
    if (FAILED(SHGetKnownFolderItem(FOLDERID_AppsFolder, KF_FLAG_DONT_VERIFY, nullptr, IID_PPV_ARGS(&folder)))) return entries;
    ComPtr<IEnumShellItems> en;
    if (FAILED(folder->BindToHandler(nullptr, BHID_EnumItems, IID_PPV_ARGS(&en)))) return entries;
    ComPtr<IShellItem> item;
    while (en->Next(1, &item, nullptr) == S_OK) {
        ShellEntry e;
        PWSTR nm = nullptr, parsing = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_NORMALDISPLAY, &nm)) && nm) e.name = nm;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING, &parsing)) && parsing && *parsing) {
            std::wstring id = parsing;
            e.launch = L"shell:AppsFolder\\" + id;
            // a real AUMID (Discord's com.squirrel.Discord.Discord), not a path / GUID parsing name
            if (id.find(L'\\') == std::wstring::npos && id.find(L'/') == std::wstring::npos &&
                id.find(L':') == std::wstring::npos) e.aumid = id;
        }
        ComPtr<IShellItem2> si2;
        ComPtr<IPropertyStore> ps;
        if (SUCCEEDED(item.As(&si2)) && SUCCEEDED(si2->GetPropertyStore(GPS_DEFAULT, IID_PPV_ARGS(&ps)))) {
            PROPVARIANT pv; PropVariantInit(&pv);
            if (SUCCEEDED(ps->GetValue(PKEY_Link_TargetParsingPath, &pv)) && pv.vt == VT_LPWSTR && pv.pwszVal) {
                std::wstring t = pv.pwszVal;
                if (t.find(L'\\') != std::wstring::npos) e.exe = ToLower(t);
            }
            PropVariantClear(&pv);
        }
        if (!e.name.empty() && !e.launch.empty()) entries.push_back(std::move(e));
        CoTaskMemFree(nm);
        CoTaskMemFree(parsing);
    }
    return entries;
}

static int AppMatchScore(const AppItem& a, const ShellEntry& e) {
    if (e.exe.empty() || !FileExistsPath(e.exe)) return -1;
    int score = 0;
    std::wstring ae = ToLower(a.exe), ee = ToLower(e.exe);
    if (!a.aumid.empty() && !e.aumid.empty() && _wcsicmp(a.aumid.c_str(), e.aumid.c_str()) == 0) score += 1000;
    if (!ae.empty() && ae == ee) score += 600;
    else if (!ae.empty() && _wcsicmp(FileStem(ae).c_str(), FileStem(ee).c_str()) == 0) score += 300;
    if (!a.name.empty() && !e.name.empty()) {
        if (_wcsicmp(a.name.c_str(), e.name.c_str()) == 0) score += 200;
        else if (IsWordPrefix(e.name, a.name) || IsWordPrefix(a.name, e.name)) score += 120;
    }
    int root = CommonDirDepth(ae, ee);
    if (root >= 3) score += 20 * std::min(root, 6);
    return score;
}

struct CanonicalApp {
    bool valid = false;
    std::wstring launch, exe, aumid, name;
};

static CanonicalApp FindCanonicalApp(const AppItem& a) {
    CanonicalApp best;
    int bestScore = 0;
    auto consider = [&](const ShellEntry& e, int bonus) {
        int s = AppMatchScore(a, e);
        if (s < 0) return;
        s += bonus;   // a Start Menu shortcut carries the app's AUMID; prefer it over a bare exe
        if (s < 150) return;
        bool better = s > bestScore;
        if (s == bestScore && best.valid && PathParts(e.exe).size() < PathParts(best.exe).size()) better = true;
        if (!better) return;
        bestScore = s;
        best.valid = true;
        best.launch = e.launch;
        best.exe = e.exe;
        best.aumid = e.aumid;
        best.name = e.name;
    };
    for (auto& e : StartMenuEntries()) consider(e, 20);
    for (auto& e : AppsFolderEntries()) consider(e, 0);
    return best;
}

bool AppModel::RepairPin(AppItem& a) {
    std::wstring nm;
    if (!a.aumid.empty() && a.aumid.find(L'!') != std::wstring::npos && AppsFolderItem(a.aumid, &nm)) {
        std::wstring launch = L"shell:AppsFolder\\" + a.aumid;
        if (a.launch == launch) return false;
        a.launch = launch;
        return true;
    }

    bool shellLaunch = a.launch.rfind(L"shell:", 0) == 0;
    bool missing = !shellLaunch && !FileExistsPath(a.launch);
    if (shellLaunch && !a.aumid.empty() && !AppsFolderItem(a.aumid, &nm)) missing = true;

    // A shortcut still points at the app after it updates itself: follow it and keep its AUMID.
    if (!shellLaunch && EndsWithI(a.launch, L".lnk") && FileExistsPath(a.launch)) {
        std::wstring exe, aumid;
        if (ReadShortcut(a.launch, exe, aumid) && !exe.empty() && FileExistsPath(exe)) {
            bool changed = false;
            if (_wcsicmp(a.exe.c_str(), exe.c_str()) != 0) { a.exe = exe; changed = true; }
            if (a.aumid.empty() && !aumid.empty()) { a.aumid = aumid; changed = true; }
            if (changed) {
                a.icon.Reset();
                LoadIconAndName(a, a.windows.empty() ? nullptr : a.windows.front());
            }
            return changed;
        }
    }

    std::wstring current = a.exe;
    if (current.empty() && !shellLaunch) current = a.launch;
    CanonicalApp c = FindCanonicalApp(a);
    if (!c.valid) return false;
    // only step in when the saved path is gone, or when it points at a helper deep inside an
    // install directory while the app's own launcher sits higher up (Steam Client WebHelper)
    bool shallower = !current.empty() && PathParts(c.exe).size() + 1 < PathParts(current).size();
    if (!missing && !shallower) return false;

    bool changed = false;
    if (!c.launch.empty() && _wcsicmp(a.launch.c_str(), c.launch.c_str()) != 0) { a.launch = c.launch; changed = true; }
    if (!c.exe.empty() && _wcsicmp(a.exe.c_str(), c.exe.c_str()) != 0) { a.exe = c.exe; changed = true; }
    if (a.aumid.empty() && !c.aumid.empty()) { a.aumid = c.aumid; changed = true; }
    if (!c.name.empty() && (a.name.empty() || IsWordPrefix(c.name, a.name)) && a.name != c.name) { a.name = c.name; changed = true; }
    if (changed) {
        Log(L"repaired pin %s -> %s (%s)", a.name.c_str(), a.launch.c_str(), a.exe.c_str());
        a.icon.Reset();
        LoadIconAndName(a, a.windows.empty() ? nullptr : a.windows.front());
    }
    return changed;
}

// A running app has no saved launch target until it is pinned; use its Start Menu entry (stable
// across self-updates) instead of the process exe it happens to be running from.
void AppModel::EnsureLaunch(AppItem& a) {
    if (!a.launch.empty()) return;
    CanonicalApp c = FindCanonicalApp(a);
    std::wstring nm;
    if (c.valid) {
        a.launch = c.launch;
        if (!c.exe.empty()) a.exe = c.exe;
        if (a.aumid.empty() && !c.aumid.empty()) a.aumid = c.aumid;
        if (!c.name.empty() && (a.name.empty() || IsWordPrefix(c.name, a.name))) a.name = c.name;
    } else if (!a.aumid.empty() && AppsFolderItem(a.aumid, &nm)) {
        a.launch = L"shell:AppsFolder\\" + a.aumid;
    } else {
        a.launch = a.exe;
    }
    a.icon.Reset();
    LoadIconAndName(a, a.windows.empty() ? nullptr : a.windows.front());
}

// The taskbar's own pin list (binary PIDL blob). Store (MSIX) apps are pinned only here - as
// "PackageFamily!AppId" - while desktop apps also have a .lnk; the blob gives the pin order.
static std::wstring TaskbandBlob() {
    DWORD size = 0;
    const wchar_t* key = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband";
    if (RegGetValueW(HKEY_CURRENT_USER, key, L"Favorites", RRF_RT_REG_BINARY, nullptr, nullptr, &size) != ERROR_SUCCESS || size < 2) return {};
    std::wstring s(size / 2, L'\0');
    RegGetValueW(HKEY_CURRENT_USER, key, L"Favorites", RRF_RT_REG_BINARY, nullptr, s.data(), &size);
    return s;
}

// AUMIDs of pinned store apps, in pin order, with their position in the blob
static std::vector<std::pair<size_t, std::wstring>> PackagedPins(const std::wstring& blob) {
    std::vector<std::pair<size_t, std::wstring>> out;
    auto isName = [](wchar_t c) { return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'.' || c == L'-' || c == L'_'; };
    for (size_t bang = blob.find(L'!'); bang != std::wstring::npos; bang = blob.find(L'!', bang + 1)) {
        size_t b = bang; while (b > 0 && isName(blob[b - 1])) --b;
        size_t e = bang + 1; while (e < blob.size() && isName(blob[e])) ++e;
        std::wstring fam = blob.substr(b, bang - b), app = blob.substr(bang + 1, e - bang - 1);
        size_t us = fam.rfind(L'_');   // PackageName_publisherId (13 chars)
        if (us == std::wstring::npos || fam.size() - us - 1 != 13 || us < 2 || app.empty()) continue;
        std::wstring id = fam + L"!" + app;
        if (std::none_of(out.begin(), out.end(), [&](auto& p) { return p.second == id; })) out.push_back({ b, id });
    }
    return out;
}

static std::wstring PackageFamily(const std::wstring& aumid) {
    size_t bang = aumid.find(L'!');
    return bang == std::wstring::npos ? std::wstring() : ToLower(aumid.substr(0, bang));
}

// A pin on the Windows taskbar, in taskbar order. Kept separate from AppItem so the same
// collection can both seed a fresh pins.txt and add newly pinned apps to an existing one.
struct TaskbarPin {
    std::wstring name, aumid, exe, launch;
    size_t pos = SIZE_MAX;
};

static bool SamePinIdentity(const TaskbarPin& a, const std::wstring& aumid, const std::wstring& exe) {
    if (!a.aumid.empty() && !aumid.empty() && _wcsicmp(a.aumid.c_str(), aumid.c_str()) == 0) return true;
    if (!a.exe.empty() && !exe.empty() && _wcsicmp(a.exe.c_str(), exe.c_str()) == 0) return true;
    std::wstring af = PackageFamily(a.aumid), bf = PackageFamily(aumid);
    return !af.empty() && af == bf;
}

static std::vector<TaskbarPin> CollectTaskbarPins() {
    std::vector<TaskbarPin> out;
    PWSTR p = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &p))) return out;
    std::wstring base = std::wstring(p) + L"\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\";
    CoTaskMemFree(p);
    std::wstring blob = TaskbandBlob();

    auto add = [&](TaskbarPin pin, size_t pos) {
        for (auto& it : out) if (SamePinIdentity(it, pin.aumid, pin.exe)) return;
        pin.pos = pos;
        out.push_back(std::move(pin));
    };
    auto addShortcut = [&](const std::wstring& lnk, const wchar_t* fileName) {
        TaskbarPin pin;
        pin.name = FileStem(lnk);
        pin.launch = lnk;
        ReadShortcut(lnk, pin.exe, pin.aumid);
        size_t pos = blob.find(fileName);
        if (pos == std::wstring::npos && !pin.aumid.empty()) pos = blob.find(pin.aumid);
        add(std::move(pin), pos);
    };

    std::wstring dir = base + L"TaskBar\\";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"*.lnk").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            addShortcut(dir + fd.cFileName, fd.cFileName);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    // Apps that carry their own AppUserModelID (Steam) are pinned under ImplicitAppShortcuts,
    // not in the TaskBar folder. Missing them made Steam look like a running helper process.
    std::wstring imp = base + L"ImplicitAppShortcuts\\";
    HANDLE d = FindFirstFileW((imp + L"*").c_str(), &fd);
    if (d != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            std::wstring sub = imp + fd.cFileName + L"\\";
            WIN32_FIND_DATAW lfd;
            HANDLE l = FindFirstFileW((sub + L"*.lnk").c_str(), &lfd);
            if (l == INVALID_HANDLE_VALUE) continue;
            do {
                addShortcut(sub + lfd.cFileName, lfd.cFileName);
            } while (FindNextFileW(l, &lfd));
            FindClose(l);
        } while (FindNextFileW(d, &fd));
        FindClose(d);
    }
    for (auto& [pos, id] : PackagedPins(blob)) {
        TaskbarPin pin;
        pin.aumid = id;
        pin.launch = L"shell:AppsFolder\\" + id;
        add(std::move(pin), pos);
    }
    // Some store pins put only the package family in the blob (Apple Music), so the app id after
    // '!' is not there to read. Ask the shell which AppsFolder entry belongs to that family.
    for (auto& e : AppsFolderEntries()) {
        size_t bang = e.aumid.find(L'!');
        if (bang == std::wstring::npos || bang < 2) continue;
        std::wstring fam = e.aumid.substr(0, bang);
        size_t pos = blob.find(fam);
        if (pos == std::wstring::npos) continue;
        TaskbarPin pin;
        pin.name = e.name;
        pin.aumid = e.aumid;
        pin.launch = e.launch;
        add(std::move(pin), pos);
    }
    std::stable_sort(out.begin(), out.end(), [](auto& a, auto& b) { return a.pos < b.pos; });
    return out;
}

void AppModel::ImportTaskbarPins() {
    for (auto& pin : CollectTaskbarPins()) {
        auto a = NewItem();
        a->pinned = true;
        a->name = pin.name;
        a->aumid = pin.aumid;
        a->exe = pin.exe;
        a->launch = pin.launch;
        LoadIconAndName(*a, nullptr);
        items.push_back(a);
        Log(L"imported pin %s (%s | %s)", a->name.c_str(), a->exe.c_str(), a->aumid.c_str());
    }
}

// A stable identity for "which taskbar pins have we already seen". AUMID first (survives
// updates), then the exe path, then the .lnk path.
static std::wstring PinIdentity(const TaskbarPin& p) {
    if (!p.aumid.empty()) return ToLower(p.aumid);
    if (!p.exe.empty()) return L"exe:" + ToLower(p.exe);
    return L"lnk:" + ToLower(p.launch);
}

// Add taskbar pins that are missing from an existing pins.txt. On the one-time migration
// (addAllMissing) every missing pin is added; afterwards only apps newly pinned to the taskbar
// are added, so unpinning something in the dock is not undone on the next launch.
bool AppModel::SyncTaskbarPins(bool addAllMissing) {
    auto pins = CollectTaskbarPins();
    if (pins.empty()) return false;
    auto matches = [](const AppItem& a, const TaskbarPin& p) {
        if (!p.aumid.empty() && !a.aumid.empty() && _wcsicmp(a.aumid.c_str(), p.aumid.c_str()) == 0) return true;
        std::wstring pf = PackageFamily(p.aumid), af = PackageFamily(a.aumid);
        if (!pf.empty() && pf == af) return true;
        if (!p.exe.empty() && !a.exe.empty() && _wcsicmp(a.exe.c_str(), p.exe.c_str()) == 0) return true;
        if (!p.launch.empty() && _wcsicmp(a.launch.c_str(), p.launch.c_str()) == 0) return true;
        return false;
    };

    std::unordered_map<std::wstring, int> seen;
    bool seedOnly = !addAllMissing;
    {
        std::ifstream f(AppDataDir() + L"\\taskbar_seen.txt");
        if (f) {
            seedOnly = false;
            std::string line;
            while (std::getline(f, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty()) seen[FromUtf8(line)] = 1;
            }
        }
    }

    bool added = false;
    for (size_t i = 0; i < pins.size(); ++i) {
        auto& p = pins[i];
        if (seedOnly || (!addAllMissing && seen.count(PinIdentity(p)))) continue;
        auto it = std::find_if(items.begin(), items.end(), [&](auto& a) { return matches(*a, p); });
        if (it != items.end()) {
            if (!(*it)->pinned) {   // the app is running but was not pinned in the dock yet
                auto sp = *it;
                SetPinned(*sp, true);
                added = true;
            }
            continue;
        }
        auto a = NewItem();
        a->pinned = true;
        a->name = p.name;
        a->aumid = p.aumid;
        a->exe = p.exe;
        a->launch = p.launch;
        LoadIconAndName(*a, nullptr);
        int at = PinnedCount();
        for (size_t j = i + 1; j < pins.size(); ++j) {
            auto next = std::find_if(items.begin(), items.begin() + PinnedCount(), [&](auto& a2) { return matches(*a2, pins[j]); });
            if (next != items.begin() + PinnedCount()) { at = (int)(next - items.begin()); break; }
        }
        items.insert(items.begin() + at, a);
        Log(L"added taskbar pin %s (%s | %s)", a->name.c_str(), a->exe.c_str(), a->aumid.c_str());
        added = true;
    }

    // remember what the taskbar had, so a dock pin the user removed stays removed
    {
        std::ofstream f(AppDataDir() + L"\\taskbar_seen.txt", std::ios::trunc);
        for (auto& p : pins) f << ToUtf8(PinIdentity(p)) << "\n";
    }
    if (added) { structureVersion++; SavePins(); }
    return added;
}

// Pins saved by older versions: add store apps (v2) and taskbar apps that were pinned later (v3).
void AppModel::MigratePins() {
    if (g_settings.pinsVersion < 2) {
        std::wstring blob = TaskbandBlob();
        int added = 0;
        for (auto& [pos, id] : PackagedPins(blob)) {
            std::wstring fam = PackageFamily(id);
            bool have = std::any_of(items.begin(), items.end(), [&](auto& it) { return !it->aumid.empty() && PackageFamily(it->aumid) == fam; });
            if (have) continue;
            auto a = NewItem();
            a->pinned = true;
            a->aumid = id;
            a->launch = L"shell:AppsFolder\\" + id;
            LoadIconAndName(*a, nullptr);
            items.insert(items.begin() + PinnedCount(), a);
            added++;
            Log(L"migrated store pin %s (%s)", a->name.c_str(), id.c_str());
        }
        if (added) { structureVersion++; SavePins(); }
        g_settings.pinsVersion = 2;
        g_settings.Save();
    }
    if (g_settings.pinsVersion < 3) {
        SyncTaskbarPins(true);      // one-time: add everything missing from the taskbar
        g_settings.pinsVersion = 3;
        g_settings.Save();
    } else {
        SyncTaskbarPins(false);     // afterwards only apps newly pinned to the taskbar
    }
}

void AppModel::PinFile(const std::wstring& path, int index) {
    auto a = NewItem();
    a->pinned = true;
    a->launch = path;
    if (EndsWithI(path, L".lnk")) { ReadShortcut(path, a->exe, a->aumid); a->name = FileStem(path); }
    else a->exe = ToLower(path);
    // same app already present? just pin/move it
    for (auto& it : items) {
        if ((!a->aumid.empty() && it->aumid == a->aumid) || (!a->exe.empty() && it->exe == a->exe)) {
            MoveTo(*it, index, true);
            return;
        }
    }
    LoadIconAndName(*a, nullptr);
    int pc = PinnedCount();
    index = std::clamp(index, 0, pc);
    items.insert(items.begin() + index, a);
    structureVersion++;
    SavePins();
    dirty = true;
}

void AppModel::SetPinned(AppItem& a, bool pinned) {
    if (a.pinned == pinned) return;
    if (pinned) {
        if (a.launch.empty()) EnsureLaunch(a);
        MoveTo(a, PinnedCount(), true);
        if (RepairPin(a)) SavePins();
    } else {
        a.pinned = false;
        // move to the running section (or drop entirely when not running)
        auto it = std::find_if(items.begin(), items.end(), [&](auto& p) { return p.get() == &a; });
        if (it == items.end()) return;
        auto sp = *it;
        items.erase(it);
        if (sp->Running()) items.insert(items.begin() + PinnedCount(), sp);
        structureVersion++;
        SavePins();
    }
}

void AppModel::MoveTo(AppItem& a, int index, bool pin) {
    auto it = std::find_if(items.begin(), items.end(), [&](auto& p) { return p.get() == &a; });
    if (it == items.end()) return;
    auto sp = *it;
    items.erase(it);
    if (pin) {
        if (sp->launch.empty()) EnsureLaunch(*sp);
        sp->pinned = true;
        index = std::clamp(index, 0, PinnedCount());
    } else {
        int pc = PinnedCount();
        index = std::clamp(index, pc, (int)items.size());
    }
    items.insert(items.begin() + index, sp);
    structureVersion++;
    SavePins();
}

std::shared_ptr<AppItem> AppModel::FindByWindow(HWND h) {
    for (auto& a : items)
        for (HWND w : a->windows) if (w == h) return a;
    return nullptr;
}

void AppModel::Refresh() {
    lastRefresh = NowSeconds();
    dirty = false;

    std::vector<HWND> wins;
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        if (IsTaskbarWindow(h)) ((std::vector<HWND>*)lp)->push_back(h);
        return TRUE;
    }, (LPARAM)&wins);

    std::unordered_map<HWND, WinCache> newCache;
    std::vector<size_t> prevCounts;
    for (auto& a : items) { prevCounts.push_back(a->windows.size()); a->windows.clear(); }

    bool structural = false;
    for (HWND h : wins) {
        WinCache wc;
        auto f = winCache.find(h);
        if (f != winCache.end()) {
            wc = f->second;
            // Some apps (Discord) set their AUMID just after the first window appears. Do not keep
            // the empty value from that first look forever.
            if (wc.aumid.empty() && wc.aumidTries < 4) {
                DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
                std::wstring late = WindowAumid(h);
                if (late.empty()) late = ProcessAumid(pid);
                if (!late.empty()) { wc.aumid = late; wc.family = PackageFamily(late); }
                wc.aumidTries++;
            }
        }
        else {
            DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
            wc.exe = ProcessExe(pid);
            wc.aumid = WindowAumid(h);
            std::wstring procAumid = ProcessAumid(pid);
            if (wc.aumid.empty()) wc.aumid = procAumid;
            // packaged apps may label their windows with their own AUMID; the package identifies them
            wc.family = PackageFamily(!procAumid.empty() ? procAumid : wc.aumid);
            if (EndsWithI(wc.exe, L"\\applicationframehost.exe")) {
                // UWP: the real app lives in a child CoreWindow from another process
                struct Ctx { DWORD host; DWORD found; } c{ pid, 0 };
                EnumChildWindows(h, [](HWND ch, LPARAM lp) -> BOOL {
                    auto* c = (Ctx*)lp; DWORD p = 0; GetWindowThreadProcessId(ch, &p);
                    if (p != c->host) { c->found = p; return FALSE; }
                    return TRUE;
                }, (LPARAM)&c);
                if (c.found) {
                    wc.exe = ProcessExe(c.found);
                    std::wstring pa = ProcessAumid(c.found);
                    if (wc.aumid.empty()) wc.aumid = pa;
                    if (!pa.empty()) wc.family = PackageFamily(pa);
                }
                if (wc.aumid.empty()) continue;   // suspended frame we can't identify yet
            }
            wc.valid = true;
        }
        newCache[h] = wc;

        std::shared_ptr<AppItem> match;
        if (!wc.aumid.empty())
            for (auto& a : items) if (_wcsicmp(a->aumid.c_str(), wc.aumid.c_str()) == 0) { match = a; break; }
        if (!match && !wc.family.empty())
            for (auto& a : items) if (!a->aumid.empty() && PackageFamily(a->aumid) == wc.family) { match = a; break; }
        if (!match && !wc.exe.empty())
            for (auto& a : items)
                if (a->exe == wc.exe && (a->aumid.empty() || wc.aumid.empty())) { match = a; break; }
        if (!match && !wc.exe.empty())
            for (auto& a : items)
                if (SameAppExe(a->exe, wc.exe) && (a->aumid.empty() || wc.aumid.empty())) { match = a; break; }
        if (!match && g_demoMode) continue;
        if (!match) {
            match = NewItem();
            match->aumid = wc.aumid;
            match->exe = wc.exe;
            LoadIconAndName(*match, h);
            items.push_back(match);
            Log(L"running app: %s (aumid %s, package %s)", match->name.c_str(), wc.aumid.c_str(), wc.family.c_str());
            prevCounts.push_back(0);
            structural = true;
        } else if (match->pinned && match->aumid.empty() && !wc.aumid.empty()) {
            match->aumid = wc.aumid;   // the window knows the app's AUMID even if the pin did not
            SavePins();
        }
        match->windows.push_back(h);
    }
    winCache.swap(newCache);

    // drop unpinned apps whose windows are gone
    double now = NowSeconds();
    for (size_t i = 0; i < items.size(); ++i) {
        auto& a = items[i];
        if (a->launchStarted > 0) {
            if (a->windows.size() > a->launchWindowCount || now - a->launchStarted > 8.0) a->launchStarted = 0;
        }
    }
    size_t before = items.size();
    items.erase(std::remove_if(items.begin(), items.end(), [](auto& a) { return !a->pinned && !a->Running(); }), items.end());
    if (items.size() != before) structural = true;

    // clear attention for the foreground app
    HWND fg = GetForegroundWindow();
    for (auto& a : items)
        if (a->attention && std::find(a->windows.begin(), a->windows.end(), fg) != a->windows.end()) a->attention = false;

    if (structural) structureVersion++;
}

void AppModel::Tick(double now) {
    if (dirty || now - lastRefresh > 1.0) Refresh();
}

void AppModel::OnShellHook(WPARAM code, LPARAM lp) {
    HWND h = (HWND)lp;
    switch (code) {
    case HSHELL_WINDOWCREATED:
    case HSHELL_WINDOWDESTROYED:
    case HSHELL_WINDOWREPLACED:
    case HSHELL_MONITORCHANGED:
        dirty = true;
        break;
    case HSHELL_WINDOWACTIVATED:
    case HSHELL_RUDEAPPACTIVATED: {
        if (auto a = FindByWindow(h)) a->attention = false;
        dirty = true;
        break;
    }
    case HSHELL_FLASH: {
        auto a = FindByWindow(h);
        if (!a) { Refresh(); a = FindByWindow(h); }
        if (!a) break;
        if (GetForegroundWindow() == h) break;
        double now = NowSeconds();
        bool fresh = !a->attention;
        a->attention = true;
        // bounce for a new notification; a window that keeps flashing re-bounces at most every 30 s
        if (fresh || now - a->lastAttentionBounce > 30.0) {
            a->lastAttentionBounce = now;
            attentionEvents.push_back({ a->id });
            Log(L"attention: %s", a->name.c_str());
        }
        break;
    }
    }
}

// ---------------------------------------------------------------- actions

void AppModel::ActivateWindow(HWND h) {
    if (!h || !IsWindow(h)) return;
    // A minimized window can remain the foreground window. Only an actually visible,
    // non-minimized foreground window means there is nothing to do.
    auto active = [h] {
        return GetForegroundWindow() == h && !IsIconic(h) && IsWindowVisible(h);
    };
    if (active()) return;
    HWND fg = GetForegroundWindow();

    // Restore synchronously. ShowWindowAsync queues the restore, so SetForegroundWindow can run
    // while the window is still iconic and be ignored (the intermittent "click does nothing").
    // UIPI blocks ShowWindow for windows owned by a higher-integrity process (Task Manager is
    // auto-elevated), so a failed restore is handled by SwitchToThisWindow further down.
    bool restoreBlocked = false;
    if (IsIconic(h)) {
        SetLastError(ERROR_SUCCESS);
        ShowWindow(h, SW_RESTORE);
        DWORD err = GetLastError();
        restoreBlocked = IsIconic(h) || err == ERROR_ACCESS_DENIED;
    } else if (!IsWindowVisible(h)) {
        SetLastError(ERROR_SUCCESS);
        ShowWindow(h, SW_SHOW);
        DWORD err = GetLastError();
        restoreBlocked = !IsWindowVisible(h) || err == ERROR_ACCESS_DENIED;
    }

    DWORD me = GetCurrentThreadId();
    DWORD targetThread = GetWindowThreadProcessId(h, nullptr);
    DWORD fgThread = fg ? GetWindowThreadProcessId(fg, nullptr) : 0;

    // Share the input queues with both the foreground and the target thread. Attaching to the
    // target as well is what lets SetForegroundWindow/SetActiveWindow stick for the target.
    bool attachTarget = targetThread && targetThread != me && AttachThreadInput(me, targetThread, TRUE);
    bool attachFg = fgThread && fgThread != me && fgThread != targetThread && AttachThreadInput(me, fgThread, TRUE);

    BringWindowToTop(h);
    SetForegroundWindow(h);
    SetActiveWindow(h);

    // Windows' foreground lock can still refuse the change (another app was foreground, the
    // restore animation is running, or the app is elevated). Verify and retry; a quick Alt tap
    // makes the shell treat this process as the last input owner and releases the lock.
    if (!active() && !restoreBlocked) {
        Log(L"activate: retry hwnd %p (fg %p, iconic %d, attach %d/%d)", h, fg, (int)IsIconic(h), (int)attachTarget, (int)attachFg);
        for (int attempt = 0; attempt < 4 && !active(); ++attempt) {
            INPUT in[2] = {};
            in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = VK_MENU;
            in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = VK_MENU; in[1].ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(2, in, sizeof(INPUT));
            if (IsIconic(h)) ShowWindow(h, SW_RESTORE);
            BringWindowToTop(h);
            SetForegroundWindow(h);
            if (active()) break;
            Sleep(15);
        }
    }

    if (attachFg) AttachThreadInput(me, fgThread, FALSE);
    if (attachTarget) AttachThreadInput(me, targetThread, FALSE);

    // A non-elevated dock cannot ShowWindow/SetForegroundWindow an elevated window. The calls
    // above then fail silently (or only make the still-minimized window "foreground"), which is
    // exactly the Task Manager click that did nothing. SwitchToThisWindow is handled by the
    // window manager rather than by the target's input queue, so it is not filtered by UIPI and
    // does restore minimized windows.
    if (!active()) {
        Log(L"activate: SwitchToThisWindow hwnd %p class %s (blocked %d, fg %p, iconic %d, visible %d)",
            h, WindowClass(h).c_str(), (int)restoreBlocked, GetForegroundWindow(), (int)IsIconic(h), (int)IsWindowVisible(h));
        SwitchToThisWindow(h, TRUE);
        // The restore can finish on the target's UI thread after this call returns. Wait briefly
        // so the diagnostic below does not report a success as a failure.
        for (int i = 0; i < 20 && !active(); ++i) Sleep(10);
    }

    if (!active()) Log(L"activate failed: hwnd %p class %s", h, WindowClass(h).c_str());
}

static std::wstring LaunchTargetOf(const AppItem& a) {
    std::wstring target = a.launch;
    if (target.empty()) target = !a.aumid.empty() ? L"shell:AppsFolder\\" + a.aumid : a.exe;
    if (target.rfind(L"shell:", 0) != 0 && !FileExistsPath(target)) {
        if (!a.exe.empty() && FileExistsPath(a.exe)) target = a.exe;
        else if (!a.aumid.empty()) target = L"shell:AppsFolder\\" + a.aumid;
    }
    return target;
}

static bool ShellLaunch(const std::wstring& target, const wchar_t* verb) {
    if (target.empty()) return false;
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_ASYNCOK | SEE_MASK_FLAG_NO_UI;
    sei.lpFile = target.c_str();
    sei.lpVerb = verb;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) != FALSE;
}

void AppModel::Launch(AppItem& a, int dockIndex, bool elevated) {
    std::wstring target = LaunchTargetOf(a);
    bool repaired = false;
    // A self-updating app left the pinned path behind: find its current launcher and retry.
    if ((target.empty() || (target.rfind(L"shell:", 0) != 0 && !FileExistsPath(target))) && !repaired) {
        repaired = RepairPin(a);
        target = LaunchTargetOf(a);
    }
    const wchar_t* verb = (elevated && target.rfind(L"shell:", 0) != 0) ? L"runas" : nullptr;   // Windows shows its own consent prompt
    bool ok = ShellLaunch(target, verb);
    if (!ok && !repaired && RepairPin(a)) {
        target = LaunchTargetOf(a);
        verb = (elevated && target.rfind(L"shell:", 0) != 0) ? L"runas" : nullptr;
        ok = ShellLaunch(target, verb);
    }
    if (ok) {
        a.launchStarted = NowSeconds();
        a.launchDock = dockIndex;
        a.launchWindowCount = a.windows.size();
    } else Log(L"launch failed %s (%lu)", target.c_str(), GetLastError());
}

void AppModel::Click(AppItem& a, int dockIndex) {
    if (a.windows.empty()) { Launch(a, dockIndex); return; }
    HWND fg = GetForegroundWindow();
    auto it = std::find(a.windows.begin(), a.windows.end(), fg);
    // A minimized window can still be the foreground window for a moment. Treating that as
    // "already active" used to minimize/cycle it again, so clicking the dock icon did nothing.
    if (it != a.windows.end() && !IsIconic(fg)) {
        if (a.windows.size() == 1) {
            PostMessageW(fg, WM_SYSCOMMAND, SC_MINIMIZE, 0);
        } else {
            // cycle: bring the bottom-most window of this app to the front
            ActivateWindow(a.windows.back());
        }
    } else if (it != a.windows.end()) {
        ActivateWindow(fg);   // the app's foreground window is minimized: restore it
    } else {
        ActivateWindow(a.windows.front());
    }
    a.attention = false;
}

void AppModel::CloseAll(AppItem& a) {
    for (HWND h : a.windows) PostMessageW(h, WM_CLOSE, 0, 0);
}
