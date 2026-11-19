#include "native_tray.h"
#include "system.h"
#include <shellapi.h>
#include <shldisp.h>
#include <uiautomation.h>

// The native taskbar stays "shown" (just invisible, see NativeTaskbar), so Explorer's own tray
// windows open normally when their buttons are pressed.
namespace nativetray {

bool ToggleDesktop() {
    // Same Shell action as the native taskbar button. No synthetic key presses,
    // per-window minimization, or locally maintained restore list.
    ComPtr<IShellDispatch4> shell;
    HRESULT hr = CoCreateInstance(CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&shell));
    if (SUCCEEDED(hr)) hr = shell->ToggleDesktop();
    if (FAILED(hr)) Log(L"show desktop failed: %08x", hr);
    return SUCCEEDED(hr);
}

// Stock Windows 11 taskbar (XAML): its tray buttons are only reachable through UI Automation.
// The overflow host can be positioned after Explorer creates it.
//
// The XAML tray content only exists in the automation tree while the taskbar is expanded; once it
// auto-hides (as the dock makes it) it can't be found any more. Elements found earlier keep
// working though, so they are looked up before the taskbar vanishes (CacheTrayButtons) and reused.
enum Button { Chevron, Network, Clock, ButtonCount };
static const wchar_t* kButtonClass[ButtonCount] = { L"SystemTray.NormalButton",    // first one: hidden icons
                                                    L"SystemTray.AccentButton",    // network / quick settings
                                                    L"SystemTray.OmniButton" };    // clock / calendar
static ComPtr<IUIAutomation> g_uia;
static ComPtr<IUIAutomationElement> g_button[ButtonCount];
static HWND g_buttonTray = nullptr;

static bool EnsureUia() {
    if (g_uia) return true;
    if (FAILED(CoCreateInstance(__uuidof(CUIAutomation), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&g_uia)))) return false;
    // a busy explorer must not freeze the dock: give up quickly
    ComPtr<IUIAutomation2> u2;
    if (SUCCEEDED(g_uia.As(&u2))) { u2->put_ConnectionTimeout(500); u2->put_TransactionTimeout(500); }
    return true;
}

static ComPtr<IUIAutomationElement> FindButton(HWND tray, Button b) {
    ComPtr<IUIAutomationElement> root, btn;
    ComPtr<IUIAutomationCondition> cls;
    VARIANT v; v.vt = VT_BSTR; v.bstrVal = SysAllocString(kButtonClass[b]);
    g_uia->CreatePropertyCondition(UIA_ClassNamePropertyId, v, &cls);
    VariantClear(&v);
    if (cls && SUCCEEDED(g_uia->ElementFromHandle(tray, &root)) && root)
        root->FindFirst(TreeScope_Descendants, cls.Get(), &btn);
    return btn;
}

void CacheTrayButtons(HWND tray) {
    HWND notify = FindWindowExW(tray, nullptr, L"TrayNotifyWnd", nullptr);
    if (notify && GetDlgItem(notify, 1502)) return;   // classic taskbar, no XAML buttons
    if (g_buttonTray != tray) { for (auto& b : g_button) b.Reset(); g_buttonTray = tray; }
    if (!EnsureUia()) return;
    for (int i = 0; i < ButtonCount; ++i)
        if (!g_button[i] && (g_button[i] = FindButton(tray, (Button)i))) Log(L"tray button %d cached", i);
}

static ComPtr<IUIAutomationElement> FindStartButton(HWND tray) {
    ComPtr<IUIAutomationElement> root, btn;
    ComPtr<IUIAutomationCondition> cond;
    VARIANT v; v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"StartButton");
    g_uia->CreatePropertyCondition(UIA_AutomationIdPropertyId, v, &cond);
    VariantClear(&v);
    if (cond && SUCCEEDED(g_uia->ElementFromHandle(tray, &root)) && root)
        root->FindFirst(TreeScope_Descendants, cond.Get(), &btn);
    return btn;
}

// One Start button per taskbar (primary and each secondary monitor).
static std::unordered_map<HWND, ComPtr<IUIAutomationElement>> g_startButton;

void CacheStartButton(HWND tray) {
    if (!tray || g_startButton.count(tray)) return;
    if (!EnsureUia()) return;
    auto b = FindStartButton(tray);
    if (!b) return;
    RECT r{};
    if (FAILED(b->get_CurrentBoundingRectangle(&r)) || r.right <= r.left || r.bottom <= r.top) return;
    POINT c = { (r.left + r.right) / 2, (r.top + r.bottom) / 2 };
    if (MonitorFromPoint(c, MONITOR_DEFAULTTONEAREST) != MonitorFromWindow(tray, MONITOR_DEFAULTTONEAREST)) return;
    g_startButton[tray] = b;
    Log(L"start button cached for taskbar %p rect %ld,%ld", tray, r.left, r.top);
}

// Passive cache fill: only when the taskbar is already expanded. Forcing it expanded would
// change the shell's work area and visibly move every window up and down.
void CacheStartButtons() {
    auto each = [&](HWND h) {
        if (!h || g_startButton.count(h)) return;
        MONITORINFO mi = { sizeof(mi) };
        if (!GetMonitorInfoW(MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST), &mi)) return;
        RECT wr{};
        if (!GetWindowRect(h, &wr) || wr.top >= mi.rcMonitor.bottom - 8) return;   // collapsed
        CacheStartButton(h);
    };
    each(FindWindowW(L"Shell_TrayWnd", nullptr));
    for (HWND s = nullptr; (s = FindWindowExW(nullptr, s, L"Shell_SecondaryTrayWnd", nullptr));) each(s);
}

bool IsShellPopupWindow(HWND w) {
    static HWND last = nullptr; static bool lastResult = false;   // the foreground rarely changes
    if (w == last) return lastResult;
    last = w; lastResult = false;
    DWORD pid = 0; GetWindowThreadProcessId(w, &pid);
    HANDLE p = pid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) : nullptr;
    if (!p) return false;
    wchar_t path[MAX_PATH]; DWORD n = MAX_PATH;
    if (QueryFullProcessImageNameW(p, 0, path, &n)) {
        const wchar_t* name = wcsrchr(path, L'\\'); name = name ? name + 1 : path;
        for (const wchar_t* shell : { L"StartMenuExperienceHost.exe", L"SearchHost.exe", L"SearchApp.exe",
                                      L"ShellExperienceHost.exe", L"ShellHost.exe" })
            if (!_wcsicmp(name, shell)) { lastResult = true; break; }
    }
    CloseHandle(p);
    return lastResult;
}

// Is the Start / search surface visibly on this monitor right now?
static bool StartVisibleOn(HMONITOR monitor) {
    HWND fg = GetForegroundWindow();
    if (!fg || !IsShellPopupWindow(fg)) return false;
    RECT r{};
    if (!GetWindowRect(fg, &r) || r.right - r.left < 80 || r.bottom - r.top < 80) return false;
    return MonitorFromWindow(fg, MONITOR_DEFAULTTONEAREST) == monitor;
}

// A Start/search surface on any monitor (used to avoid toggling it closed again while the
// shell is moving it from one monitor to the other).
static bool ShellPopupVisibleAny() {
    HWND fg = GetForegroundWindow();
    if (!fg || !IsShellPopupWindow(fg)) return false;
    RECT r{};
    return GetWindowRect(fg, &r) && r.right - r.left >= 80 && r.bottom - r.top >= 80;
}

// A UIA element can survive an Explorer restart and then point at the other monitor's Start
// button. Accept it only while its bounds still belong to the requested monitor.
static bool StartButtonOn(const ComPtr<IUIAutomationElement>& b, HMONITOR monitor) {
    if (!b) return false;
    RECT r{};
    if (FAILED(b->get_CurrentBoundingRectangle(&r))) return false;
    if (r.right <= r.left || r.bottom <= r.top) return false;
    POINT c = { (r.left + r.right) / 2, (r.top + r.bottom) / 2 };
    return MonitorFromPoint(c, MONITOR_DEFAULTTONEAREST) == monitor;
}

int StartPopupState(HMONITOR monitor) {
    HWND fg = GetForegroundWindow();
    if (!fg || !IsShellPopupWindow(fg)) return 0;
    RECT r{};
    if (!GetWindowRect(fg, &r) || r.right - r.left < 80 || r.bottom - r.top < 80) return 0;
    return MonitorFromWindow(fg, MONITOR_DEFAULTTONEAREST) == monitor ? 1 : 2;
}

bool OpenStart(HMONITOR monitor, int popupAtPress) {
    static std::unordered_map<HMONITOR, double> lastToggle;
    double now = NowSeconds();
    auto lt = lastToggle.find(monitor);
    if (lt != lastToggle.end() && now - lt->second < 0.30) return true;   // one click, one toggle
    Log(L"open start: monitor %p popupAtPress %d", monitor, popupAtPress);

    if (popupAtPress == 1) {
        // A Start menu is already open on this monitor: the click closes it. Esc goes to the
        // foreground flyout; wait for the close animation before deciding it failed.
        SendKeyCombo({ VK_ESCAPE });
        for (int i = 0; i < 20 && StartVisibleOn(monitor); ++i) Sleep(40);
        if (!StartVisibleOn(monitor)) { Log(L"start closed on monitor %p", monitor); return true; }
        // Still open after the animation: the Win key toggles it closed. If it opened on the
        // other monitor instead, close that one too.
        SendKeyCombo({ VK_LWIN });
        for (int i = 0; i < 15 && StartVisibleOn(monitor); ++i) Sleep(40);
        if (ShellPopupVisibleAny()) { SendKeyCombo({ VK_LWIN }); Sleep(150); }
        Log(L"start closed on monitor %p", monitor);
        return true;
    }
    if (popupAtPress == 2 && ShellPopupVisibleAny()) {
        // A Start menu is open on another monitor and the no-activate dock click did not dismiss
        // it. Close it first so the target toggle starts from a clean state.
        SendKeyCombo({ VK_LWIN });
        for (int i = 0; i < 25 && ShellPopupVisibleAny(); ++i) Sleep(40);
        Sleep(250);
    }

    bool toggled = false;
    g_taskbar.WithProtectedTaskbars([&]() -> bool {
        HWND tray = nullptr;
        auto consider = [&](HWND h) {
            if (!tray && h && MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) == monitor) tray = h;
        };
        consider(FindWindowW(L"Shell_TrayWnd", nullptr));
        for (HWND s = nullptr; !tray && (s = FindWindowExW(nullptr, s, L"Shell_SecondaryTrayWnd", nullptr));) consider(s);
        if (!tray) return false;

        // Use the Start button cached while the taskbar was expanded. Never force auto-hide off
        // here: that changes the shell's work area and visibly moves every window up and down.
        auto it = g_startButton.find(tray);
        auto btn = it != g_startButton.end() ? it->second : nullptr;
        if (!btn || !StartButtonOn(btn, monitor)) {
            if (it != g_startButton.end()) g_startButton.erase(it);
            CacheStartButtons();   // fills only if the taskbar happens to be expanded right now
            it = g_startButton.find(tray);
            btn = it != g_startButton.end() ? it->second : nullptr;
        }
        if (!btn || !StartButtonOn(btn, monitor)) return false;   // caller falls back to Win

        // The shell chooses which monitor Start opens on from the foreground window. Make this
        // monitor's taskbar foreground (it is alpha-0 hidden) so the toggle lands here.
        BOOL foreground = SetForegroundWindow(tray);
        Sleep(80);
        Log(L"start foreground %d", (int)foreground);

        if (StartVisibleOn(monitor)) {   // an unexpected leftover: close it instead of toggling
            SendKeyCombo({ VK_ESCAPE });
            Sleep(120);
            return true;
        }

        ComPtr<IUIAutomationTogglePattern> tog;
        if (SUCCEEDED(btn->GetCurrentPatternAs(UIA_TogglePatternId, IID_PPV_ARGS(&tog))) && tog) {
            if (SUCCEEDED(tog->Toggle())) {
                toggled = true;
                Log(L"start toggled on monitor %p", monitor);
                for (int i = 0; i < 20 && !StartVisibleOn(monitor); ++i) Sleep(40);
                Log(L"start after toggle: target %d any %d", (int)StartVisibleOn(monitor), (int)ShellPopupVisibleAny());
                return true;
            }
        }
        ComPtr<IUIAutomationInvokePattern> inv;
        if (SUCCEEDED(btn->GetCurrentPatternAs(UIA_InvokePatternId, IID_PPV_ARGS(&inv))) && inv &&
            SUCCEEDED(inv->Invoke())) { toggled = true; Log(L"start invoked on monitor %p", monitor); return true; }
        return false;
    });
    if (toggled) lastToggle[monitor] = NowSeconds();
    return toggled;
}

static bool InvokeButton(Button b) {
    ComPtr<IUIAutomationInvokePattern> inv;
    if (g_button[b] && SUCCEEDED(g_button[b]->GetCurrentPatternAs(UIA_InvokePatternId, IID_PPV_ARGS(&inv))) && inv && SUCCEEDED(inv->Invoke())) return true;
    g_button[b].Reset();   // stale (explorer restarted?)
    return false;
}

static bool OpenOverflowWin11(HWND tray) {
    bool cached = g_buttonTray == tray && g_button[Chevron], ok = cached && InvokeButton(Chevron);
    if (!ok) {
        // Materialize Explorer's automation content only under the opacity guard
        // acquired by OpenOverflow. An empty region alone is NOT sufficient:
        // Explorer rebuilds it while expanding its taskbar.
        APPBARDATA abd = { sizeof(abd) }; abd.hWnd = tray;
        UINT_PTR st = SHAppBarMessage(ABM_GETSTATE, &abd);
        bool autoHide = (st & ABS_AUTOHIDE) != 0;
        if (autoHide) { abd.lParam = st & ~ABS_AUTOHIDE; SHAppBarMessage(ABM_SETSTATE, &abd); }
        for (int i = 0; i < 40 && !g_button[Chevron]; ++i) { CacheTrayButtons(tray); if (!g_button[Chevron]) Sleep(25); }
        ok = InvokeButton(Chevron);
        if (autoHide) { abd.lParam = st; SHAppBarMessage(ABM_SETSTATE, &abd); }
    }
    Log(L"win11 overflow: cached=%d invoked=%d", (int)cached, (int)ok);
    return ok;
}

bool OpenOverflow(POINT anchor, Edge edge, RECT bar) {
    return g_taskbar.WithInvisibleTaskbars([&]() -> bool {
    HWND tray = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (!tray) return false;
    HWND notify = FindWindowExW(tray, nullptr, L"TrayNotifyWnd", nullptr);
    HWND chevron = notify ? GetDlgItem(notify, 1502) : nullptr;   // classic (Windows 10 style) taskbar
    const wchar_t* popupClass = chevron ? L"NotifyIconOverflowWindow" : L"TopLevelWindowForOverflowXamlIsland";
    HWND previous = FindWindowW(popupClass, nullptr);
    bool wasOpen = previous && IsWindowVisible(previous);
    if (!chevron) {
        if (!OpenOverflowWin11(tray)) return false;
    } else {
        DWORD_PTR r = 0;
        if (!SendMessageTimeoutW(chevron, BM_CLICK, 0, 0, SMTO_ABORTIFHUNG, 500, &r)) return false;
    }

    // A second click closes the existing flyout. Do not reopen or reposition it.
    if (wasOpen) return true;
    HWND ov = nullptr;
    for (int i = 0; i < 25 && !(ov = FindWindowW(popupClass, nullptr)); ++i) Sleep(10);
    for (int i = 0; i < 25 && ov && !IsWindowVisible(ov); ++i) Sleep(10);
    if (!ov || !IsWindowVisible(ov)) return false;
    RECT wr{}; if (!GetWindowRect(ov, &wr)) return false;
    int w = wr.right - wr.left, h = wr.bottom - wr.top, gap = 12;
    int x = anchor.x - w / 2, y = anchor.y - h / 2;
    switch (edge) {
    case Edge::Bottom: y = bar.top - h - gap; break;
    case Edge::Top:    y = bar.bottom + gap; break;
    case Edge::Left:   x = bar.right + gap; break;
    case Edge::Right:  x = bar.left - w - gap; break;
    }
    HMONITOR mon = MonitorFromPoint(anchor, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = { sizeof(mi) }; GetMonitorInfoW(mon, &mi);
    x = std::clamp<int>(x, mi.rcMonitor.left + 4, std::max(mi.rcMonitor.left + 4, mi.rcMonitor.right - w - 4));
    y = std::clamp<int>(y, mi.rcMonitor.top + 4, std::max(mi.rcMonitor.top + 4, mi.rcMonitor.bottom - h - 4));
    return SetWindowPos(ov, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE) != FALSE;
    });
}

// With the stock taskbar the buttons are invoked directly; the shortcuts are the fallback.
void OpenCalendar() { if (!InvokeButton(Clock)) SendKeyCombo({ VK_LWIN, VK_MENU, 'D' }); }

void OpenVolume(POINT c) {
    // SndVol's flyout mode takes the screen position as MAKELPARAM(x, y) of its centre
    wchar_t arg[32]; swprintf_s(arg, L"-f %ld", (long)MAKELPARAM((WORD)c.x, (WORD)c.y));
    ShellExecuteW(nullptr, L"open", L"SndVol.exe", arg, nullptr, SW_SHOWNORMAL);
}

void OpenQuickSettings() { if (!InvokeButton(Network)) SendKeyCombo({ VK_LWIN, 'A' }); }

}
