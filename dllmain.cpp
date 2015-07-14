#include <algorithm>

#include <xlib.h>

#include <lua.hpp>
#pragma comment(lib, "lua")

using namespace std;

static const char* const gk_aly_name = "tps_aly";

lua_State* xlua = nullptr;
static SysCritical xlua_cri;

//////////////////////////////////////////////////////////////////////////
#undef xlog_static_lvl
#define xlog_static_lvl xlog::lvl_debug

//! 获取当前模块全路径，包含"\"
static string get_this_path()
  {
  HMODULE hMod;
  auto rets = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                (LPCTSTR)&get_this_path,
                                &hMod);
  if(!rets)
    {
    throw runtime_error(
      xmsg() << "获取当前模块位置失败:" << (intptr_t)GetLastError()
      );
    }
  xtrace << "当前模块位置:" << hMod;

  char path[MAX_PATH];

  if(0 == GetModuleFileNameA(hMod, path, _countof(path)))
    {
    throw runtime_error(
      xmsg() << "获取当前模块文件名失败:" << (intptr_t)GetLastError()
      );
    }

  xtrace << "当前模块文件名:" << path;

  char drive[_MAX_DRIVE];
  char dir[_MAX_DIR];
  char fname[_MAX_FNAME];
  char ext[_MAX_EXT];

  auto en = _splitpath_s(path, drive, dir, fname, ext);
  if(0 != en)
    {
    throw runtime_error(
      xmsg() << "分解当前模块路径失败:" << strerror(en)
      );
    }

  return string(drive) + string(dir);
  }

//! 向Lua状态的package.path、package.cpath加入当前模块路径，有相同判定，不重复添加
static void lua_append_this_path(lua_State* ls)
  {
  const string path(get_this_path());
  xtrace << "path:" << path;

  xmsg lua_path;
  lua_path << path << "?.lua";
  string lp(lua_path);
  transform(lp.begin(), lp.end(), lp.begin(), tolower);
  xtrace << "lua_path:" << lua_path << " -- " << lp;

  xmsg dll_path;
  dll_path << path << "?.dll";
  string dp(dll_path);
  transform(dp.begin(), dp.end(), dp.begin(), tolower);
  xtrace << "dll_path:" << dll_path << " -- " << dp;

  lua_getglobal(ls, LUA_LOADLIBNAME);

  lua_pushstring(ls, "path");
  lua_gettable(ls, -2);
  string pkp(lua_tostring(ls, -1));
  lua_pop(ls, 1);
  string pp(pkp);
  transform(pp.begin(), pp.end(), pp.begin(), tolower);
  xtrace << "package.path:" << pkp;
  xtrace << "package.path:" << pp;

  lua_pushstring(ls, "cpath");
  lua_gettable(ls, -2);
  string pkc(lua_tostring(ls, -1));
  lua_pop(ls, 1);
  string pc(pkc);
  transform(pc.begin(), pc.end(), pc.begin(), tolower);
  xtrace << "package.cpath:" << pkc;
  xtrace << "package.cpath:" << pc;

  if(string::npos == pp.find(lp))
    {
    xmsg ss;
    ss << pkp << ';' << lua_path;
    lua_pushstring(ls, "path");
    lua_pushstring(ls, ss.c_str());
    lua_settable(ls, -3);
    xtrace << "Append package.path";
    }

  if(string::npos == pc.find(dp))
    {
    xmsg ss;
    ss << pkc << ';' << dll_path;
    lua_pushstring(ls, "cpath");
    lua_pushstring(ls, ss.c_str());
    lua_settable(ls, -3);
    xtrace << "Append package.cpath";
    }
  lua_pop(ls, lua_gettop(ls));
  }

//////////////////////////////////////////////////////////////////////////
static sockaddr_in g_addr;
static bool load()
  {
  try
    {
    string ip("127.0.0.1");
    string port("42108");

    xlua = luaL_newstate();
    luaL_openlibs(xlua);
    lua_append_this_path(xlua);

    lua_getglobal(xlua, "require");
    if(lua_type(xlua, -1) != LUA_TFUNCTION)
      {
      xmsg msg;
      msg << "提取require函数出错:" << lua_type(xlua, -1);
      lua_pop(xlua, lua_gettop(xlua));
      throw runtime_error(msg);
      }
    else
      {
      lua_pushstring(xlua, gk_aly_name);
      if(LUA_OK != lua_pcall(xlua, 1, LUA_MULTRET, 0))
        {
        xmsg msg;
        msg << "加载解析脚本出错:" << lua_tostring(xlua, -1);
        lua_pop(xlua, lua_gettop(xlua));
        throw runtime_error(msg);
        }
      }
    lua_pop(xlua, lua_gettop(xlua));

    return true;
    }
  catch(const runtime_error& err)
    {
    xerr << "初始化出错：" << err.what();
    }
  catch(...)
    {
    xerr << "初始化异常";
    }
  return false;
  }

static void free()
  {
  if(xlua)  lua_close(xlua);
  }

//////////////////////////////////////////////////////////////////////////
void TXSpy(const char* funcname)
  {
  lua_getglobal(xlua, funcname);
  if(lua_type(xlua, -1) == LUA_TFUNCTION)
    {
    lua_replace(xlua, 1);

    if(LUA_OK != lua_pcall(xlua, lua_gettop(xlua) - 1, 0, 0))
      {
      xerr << funcname << "函数运行出错：" << lua_tostring(xlua, -1);
      }
    }
  else
    {
    xerr << "缺少解析函数：" << funcname;
    }
  }

//////////////////////////////////////////////////////////////////////////
static void __stdcall Routine_TXLog_DoTXLogVW(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    const wchar_t* name = (const wchar_t*)mkD(lpcpu->regEsp + 0x08);
    const wchar_t* fmt = (const wchar_t*)mkD(lpcpu->regEsp + 0x0C);
    va_list ap = (va_list)mkD(lpcpu->regEsp + 0x10);

    wstring ws;
    while(true)
      {
      if((fmt == nullptr) || (ap == nullptr)) break;
      if(ws.capacity() - ws.size() <= 1)
        {
        ws.reserve(ws.capacity() + 0x10);
        }
      const size_t rst = ws.capacity() - ws.size();
      wchar_t* lpend = const_cast<wchar_t*>(ws.end()._Ptr);
      const size_t rt = _vsnwprintf_s(lpend, rst, rst - 1, fmt, ap);  //数据不足，返回-1
      if(rt < rst)
        {
        ws.append(lpend, rt);
        break;
        }
      ws.reserve(ws.capacity() + 0x10);
      }

    if(name == nullptr) name = L"";

    lua_pushnil(xlua);
    lua_pushinteger(xlua, (size_t)name);
    lua_pushinteger(xlua, (size_t)ws.c_str());

    TXSpy("TXLog_DoTXLogVW");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }

static void __stdcall Routine_TXDataHook(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    lua_pushnil(xlua);
    lua_pushinteger(xlua, mkD(lpcpu->regEbp + 0x08));       //lpname
    lua_pushinteger(xlua, mkD(lpcpu->regEbp + 0x0C));       //type
    lua_pushinteger(xlua, mkD(lpcpu->regEbp + 0x10));       //lpdata

    TXSpy("TXDataHook");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }

static void __stdcall Routine_CTXUDPDataSender__InternalSendData(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    lua_pushnil(xlua);
    lua_pushinteger(xlua, lpcpu->regEax);
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x00));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x04));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x08));

    TXSpy("CTXUDPDataSender__InternalSendData");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }


static void __stdcall Routine_CTXUDPDataSenderInternalRecvData(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    lua_pushnil(xlua);
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x08));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x0C));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x10));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x14));

    TXSpy("CTXUDPDataSenderInternalRecvData");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }

static void __stdcall Routine_uv_udp_send(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    lua_pushnil(xlua);
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x18));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x0C));
    lua_pushinteger(xlua, mkD(lpcpu->regEsp + 0x08));

    TXSpy("uv_udp_send");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }

void WSAAPI fake_ret_WSARecvFrom(
  __in SOCKET s,
  __in_ecount(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
  __in DWORD dwBufferCount,
  __out_opt LPDWORD lpNumberOfBytesRecvd,
  __inout LPDWORD lpFlags,
  __out_bcount_part_opt(*lpFromlen, *lpFromlen) struct sockaddr FAR * lpFrom,
  __inout_opt LPINT lpFromlen,
  __inout_opt LPWSAOVERLAPPED lpOverlapped,
  __in_opt LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
  )
  {

  }

static void __stdcall Routine_uv_udp_recv(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    typedef
      int
      (
      WSAAPI
      *fun_WSARecvFrom
      )(
      __in SOCKET s,
      __in_ecount(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
      __in DWORD dwBufferCount,
      __out_opt LPDWORD lpNumberOfBytesRecvd,
      __inout LPDWORD lpFlags,
      __out_bcount_part_opt(*lpFromlen, *lpFromlen) struct sockaddr FAR * lpFrom,
      __inout_opt LPINT lpFromlen,
      __inout_opt LPWSAOVERLAPPED lpOverlapped,
      __in_opt LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
      );
    fun_WSARecvFrom oldfun = (fun_WSARecvFrom)lpcpu->regEip;

    SOCKET s = (SOCKET)mkD(lpcpu->regEsp + 4 * 1);
    LPWSABUF lpBuffers = (LPWSABUF)mkD(lpcpu->regEsp + 4 * 2);
    DWORD dwBufferCount = (DWORD)mkD(lpcpu->regEsp + 4 * 3);
    LPDWORD lpNumberOfBytesRecvd = (LPDWORD)mkD(lpcpu->regEsp + 4 * 4);
    LPDWORD lpFlags = (LPDWORD)mkD(lpcpu->regEsp + 4 * 5);
    sockaddr FAR * lpFrom = (sockaddr FAR *)mkD(lpcpu->regEsp + 4 * 6);
    LPINT lpFromlen = (LPINT)mkD(lpcpu->regEsp + 4 * 7);
    LPWSAOVERLAPPED lpOverlapped = (LPWSAOVERLAPPED)mkD(lpcpu->regEsp + 4 * 8);
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine = (LPWSAOVERLAPPED_COMPLETION_ROUTINE)mkD(lpcpu->regEsp + 4 * 9);


    lpcpu->regEax = oldfun(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    lpcpu->regEip = (DWORD)fake_ret_WSARecvFrom;

    lua_pushnil(xlua);
    lua_pushinteger(xlua, (DWORD)lpFrom);
    lua_pushinteger(xlua, (DWORD)lpNumberOfBytesRecvd);
    lua_pushinteger(xlua, (DWORD)lpBuffers);

    TXSpy("uv_udp_recv");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }

static void __stdcall Routine_acc_pwd(CPU_ST* lpcpu)
  {
  xlua_cri.enter();
  try
    {
    lua_pushnil(xlua);
    lua_pushinteger(xlua, mkD(lpcpu->regEsp));

    TXSpy("acc_pwd");
    }
  catch(const runtime_error& err)
    {
    xerr << xfunexpt << ":" << err.what();
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  lua_pop(xlua, lua_gettop(xlua));
  xlua_cri.leave();
  }

static void HookSSO()
  {
  try
    {
    xdbg << __FUNCTION__ << "查找中...";
    const HMODULE hssocomm = GetModuleHandle(TEXT("SSOCommon"));
    if(hssocomm == nullptr)
      {
      xerr << __FUNCTION__ << "×无法定位到SSOCommon";
      }

    const HMODULE hcomm = GetModuleHandle(TEXT("Common"));
    if(hcomm == nullptr)
      {
      xerr << __FUNCTION__ << "×无法定位到Common";
      }

    const pe ssocomm(hssocomm);
    const xblk ssocommcode(ssocomm.GetCode());

    const pe comm(hcomm);
    const xblk commcode(comm.GetCode());

    //////////////////////////////////////////////////////////////////////////
    void* lp_TXLog_DoTXLogVW =
      (void*)GetProcAddress(hssocomm, "?TXLog_DoTXLogVW@@YAXPAUtagLogObj@@PB_W1PAD@Z");
    if(lp_TXLog_DoTXLogVW == nullptr)
      {
      xerr << __FUNCTION__ << "×无法定位SSOCommon TXLog_DoTXLogVW";
      }
    else
      {
      xdbg << __FUNCTION__ << "定位到SSOCommon TXLog_DoTXLogVW:" << lp_TXLog_DoTXLogVW;
      if(!Hook(lp_TXLog_DoTXLogVW, 7, Routine_TXLog_DoTXLogVW, true))
        {
        xerr << __FUNCTION__ << "×HOOK SSOCommon TXLog_DoTXLogVW失败：" << GetLastHookErr();
        }
      }
    //-------- -------- -------- -------- -------- --------
    lp_TXLog_DoTXLogVW =
      (void*)GetProcAddress(hcomm, "?TXLog_DoTXLogVW@@YAXPAUtagLogObj@@PB_W1PAD@Z");
    if(lp_TXLog_DoTXLogVW == nullptr)
      {
      xerr << __FUNCTION__ << "×无法定位Common TXLog_DoTXLogVW";
      }
    else
      {
      xdbg << __FUNCTION__ << "定位到Common TXLog_DoTXLogVW:" << lp_TXLog_DoTXLogVW;
      if(!Hook(lp_TXLog_DoTXLogVW, 7, Routine_TXLog_DoTXLogVW, true))
        {
        xerr << __FUNCTION__ << "×HOOK Common TXLog_DoTXLogVW失败：" << GetLastHookErr();
        }
      }
    //////////////////////////////////////////////////////////////////////////
    signaturematcher::REPORT rep = signaturematcher::match(
      ssocommcode.start(), ssocommcode.end(),
      "<A> 55 8BEC .{4,10} 750A B8 57000780 E9 . 00-01 00 00"
      "0F B7 46&R . ");
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位SSOCommon TXDataHook";
      }
    else
      {
      void* TXDataHook = rep.begin()->second.values.p;
      xdbg << __FUNCTION__ << "定位到SSOCommon TXDataHook:" << TXDataHook;
      if(!Hook(TXDataHook, 7, Routine_TXDataHook, false))
        {
        xerr << __FUNCTION__ << "×HOOK SSOCommon TXDataHook失败：" << GetLastHookErr();
        }
      }

    //////////////////////////////////////////////////////////////////////////
    rep = signaturematcher::match(
      ssocommcode.start(), ssocommcode.end(),
      "E8 .{4} <A> 50 FF75. FF 16&R|57&R .? <A>0FB647&L&R. FF4508 3945&L08 7C"
      ".{,18} C20400");
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位SSOCommon CTXUDPDataSender::InternalSendData";
      }
    else
      {
      void* CTXUDPDataSender__InternalSendData = rep.begin()->second.values.p;
      size_t hooksize = (++rep.begin())->second.values.d - rep.begin()->second.values.d;
      xdbg << __FUNCTION__ << "定位到SSOCommon CTXUDPDataSender::InternalSendData:"
        << CTXUDPDataSender__InternalSendData;
      if(!Hook(CTXUDPDataSender__InternalSendData, hooksize, Routine_CTXUDPDataSender__InternalSendData, true))
        {
        xerr << __FUNCTION__ << "×HOOK SSOCommon CTXUDPDataSender::InternalSendData失败：" << GetLastHookErr();
        }
      }
    //-------- -------- -------- -------- -------- --------
    rep = signaturematcher::match(
      commcode.start(), commcode.end(),
      "E8 .{4} <A> 50 FF75. FF 16&R|57&R .? <A>0FB647&L&R. FF4508 3945&L08 7C"
      ".{,18} C20400");
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位Common CTXUDPDataSender::InternalSendData";
      }
    else
      {
      void* CTXUDPDataSender__InternalSendData = rep.begin()->second.values.p;
      size_t hooksize = (++rep.begin())->second.values.d - rep.begin()->second.values.d;
      xdbg << __FUNCTION__ << "定位到Common CTXUDPDataSender::InternalSendData:"
        << CTXUDPDataSender__InternalSendData;
      if(!Hook(CTXUDPDataSender__InternalSendData, hooksize, Routine_CTXUDPDataSender__InternalSendData, true))
        {
        xerr << __FUNCTION__ << "×HOOK Common CTXUDPDataSender::InternalSendData失败：" << GetLastHookErr();
        }
      }
    //////////////////////////////////////////////////////////////////////////
    //CNativeUDP::ReceiveFrom()
    rep = signaturematcher::match(
      ssocommcode.start(), ssocommcode.end(),
      "EB22 8D8D@L..FFFF 51$R 50 FFB5..FFFF 8D8D..FFFF"
      "E8.... 50 53&R 8BCE&R E8<F>");
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位SSOCommon CTXUDPDataSenderInternalRecvData";
      }
    else
      {
      void* CTXUDPDataSenderInternalRecvData = rep.begin()->second.values.p;
      xdbg << __FUNCTION__ << "定位到SSOCommon CTXUDPDataSenderInternalRecvData:"
        << CTXUDPDataSenderInternalRecvData;
      if(!Hook(CTXUDPDataSenderInternalRecvData, 7, Routine_CTXUDPDataSenderInternalRecvData, true))
        {
        xerr << __FUNCTION__ << "×HOOK SSOCommon CTXUDPDataSenderInternalRecvData失败：" << GetLastHookErr();
        }
      }
    //-------- -------- -------- -------- -------- --------
    rep = signaturematcher::match(
      commcode.start(), commcode.end(),
      "EB22 8D8D@L..FFFF 51$R 50 FFB5..FFFF 8D8D..FFFF"
      "E8.... 50 53&R 8BCE&R E8<F>");
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位Common CTXUDPDataSenderInternalRecvData";
      }
    else
      {
      void* CTXUDPDataSenderInternalRecvData = rep.begin()->second.values.p;
      xdbg << __FUNCTION__ << "定位到Common CTXUDPDataSenderInternalRecvData:"
        << CTXUDPDataSenderInternalRecvData;
      if(!Hook(CTXUDPDataSenderInternalRecvData, 7, Routine_CTXUDPDataSenderInternalRecvData, true))
        {
        xerr << __FUNCTION__ << "×HOOK Common CTXUDPDataSenderInternalRecvData失败：" << GetLastHookErr();
        }
      }
    //////////////////////////////////////////////////////////////////////////
    const HMODULE hlibuv = GetModuleHandle(TEXT("libuv"));
    if(hlibuv == nullptr)
      {
      xerr << __FUNCTION__ << "×无法定位到libuv";
      }

    const pe libuv(hlibuv);
    const xblk libuvimg(libuv.GetImage());

    //xdbg << libuvimg.start() << "~"<< libuvimg.end();
    void* dwWSASendTo = WSASendTo;
    dwWSASendTo = bswap(dwWSASendTo);
    xmsg bssend;
    bssend << "<A>" << dwWSASendTo;
    //xdbg << bssend;

    void* dwWSARecvFrom = WSARecvFrom;
    dwWSARecvFrom = bswap(dwWSARecvFrom);
    xmsg bsrecv;
    bsrecv << "<A>" << dwWSARecvFrom;
    //xdbg << bsrecv;
    //-------- -------- -------- -------- -------- --------
    rep = signaturematcher::match(
      libuvimg.start(), libuvimg.end(),
      bssend.c_str());
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位libuv uv_udp_send";
      }
    else
      {
      void* uv_udp_send = rep.begin()->second.values.p;
      xdbg << __FUNCTION__ << "定位到libuv uv_udp_send:"
        << uv_udp_send;
      if(!Hook(uv_udp_send, Routine_uv_udp_send, true, true))
        {
        xerr << __FUNCTION__ << "×HOOK libuv uv_udp_send失败：" << GetLastHookErr();
        }
      }
    //-------- -------- -------- -------- -------- --------
    rep = signaturematcher::match(
      libuvimg.start(), libuvimg.end(),
      bsrecv.c_str());
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位libuv uv_udp_recv";
      }
    else
      {
      void* uv_udp_recv = rep.begin()->second.values.p;
      xdbg << __FUNCTION__ << "定位到libuv uv_udp_recv:"
        << uv_udp_recv;
      //这XX参数超过8
      if(!Hook(uv_udp_recv, Routine_uv_udp_recv, true, true, nullptr, 1))
        {
        xerr << __FUNCTION__ << "×HOOK libuv uv_udp_recv失败：" << GetLastHookErr();
        }
      }
    //////////////////////////////////////////////////////////////////////////
    const HMODULE hAppFramework = GetModuleHandle(TEXT("AppFramework"));
    if(hAppFramework == nullptr)
      {
      xerr << __FUNCTION__ << "×无法定位到AppFramework";
      }

    const pe AppFramework(hAppFramework);
    const xblk AppFramework_img(AppFramework.GetImage());

    rep = signaturematcher::match(
      AppFramework_img.start(), AppFramework_img.end(),
      "51|50&57    <A>68 \"bufPwd\\x0\"    57|50&57    FF 50|90");
    if(rep.empty())
      {
      xerr << __FUNCTION__ << "×无法定位AppFramework acc_pwd";
      }
    else
      {
      void* acc_pwd = rep.begin()->second.values.p;
      xdbg << __FUNCTION__ << "定位到AppFramework acc_pwd:"
        << acc_pwd;
      if(!Hook(acc_pwd, 6, Routine_acc_pwd, false))
        {
        xerr << __FUNCTION__ << "×HOOK AppFramework acc_pwd失败：" << GetLastHookErr();
        }
      }

    //////////////////////////////////////////////////////////////////////////
    xdbg << __FUNCTION__ << "完成";
    }
  catch(...)
    {
    xerr << xfunexpt;
    }
  }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
  {
  UNREFERENCED_PARAMETER(hModule);
  UNREFERENCED_PARAMETER(lpReserved);
  switch(ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
      if(!load()) return FALSE;
      HookSSO();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      free();
      break;
    }
  return TRUE;
  }