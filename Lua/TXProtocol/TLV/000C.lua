local tag = 0x000C;
local name = "SSO2::TLV_PingRedirect_0xC";
local subver = 0x0002;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0002 then
    data:sw(0);
    data:sd(td.dwIDC);
    data:sd(td.dwISP);
    data:sd(td.dwServerIP);
    data:sw(td.wServerPort);
    data:sd(0);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0002 then
    data:gw();
    td.dwIDC = data:gd();
    td.dwISP = data:gd();
    local dwRedirectIP = data:gd();
    local wRedirectPort = data:gw();

    td.RedirectIP[#td.RedirectIP + 1] = td.dwServerIP;
    local ip = string.format("%d.%d.%d.%d",string.unpack("BBBB", string.pack(">I4", ip)));
    local port = tostring(td.wServerPort);
    td.link = udp_new(ip, port);
    string.format("重新连接%s:%s", ip, port):xlog();
    td.dwServerIP = dwRedirectIP;
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  local ds, wSubVer = data:pw("wSubVer");
  if wSubVer == 0x0002 then
ds = ds ..
  data:pw("UNKNOW") ..
  data:pd("dwIDC?") ..
  data:pd("dwISP?") ..
  data:pip("dwRedirectIP") ..
  data:pw("wRedirectPort") ..
  data:pd("UNKNOW");

  elseif wSubVer == 0x0001 then
ds = ds ..
  data:pw("UNKNOW") ..
  data:pd("UNKNOW") ..
  data:pd("UNKNOW") ..
  data:pw("UNKNOW")

  else
  end

  return ds;
end