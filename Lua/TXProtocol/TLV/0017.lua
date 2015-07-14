local tag = 0x0017;
local name = "SSO2::TLV_ClientInfo_0x17";

TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    td.dwServerTime = data:gd();
    td.dwClientWanIP = data:gd();
    td.wClientWanPort = data:gw();
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  return;
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pw("wSubVer") ..
  data:ptm("dwServerTime") ..
  data:pip("dwClientWanIP") ..
  data:pw("wClientWanPort") ..
  data:phhs("UNKNOW");
end