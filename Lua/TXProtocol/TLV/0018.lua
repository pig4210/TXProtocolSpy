local tag = 0x0018;
local name = "SSO2::TLV_Ping_0x18";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0001 then
    data:sd(td.dwSSOVersion);
    data:sd(td.dwServiceId);
    data:sd(td.dwClientVer);
    data:sd(td.dwUin);
    data:sw(#td.RedirectIP);
    data:sha("");
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pw("wSubVer") ..
  data:pd("dwSSOVersion") ..
  data:pd("ServiceId") ..
  data:pd("ClientVer") ..
  data:pd("dwUin") ..
  data:pw("wRedirectCount") ..
  data:phhs("NullBuf");
end