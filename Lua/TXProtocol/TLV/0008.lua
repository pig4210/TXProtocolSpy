local tag = 0x0008;
local name = "SSO2::TLV_TimeZone_0x8";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0001 then
    if (td.dwLocaleID == 0x00000804) and (td.wTimeZoneoffsetMin == 0x01E0) then
      return tlv;
    end
    data:sd(td.dwLocaleID);
    data:sw(td.wTimeZoneoffsetMin);
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
  data:pd("dwLocaleID") ..
  data:pw("wTimeZoneoffsetMin");
end