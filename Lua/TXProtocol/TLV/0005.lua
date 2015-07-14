local tag = 0x0005;
local name = "SSO2::TLV_Uin_0x5";
local subver = 0x0002;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0002 then
    if td.dwUin == 0 then
      return tlv;
    end
    data:sd(td.dwUin);
  else
    error("TLV Uin无法识别的版本号");
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end


TXP.TLVSpy[tag] = function(td, data)
  return
  data:pw("wSubVer") ..
  data:pd("dwUin");
end