local tag = 0x0036;
local name = "SSO2::TLV_LoginReason_0x36";
local subver = 0x0002;


TXP.TLVName[tag] = name;


TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0002 then
    data:sw(1);
    data:sd(0);
    data:sw(0);
    data:sw(0);
    data:sd(0);
    data:sb(0);
    data:sb(0);
  elseif wSubVer == 0x0001 then
    data:sw(1);
    data:sd(0);
    data:sw(0);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds, wSubVer = data:pw("wSubVer");
  if wSubVer == 0x0002 then
ds = ds ..
  data:pw("0001") ..
  data:pd("00000000") ..
  data:pw("0000") ..
  data:pw("0000") ..
  data:pd("00000000") ..
  data:pb("00") ..
  data:pb("00");

  elseif wSubVer == 0x0001 then
ds = ds ..
  data:pw("0001") ..
  data:pd("00000000") ..
  data:pw("0000");

  else

  end

  return ds;
end