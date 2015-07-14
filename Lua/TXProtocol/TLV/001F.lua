local tag = 0x001F;
local name = "TLV_DeviceID";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0001 then
    if td.bufDeviceID == nil then
      return tlv;
    end
    data:sa(td.bufDeviceID);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    td.bufDeviceID = data.line;
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  return
  data:pw("wSubVer") ..
  data:phs("bufDeviceID", #data.line);
end