local tag = 0x0015;
local name = "SSO2::TLV_ComputerGuid_0x15";
local subver = 0x0001;

TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local data = txline:new();
  local tlv = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  if wSubVer == 0x0001 then
    data:sw(wSubVer);
    data:sb(1);
    data:sd(crc32(td.bufComputerID));
    data:sha(td.bufComputerID);
    data:sb(2);
    data:sd(crc32(td.bufComputerIDEx));
    data:sha(td.bufComputerIDEx);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds , wSubVer = data:pw("wSubVer");
  local i = 0
  while #data.line > 0  do
    i = i + 1;
    ds = ds ..
        data:pb("No." .. i) ..
        data:pd("bufComputerID_" .. i .. "_CRC32") ..
        data:phhs("bufComputerID_" .. i);
  end
  return ds;
end