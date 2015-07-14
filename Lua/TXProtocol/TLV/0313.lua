local tag = 0x0313;
local name = "SSO2::TLV_GUID_Ex_0x313";
local subver = 0x01;


TXP.TLVName[tag] = name;

local GuidName  = 
  {
  "UNKNOW",
  "MacGuid",
  "UNKNOW",
  "ComputerIDEx",
  "UNKNOW",
  "MachineInfoGuid",
  };
                            
TXP.TLVBuilder[tag] = function(td)
  local data = txline:new();
  local tlv = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  if wSubVer == 0x01 then
    data:sb(wSubVer);
    local guid = txline:new();
    local c = 0;
    for k = 1, #GuidName do
      if GuidName[k] ~= "UNKNOW" then
        c = c + 1;
        guid:sb(k);
        guid:sha(td["buf" .. GuidName[k]]);
        guid:sd(0);
      end
    end
    data:sb(c);
    data:sl(guid);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end


TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pb("cSubVer");
  local buf, c = data:pb("GUID Count");
  ds = ds .. buf;
  data:inc();
  for k = 1, c do
    local buf, i = data:pb("GUID Index");
    ds = ds .. buf ..
    data:phhs(GuidName[i]) ..
    data:pd("Tick");
  end
  data:dec();
  return ds;
end