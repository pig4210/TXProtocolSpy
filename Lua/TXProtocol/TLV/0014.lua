local tag = 0x0014;
local name = "TLV_0014";
local subver = 0x0001;

TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
end


TXP.TLVSpy[tag] = function(td, data)
  return
  data:pw("wSubVer") ..
  data:pw("UNKNOW");
end