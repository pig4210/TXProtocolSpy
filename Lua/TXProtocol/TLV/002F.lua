local tag = 0x002F;
local name = "TLV_Control";
local subver = 0x0001;

TXP.TLVName[tag] = name;


TXP.TLVAnalyzer[tag] = function(td, data)
end

TXP.TLVSpy[tag] = function(td, data)
  return
  data:pw("wSubVer") ..
  data:phs("bufControl", #data.line);
end