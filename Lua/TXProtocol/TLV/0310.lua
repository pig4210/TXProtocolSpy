local tag = 0x0310;
local name = "SSO2::TLV_ServerAddress_0x310";

TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  td.dwServerIP = data:gd();
end

TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pip("dwServerIP");
end