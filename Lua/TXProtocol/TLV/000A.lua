
local tag = 0x000A;
local name = "SSO2::TLV_ErrorInfo_0xa";


TXP.TLVName[tag] = name;


TXP.TLVSpy[tag] = function(td, data)
  return 
  data:pw("wSubVer") ..
  data:pw("wErrorCode?") ..
  data:ph8("ErrorMsg");
end