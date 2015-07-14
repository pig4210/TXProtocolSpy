local tag = 0x0108;
local name = "SSO2::TLV_AccountBasicInfo_0x108";


TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    local bufAccountBasicInfo = data:ghl();
    local info = bufAccountBasicInfo:ghl();
        td.wSSO_Account_wFaceIndex = info:gw();
        local len = info:gb();
        td.strSSO_Account_strNickName = utf82s(info:ga(len));
        td.cSSO_Account_cGender = info:gb();
        td.dwSSO_Account_dwUinFlag = info:gd();
        td.cSSO_Account_cAge = info:gb();
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pw("wSubVer");
  local bufa, bufAccountBasicInfo = data:phloh("bufAccountBasicInfo");
  bufAccountBasicInfo:inc();
  local bufi, info = bufAccountBasicInfo:phloh("bufInAccountValue");
  info:inc();
  ds = ds ..
      bufa ..
      bufi ..
      info:pw("wSSO_Account_wFaceIndex");
  local len = info:gb();
  local name = info:ga(len);
ds = ds ..
          info:pn("strSSO_Account_strNickName") ..
          string.format("(%02X)UTF8\"%s\"\r\n", len, utf82s(name)) ..
          info:pb("cSSO_Account_cGender") ..
          info:pd("dwSSO_Account_dwUinFlag") ..
          info:pb("cSSO_Account_cAge") ..
          info:pr() ..
      bufAccountBasicInfo:phhs("bufSTOther") ..
      bufAccountBasicInfo:pr();
  return ds;
end