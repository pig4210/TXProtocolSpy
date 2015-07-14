local tag = 0x010E;
local name = "TLV_010E";
local subver = 0x0001;

TXP.TLVName[tag] = name;

TXP.TLVAnalyzer[tag] = function(td, data)
  local wSubVer = data:gw();
  if wSubVer == 0x0001 then
    local sig = data:ghl();
    td.dwUinLevel = sig:gd();
    td.dwUinLevelEx = sig:gd();
    td.buf24byteSignature = sig:gha();
    td.buf32byteValueAddedSignature = sig:gha();
    td.buf12byteUserBitmap = sig:gha();
    td.openkj = "http://ptlogin2.qq.com/jump?ptlang=2052&clientuin="
        .. td.dwUin ..
        "&clientkey=" ..
        hex2str(td.buf32byteValueAddedSignature) ..
        "&u1=http%3A%2F%2F10001.qzone.qq.com%2F"
          --.. td.dwUin .. "%2Finfocenter";
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pw("wSubVer");
  local buf, sig = data:phloh("info");
  sig:inc();
  return ds .. buf ..
      sig:pd("dwUinLevel") ..
      sig:pd("dwUinLevelEx") ..
      sig:phhs("buf24byteSignature") ..
      sig:phhs("buf32byteValueAddedSignature") ..
      sig:phhs("buf12byteUserBitmap") ..
      sig:pr();
end