local tag = 0x0032;
local name = "TLV_QdData";

TXP.TLVName[tag] = name;

function TXP.CreateQdData(td)
  local data = txline:new();
  data:sd(td.dwServerIP);
  local qddata = xline:new();
  qddata:sd(td.dwQdVerion);
  qddata:sd(td.dwPubNo);
  qddata:sd(td.dwUin);
  qddata:sa(data.line);
  data:clear();
    
  local encode = XTeanEncrypt(qddata.line, td.bufQdKey);
  if (encode == nil) or (#encode == 0) then
    error(name .. "º”√‹ ß∞‹");
  end

  data:sb(td.cQdProtocolVer);
  data:sd(td.dwQdVerion);
  data:sw(td.wQdCsCmdNo);
  data:sb(td.cQdCcSubNo);
  data:sw(xrand(0xFFFF) + 1);
  data:sd(0);
  data:sa(td.bufComputerIDEx);
  data:sb(td.cOsType);
  data:sb(td.bIsWOW64);
  data:sd(td.dwPubNo);
  data:sw(td.dwClientVer);
  data:sd(td.dwDrvVersionInfo / 0x10000);
  data:sd(td.dwDrvVersionInfo % 0x10000);
  data:sa(td.bufVersion_TSSafeEdit_dat);
  data:sa(td.bufVersion_QScanEngine_dll);
  data:sb(0);
  data:sa(encode);
  data:sa(td.QdSufFix);

  local size = #data.line + 3;
  qddata = txline:new();
  qddata:sa(td.QdPreFix);
  qddata:sw(size);
  qddata:sa(data.line);

  return qddata.line;
end

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  data:sa(TXP.CreateQdData(td));
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = data:pb("cQdPreFix") ..
  data:pw("wSize") ..
  data:pb("cQdProtocolVer") ..
  data:pd("dwQdVerion") ..
  data:pw("wQdCsCmdNo") ..
  data:pb("cQdCcSubNo") ..
  data:pw("wCsSeq") ..
  data:pd("00000000") ..
  data:pkey("bufComputerIDEx") ..
  data:pb("cOsType") ..
  data:pb("bIsWOW64") ..
  data:pd("dwPubNo") ..
  data:pw("wClientVer") ..
  data:pd("wDrvVersionInfoHigh") ..
  data:pd("wDrvVersionInfoLow") ..
  data:phs("bufVersion_TSSafeEdit_dat", 0x08) ..
  data:phs("bufVersion_QScanEngine_dll", 0x08) ..
  data:pb("00");

  local qddata = data.line:sub(1, -2);

  qddata = XTeanDecrypt(qddata, td.bufQdKey);
  if (qddata == nil) or (#qddata <= 0) then
    ds = ds .. data:phs("bufQdData*Ω‚√‹ ß∞‹", #data.line - 1);
  else
    ds = ds .. data:pk() ..
      string.format("QdData [%04X] >> [%04X] with bufQdKey\r\n", #data.line - 1, #qddata);
    qddata = txspyline:newline(qddata);
    qddata.level = data.level + 1;
    ds = ds .. qddata:phs("bufQdData", #qddata.line);
  end
    
  data.line = data.line:sub(-1, -1);
ds = ds ..
  data:pb("cQdSufFix");
  return ds;
end