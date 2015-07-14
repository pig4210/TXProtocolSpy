local tag = 0x0309;
local name = "SSO2::TLV_Ping_Strategy_0x309";
local subver = 0x0001;


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local tlv = txline:new();
  local data = txline:new();
  local wSubVer = td[TXP.CreateTLVSubVerName(tag)] or subver;
  data:sw(wSubVer);
  if wSubVer == 0x0001 then
    data:sd(td.dwServerIP);
    data:sb(#td.RedirectIP);
    for k = 1,#td.RedirectIP do
      data:sd(td.RedirectIP[k]);
    end
    data:sb(td.cPingType);
  else
    error(name .. "无法识别的版本号" .. wSubVer);
  end
  tlv:sw(tag);
  tlv:shl(data);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = 
  data:pw("wSubVer") ..
  data:pip("dwConnIP");
  local buf , cRedirectCount = data:pb("cRedirectCount");
  ds = ds .. buf;
  data:inc();
  for k = 1,cRedirectCount do
    ds = ds .. data:pip("dwFromIP");
  end
  data:dec();
  ds = ds ..
  data:pb("cPingType");
  return ds;
end