local tag = 0x001A;
local name = "SSO2::TLV_GTKeyTGTGTCryptedData_0x1a";


TXP.TLVName[tag] = name;

TXP.TLVBuilder[tag] = function(td)
  local data = TXP.TLVBuilder[0x0015](td);
  local tlv = txline:new();
  local encode = TeanEncrypt(data.line, td.Key["bufTGTGTKey"]);
  if (encode == nil) or (#encode == 0) then
    error(name .. " ¼ÓÃÜÊ§°Ü");
  end
  tlv:sw(tag);
  tlv:sha(encode);
  return tlv;
end

TXP.TLVSpy[tag] = function(td, data)
  local ds = "";
  local encode;
  local buf = data.line;
  for k,v in pairs(td.Key) do
    if k:sub(1,3) == "Spy" then
      encode = TeanDecrypt(buf, v);
      if (encode ~= nil) and (#encode > 0) then
        buf = "    with " .. k;
        break;
      end
    end
  end
  if (encode == nil) or (#encode <= 0) then
    ds = ds .. name .. " ½âÃÜÊ§°Ü\r\n";
    return ds;
  end
ds = ds .. data:pk() ..
  string.format("CryptedData [%04X] >> [%04X]%s", #data.line, #encode, buf);
  data.line = encode;
  ds  = ds .. data:ptlv(td);
  return ds;
end