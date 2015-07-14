--[=======[
-------- -------- -------- --------
            txline操作
-------- -------- -------- --------
]=======]
--[=======[
●
    txline    txline:new                ( );  --txline继承xline操作，只是修改成默认大端
]=======]

txline            = { }
setmetatable(txline, xline);
txline.__index = txline;

function txline:new( )
  local nline = {};
  self = self or txline;

  setmetatable(nline, self);
  self.__index = self;
  
  nline.line            = self.line         or    "";
  nline.net_flag        = self.net_flag     or    true;
  nline.head_size       = self.head_size    or    2;
  nline.head_self       = self.head_self    or    false;
  nline.deal_zero_end   = self.deal_zero_end or   false;

  if nline.net_flag then
    nline.nets = ">";
  else
    nline.nets = "<";
  end

  return nline;
end

--[=======[
    string    txline:get_key            ( );  --获取一组TxKey
    string    txline:set_rand_key       ( );  --设置一组随机的TxKey
]=======]
function txline:get_key()
  return self:get_ascii_str(TXP.TEAN_Key_Size);
end

function txline:set_rand_key()
  local key = "";
  for k = 1, TXP.TEAN_Key_Size do
      key = key .. string.char(xrand(0xFF) + 1);
  end
  self:set_ascii_str(key);
  return key;
end
--[=======[
    txline.gk       = txline.get_key;
    txline.srk      = txline.set_rand_key;
]=======]
txline.gk       = txline.get_key;
txline.srk      = txline.set_rand_key;


-------- -------- -------- --------
-------- -------- -------- --------
-------- -------- -------- --------
--[=======[
-------- -------- -------- --------
                txspyline操作
-------- -------- -------- --------
]=======]
--[=======[
●
    txspyline txspyline:new             ( );  --txspyline继承txline操作，添加level项
]=======]
txspyline = { };
setmetatable(txspyline, txline);
txspyline.__index = txspyline;


function txspyline:new(nline)
  local nline = {};
  self = self or txspyline;

  setmetatable(nline, self);
  self.__index = self;
  
  nline.line            = self.line         or    "";
  nline.net_flag        = self.net_flag     or    true;
  nline.head_size       = self.head_size    or    2;
  nline.head_self       = self.head_self    or    false;
  nline.deal_zero_end   = self.deal_zero_end or   false;

  if nline.net_flag then
    nline.nets = ">";
  else
    nline.nets = "<";
  end

  nline.level = self.level or 0;      --新增　输出层次
  return nline;
end

--[=======[
    txspyline txspyline:level_increase  ( );  --增加输出层次
    txspyline txspyline:level_decrease  ( );  --减少输出层次
]=======]
function txspyline:level_increase()
  self.level = self.level + 1;
  return self;
end
function txspyline:level_decrease()
  self.level = self.level - 1;
  if self.level < 0 then
      self.level = 0;
  end
  return self;
end

--[=======[
    string    txspyline:print_blanks    ( );  --根据输出层次，' '*levle*6
    string    txspyline:print_names     ( );  --输出格式化名字，前置空格
]=======]
function txspyline:print_blanks()
  return string.rep(' ', self.level * 6);
end
function txspyline:print_names(name)
  name  = name or "";
  return self:print_blanks() .. string.format("%-19s", name .. ':');
end
--[=======[
    --根据名字，提取并输出一个格式化的类型，同时返回值
    string, v txspyline:print_get_byte  ( name );
    string, v txspyline:print_get_word  ( name );
    string, v txspyline:print_get_dword ( name );
]=======]
function txspyline:print_get_byte(name)
  local v = self:get_byte();
  return self:print_names(name) .. string.format("%02X [%u]\r\n", v, v), v;
end
function txspyline:print_get_word(name)
  local v = self:get_word();
  return self:print_names(name) .. string.format("%04X [%u]\r\n", v, v), v;
end
function txspyline:print_get_dword(name)
  local v = self:get_dword();
  return self:print_names(name) .. string.format("%08X [%u]\r\n", v, v), v;
end
--[=======[
    string    txspyline:print_head      ( int size ); --输出一个格式化的head
]=======]
function txspyline:print_head(size)
  return string.format("%0" .. self.head_size .. "X", size);
end
--[=======[
    stirng, string txspyline:print_hexs ( string name, int size );
        --提取并输出一个hexs, 同时返回hexs串
    string, string txspyline:print_head_hexs( string name );
        --提取并输出一个带头的hexs, 同时返回hexs串
]=======]
function txspyline:print_hexs(name, size)
  local str = self:get_ascii_str(size);
  local ds = self:print_names(name) .. '[' .. self:print_head(#str) .. ']';

  self:level_increase();
  local tab = "\r\n" .. self:print_blanks();
  self:level_decrease();

  local i = 1;
  local h;
  for k = 1, #str do
    if i == 1 then
      ds = ds .. tab;
    end
    h = string.format("%02X ", str:byte(k, k));
    i = i + 1;
    if i > 0x10 then
      i  = 1;
    end
    ds = ds .. h;
  end
  return ds .. "\r\n", str;
end
function txspyline:print_head_hexs(name)
  local str = self:get_head_ascii();
  local ds = self:print_names(name) .. '(' .. self:print_head(#str) .. ')';

  self:level_increase();
  local tab = "\r\n" .. self:print_blanks();
  self:level_decrease();

  local i = 1;
  local h;
  for k = 1, #str do
    if i == 1 then
      ds = ds .. tab;
    end
    h = string.format("%02X ", str:byte(k, k));
    i = i + 1;
    if i > 0x10 then
      i  = 1;
    end
    ds = ds .. h;
  end
  return ds .. "\r\n", str;
end
--[=======[
    string, string txspyline:print_head_ascii( string name );
        --输出ASCII"..."，同时返回字符串
    string, string txspyline:print_head_utf8( string name );
        --输出UTF8"..."，同时返回转换后的字符串
]=======]
function txspyline:print_head_ascii(name)
  local str = self:get_head_ascii();
  return self:print_names(name) .. '(' .. self:print_head(#str) .. ")ASCII\"" ..
          str ..
          "\"\r\n",
          str;
end
function txspyline:print_head_utf8(name)
  local str = self:get_head_ascii();
  str = utf82s(str);
  return self:print_names(name) .. '(' .. self:print_head(#str) .. ")UTF8\"" ..
          str ..
          "\"\r\n",
          str;
end
--[=======[
    string    txspyline:print_ip        ( string name );
        --输出IP数值、IP格式，同时返回IP数值
    string    txspyline:print_time      ( string name );
        --输出时间数值、时间格式，同时返回时间数值
    string    txspyline:print_key       ( string name );
        --输出KEY，同时返回KEY串
    string    txspyline:print_head_line_only_head( string name );
        --读取带头的数据，但只输出头格式，同时返回数据
    string    txspyline:print_remain    ( string name );
        --以hex2show输出剩余数据
    string    txspyline:print_tlv       ( TXData td );
        --输出TLV格式
        --查询TXP.TLVSpy是否存在目标TLV脚本，如果存在，则调用脚本解析，不存在，则默认输出
]=======]
function txspyline:print_ip(name)
  local ip = self:get_dword();
  return self:print_names(name) ..
          string.format("%08X [%d.%d.%d.%d]\r\n",
            ip,
            string.unpack("BBBB", string.pack(">I4", ip))),
          ip;
end
function txspyline:print_time(name)
  local time = self:get_dword();
  return self:print_names(name) ..
          string.format("%08X [%s]\r\n", time,
                      os.date("%Y/%m/%d %H:%M:%S",time)),
          time;
end
function txspyline:print_key(name)
  return self:print_hexs(name, TXP.TEAN_Key_Size);
end
function txspyline:print_head_line_only_head(name)
  local nline = self:ghl();
  return self:print_names(name) .. '(' .. self:print_head(#nline.line) .. ")\r\n",
           nline;
end
function txspyline:print_remain()
  if #self.line == 0 then
    return "";
  end
  return hex2show(self.line);
end
function txspyline:print_tlv(td)
  local ds = "";
  local tag = self:get_word();
  local len = self:get_word();
  local codec = TXP.TLVSpy[tag];
  if codec == nil then
    self:level_increase();
    ds = "\r\n" .. 
          self:print_names(string.format("UNKNOW TLV_%04X", tag)) ..
          string.format("   %04X:(%04X)\r\n", tag, len);
    self:level_increase();
    ds = ds .. self:print_hexs("VALUE", len);
    self:level_decrease();
    self:level_decrease();
    return ds;
  end
  local data = self:get_line(len);
  local name = TXP.TLVName[tag]
  data:level_increase();
  ds = "\r\n" ..
        data:print_names(string.format("%s", name)) ..
        string.format("   %04X:(%04X)\r\n", tag, #data.line);
  data:level_increase();
  
    local b, dsds = pcall(codec, td, data);
    if not b then
      dsds = string.format("\r\nTLV%04X解析失败:%s\r\n", tag, dsds);
    end

  ds = ds .. dsds .. data:print_remain();
  return ds;
end

-------- -------- -------- --------
--[=======[
    txspyline.inc     = txspyline.level_increase;
    txspyline.dec     = txspyline.level_decrease;
    txspyline.pk      = txspyline.print_blanks;
    txspyline.pn      = txspyline.print_names;
    txspyline.pb      = txspyline.print_get_byte;
    txspyline.pw      = txspyline.print_get_word;
    txspyline.pd      = txspyline.print_get_dword;
    txspyline.ph      = txspyline.print_head;
    txspyline.phs     = txspyline.print_hexs;
    txspyline.phhs    = txspyline.print_head_hexs;
    txspyline.pha     = txspyline.print_head_ascii;
    txspyline.ph8     = txspyline.print_head_utf8;
    txspyline.pip     = txspyline.print_ip;
    txspyline.ptm     = txspyline.print_time;
    txspyline.pkey    = txspyline.print_key;
    txspyline.phloh   = txspyline.print_head_line_only_head;
    txspyline.pr      = txspyline.print_remain;
    txspyline.ptlv    = txspyline.print_tlv;
]=======]
txspyline.inc     = txspyline.level_increase;
txspyline.dec     = txspyline.level_decrease;
txspyline.pk      = txspyline.print_blanks;
txspyline.pn      = txspyline.print_names;
txspyline.pb      = txspyline.print_get_byte;
txspyline.pw      = txspyline.print_get_word;
txspyline.pd      = txspyline.print_get_dword;
txspyline.ph      = txspyline.print_head;
txspyline.phs     = txspyline.print_hexs;
txspyline.phhs    = txspyline.print_head_hexs;
txspyline.pha     = txspyline.print_head_ascii;
txspyline.ph8     = txspyline.print_head_utf8;
txspyline.pip     = txspyline.print_ip;
txspyline.ptm     = txspyline.print_time;
txspyline.pkey    = txspyline.print_key;
txspyline.phloh   = txspyline.print_head_line_only_head;
txspyline.pr      = txspyline.print_remain;
txspyline.ptlv    = txspyline.print_tlv;