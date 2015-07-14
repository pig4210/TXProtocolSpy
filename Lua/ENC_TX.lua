require "xlua"

local deltb =
  {
  "0032",
  "0105",
  "010B",
  }

local filename = "TXProtocol/TXProtocol.lua";
local notes = "";

local file = io.open(filename, 'r');
local data = file:read('a');
file:close();

for note in data:gmatch("%-%-%[=======%[(.-)%]=======%]") do
  notes = notes .. "\r\n" .. note .. "\r\n";
end

data = data:gsub("(require \"([^\"]+)\";?)",

    function(str, filename)
      local file = io.open(filename .. ".lua", "r");
      if file == nil then
        return str;
      end
      local da = file:read("a");
      file:close();

      for note in da:gmatch("%-%-%[=======%[(.-)%]=======%]") do
        notes = notes .. "\r\n" .. note .. "\r\n";
      end

      da = da:gsub("(require \"([^\"]+)\";?)",

          function(str, filename)
              for k, v in pairs(deltb) do
                if filename:find(v) then
                  return "";
                end
              end

              local file = io.open(filename .. ".lua", "r");
              if file == nil then
                return str;
              end
              local dada = file:read("a");
              file:close();

              for note in dada:gmatch("%-%-%[=======%[(.-)%]=======%]") do
                notes = notes .. "\r\n" .. note .. "\r\n";
              end

              return "\r\ndo\r\n" .. dada .. "\r\nend\r\n";
          end

          );
      return "\r\ndo\r\n" .. da .. "\r\nend\r\n";
    end

    );

local data, err = load(data);
if err then
  error(err);
  return;
end

data = string.dump(data, true);

local file = io.open(filename:gsub("%.lua", ".txt"), "w");
file:write(notes);
file:close();

local file = io.open(filename:gsub("%.lua", ".e.lua"), "wb");
file:write(data);
file:close();


