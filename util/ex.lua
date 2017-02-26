-- This script is meant to be used with tshark/wireshark, with command-line
-- arguments, using the '-X lua_script[N]:argN' option.
-- Each argument identifies a field we will extract into two new
-- fields called "extract.string" and "extract.hex"
-- Those new fields can then be printed by tshark.
--
-- For example, if this script is saved as "extract.lua", then the following:
--   tshark -r myfile -X lua_script:extract.lua -X lua_script1:data-text-lines -T fields -e extract.string
-- will read the file called "myfile", extract each "data-text-lines" field, and
-- print its string value out to the console.
-- The following:
--   wireshark -r myfile -X lua_script:extract.lua -X lua_script1:data-text-lines
-- will do something similar in the GUI, showing the extracted values in the tree.

local args = { ... }

-- exit if no arguments were passed in
if #args == 0 then
    return
end

-- verify tshark/wireshark version is new enough - needs to be 1.12+
local major, minor, micro = 0, 0, 0
if get_version then
    major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
    if not major then
        major, minor, micro = 0, 0, 0
    end
end
if (tonumber(major) == 0) or ((tonumber(major) <= 1) and (tonumber(minor) < 12)) then
    error("Sorry, but your Wireshark/Tshark version is too old for this script!\n"..
          "This script needs Wireshark/Tshark version 1.12 or higher.\n" )
end

-- a table to hold field extractors
local fields = {}

-- create field extractor(s) for the passed-in argument(s)
for i, arg in ipairs(args) do
    fields[i] = Field.new(arg)
end

-- our fake protocol
local exproto = Proto.new("extract", "Data Extractor")

-- the new fields that contain the extracted data (one in string form, one in hex)
local exfield_string = ProtoField.new("Extracted String Value", "extract.string", ftypes.STRING)
local exfield_hex    = ProtoField.new("Extracted Hex Value", "extract.hex", ftypes.STRING)

-- register the new fields into our fake protocol
exproto.fields = { exfield_string, exfield_hex }

function exproto.dissector(tvbuf,pktinfo,root)
    local tree = nil

    for i, field in ipairs(fields) do
        -- extract the field into a table of FieldInfos
        finfos = { field() }

        if #finfos > 0 then
            -- add our proto if we haven't already
            if not tree then
                tree = root:add(exproto)
            end

            for _, finfo in ipairs(finfos) do
                -- get a TvbRange of the FieldInfo
                local ftvbr = finfo.tvb
                tree:add(exfield_string, ftvbr:string(ENC_UTF_8))
                tree:add(exfield_hex,tostring(ftvbr:bytes()))
            end
        end
    end

end

-- register it as a postdissector, and force all fields to be generated
register_postdissector(exproto, true)
