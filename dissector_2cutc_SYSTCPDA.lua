--[[
	2cUTC SYSTCPDA dissector
    Copyright (C) 2023  Michael Stiemke

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
]]

--INIT
--INIT
--INIT

-- SYSTCPDA
local proto_systcpda = Proto("systcpda", "Component SYSTCPDA")

-- Fields that you can use in filters and coloring rules:
local systcpda_type = ProtoField.string("systcpda.type", "Type")
local systcpda_len = ProtoField.uint16("systcpda.len", "Length")
local systcpda_data = ProtoField.bytes("systcpda.data", "Data")

proto_systcpda.fields = {  
	systcpda_type,
	systcpda_len,
	systcpda_data
}

local _2cutc_extension = Field.new("2cutc.extension")

--[[
The 2cUTC extension provided for the SYSTCPDA component:

       00   01    02  03  04  05  06  07  08  09  0A    0B  0C  0D  0E  0F  ..  ..  
0000   extension_type                         ...................
]]

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPDA
function proto_systcpda.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_systcpda.name

    local subtree = tree:add(proto_systcpda, buffer)

	-- get 2cUTC derived information from higher up
	local extension = _2cutc_extension().range

	local extension_type = extension:string()

	subtree:add(systcpda_type, extension_type)

	extension_type = string.gsub(string.lower(extension_type), "^%s*(.-)%s*$", "%1")

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(systcpda_len, buffer(0, 2))
	
	-- see above, special data inserted by 2cUTC
	pinfo.cols.info:append(" " .. extension_type)
	if extension_type == "smcd" then
		Dissector.get("systcpda_smcd"):call(buffer(2, ctrace_len - 4):tvb(), pinfo, subtree)
	else
		-- dissect
		-- add to subtree here
		subtree:add(systcpda_data, buffer(2, ctrace_len - 4))
	end

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end
