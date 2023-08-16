--[[
	2cUTC CSQX dissector
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

-- CSQX
local proto_csqx = Proto("csqx", "Component CSQX")

-- Fields that you can use in filters and coloring rules:
local csqx_len = ProtoField.uint16("csqx.len", "Length")
local csqx_data = ProtoField.bytes("csqx.data", "Data")

proto_csqx.fields = {  
	csqx_len,
	csqx_data
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- CSQX
function proto_csqx.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_csqx.name

    local subtree = tree:add(proto_csqx, buffer())

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(csqx_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(csqx_data, buffer(2, ctrace_len - 4))

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end
