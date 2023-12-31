--[[
	2cUTC SYSTCPIS dissector
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

-- SYSTCPIS
local proto_systcpis = Proto("systcpis", "Component SYSTCPIS")

-- Fields that you can use in filters and coloring rules:
local systcpis_len = ProtoField.uint16("systcpis.len", "Length")
local systcpis_data = ProtoField.bytes("systcpis.data", "Data")

proto_systcpis.fields = {  
	systcpis_len,
	systcpis_data
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPIS
function proto_systcpis.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_systcpis.name

    local subtree = tree:add(proto_systcpis, buffer(), "Component SYSTCPIS")

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(systcpis_len, buffer(0, 2))

	-- dissect
	-- add to subtree here
	subtree:add(systcpis_data, buffer(2, ctrace_len - 4))

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end
