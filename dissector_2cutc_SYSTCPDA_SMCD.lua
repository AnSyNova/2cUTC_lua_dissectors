--[[
	2cUTC SYSTCPDA_SMCD dissector
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

-- SYSTCPDA_SMCD
local proto_systcpda_smcd = Proto("systcpda_smcd", "Option SMCD")

-- Fields that you can use in filters and coloring rules:
local systcpda_smcd_data = ProtoField.bytes("systcpda_smcd.data", "Data")

proto_systcpda_smcd.fields = {  
	systcpda_smcd_data
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPDA_SMCD
function proto_systcpda_smcd.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	local subtree = tree:add(proto_systcpda_smcd, buffer)

	-- dissect
	-- add to subtree here
	subtree:add(systcpda_smcd_data, buffer(0))
end
