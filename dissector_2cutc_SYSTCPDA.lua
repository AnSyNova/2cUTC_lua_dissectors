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
local systcpda_common_header = ProtoField.bytes("systcpda.common_header", "Common Header")

local systcpda_asid = ProtoField.uint16("systcpda.asid", "ASID", base.HEX)
local systcpda_entid = ProtoField.uint32("systcpda.entid","Entry ID", base.HEX)
local systcpda_tod = ProtoField.uint64("systcpda.tod", "TimeofDay", base.HEX)
local systcpda_linkname = ProtoField.string("systcpda.linkname", "Interface")
local systcpda_tod2 = ProtoField.uint64("systcpda.tod2", "TimeofDay#2", base.HEX)
local systcpda_srcip = ProtoField.uint32("systcpda.srcip", "Source IP ", base.HEX)
local systcpda_dstip = ProtoField.uint32("systcpda.dstip", "Destination IP ", base.HEX)
local systcpda_srcport = ProtoField.uint16("systcpda.srcport", "Source Port")
local systcpda_dstport = ProtoField.uint16("systcpda.dstport", "Destination Port")
local systcpda_vlanid = ProtoField.uint16("v.vlanid", "VLAN ID")

local systcpda_extension = ProtoField.bytes("systcpda.extension", "Extension")

proto_systcpda.fields = {  
	systcpda_type,
	systcpda_len,
	systcpda_common_header,

	systcpda_asid,
	systcpda_entid,
	systcpda_tod,
	systcpda_linkname,
    systcpda_tod2,
    systcpda_srcip,
    systcpda_dstip,
	systcpda_srcport,
	systcpda_dstport,
	systcpda_vlanid,

	systcpda_extension
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
	local extension_type = string.gsub(extension:string(), "^%s*(.-)%s*$", "%1")
	subtree:add(systcpda_type, extension_type)
	extension_type = string.lower(extension_type)

	-- CTRACE begin length field
	local ctrace_len = buffer(0, 2):uint()
	subtree:add(systcpda_len, buffer(0, 2))

	-- Show the common header as a big block
	-- subtree:add(systcpda_common_header, buffer(2, 106))

	-- Dissect the common_header
	subtree:add(systcpda_asid, buffer(2, 2))
	subtree:add(systcpda_entid, buffer(4, 4))
	local tstp1_z = buffer(8, 8):uint64()
	local tstp1_z_secs = ztod_2_unix(tstp1_z:tonumber())/1000000
	subtree:add(systcpda_tod, buffer(8, 8)):append_text(" (" .. format_date(tstp1_z_secs) .. ")")
	subtree:add_packet_field(systcpda_linkname, buffer:range(24, 16), ENC_EBCDIC)
	local tstp2_z = buffer(8, 8):uint64()
	local tstp2_z_secs = ztod_2_unix(tstp2_z:tonumber())/1000000
	subtree:add(systcpda_tod2, buffer(8, 8)):append_text(" (" .. format_date(tstp2_z_secs) .. ")")
	subtree:add(systcpda_srcip, buffer(60, 4))
    subtree:add(systcpda_dstip, buffer(76, 4))
	subtree:add(systcpda_srcport, buffer(80, 2))
    subtree:add(systcpda_dstport, buffer(82, 2))
    subtree:add(systcpda_vlanid, buffer(90, 2))

	-- see above, special data inserted by 2cUTC
	pinfo.cols.info:append(" " .. extension_type)
	if extension_type == "smc" then
		Dissector.get("systcpda_smc"):call(buffer(108, ctrace_len - 108 - 4):tvb(), pinfo, subtree)
	else
		subtree:add("Unknown extension type, cannot dissect:")
		subtree:add(systcpda_extension, buffer(108, ctrace_len - 108 - 4))
	end

	-- CTRACE end length field
	subtree:add(buffer(ctrace_len - 2, 2), "Length repeated: " .. buffer(ctrace_len - 2, 2):uint())
end

function ztod_2_unix(ztod)
	local offset = 9048018124800000000
    local utod = (ztod - offset) / 4096
	return utod
  end
