--[[
	2cUTC SYSTCPIP_TCP dissector
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

-- SYSTCPIP_TCP
local proto_systcpip_tcp = Proto("systcpip_tcp", "Option TCP")

-- Fields that you can use in filters and coloring rules:
-- currently none

-- setup getting the SYSTCPIP DESCRIPTION field from the SYSTCPIP dissector (that called us)
local systcpip_description = Field.new("systcpip.description")

--DISSECTOR
--DISSECTOR
--DISSECTOR

local function pkt_error_on(pinfo)
	pinfo.in_error_pkt = true
end

local function pkt_error_off(pinfo)
	pinfo.in_error_pkt = false
end

local function diss_ip(buf, pinfo, tree)
	Dissector.get("ip"):call(buf, pinfo, tree)
end

local function diss_tcp(buf, pinfo, tree)
	Dissector.get("tcp"):call(buf, pinfo, tree)
end

local function dissect_IP_TCP_header(offset_IP, offset_TCP, buffer, pinfo, tree)
	pcall(pkt_error_on, pinfo)
	local ip_header_len = buffer(offset_IP, 1):uint() % 16 * 4
	pcall(diss_ip, buffer(offset_IP, ip_header_len):tvb(), pinfo, tree)
	local tcp_header_len = buffer(offset_TCP + 12, 1):uint() / 16 * 4
	pcall(diss_tcp, buffer(offset_TCP, tcp_header_len):tvb(), pinfo, tree)
	pcall(pkt_error_off, pinfo)
end

-- SYSTCPIP_TCP
function proto_systcpip_tcp.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = proto_systcpip_tcp.name

    local subtree = tree:add(proto_systcpip_tcp, buffer)

	-- dissect
	-- add to subtree here

	-- check for special handling

	-- depending on the ENTID translation string?
	local description = systcpip_description().range

	-- this one is known to contain IP/TCP headers
	if description == "!Bad SYN return code" then
		Dissect_IP_TCP_header(i + 86, i + 134, buffer, pinfo, subtree)
		return
	end

	-- depending on something to be found in the buffer?
	local bufstr = buffer(0, -1):raw()

	-- "TCB_CTRL" E3 C3 C2 40 C3 E3 D9 D3
	i, j = string.find(bufstr, "\xE3\xC3\xC2\x40\xC3\xE3\xD9\xD3")
	if i ~= nil then
		dissect_IP_TCP_header(i + 251, i + 317, buffer, pinfo, subtree)
		return
	end

	-- If we don't have any special stuff to show, just show the data.
	subtree:add("Nothing special to show")
end
