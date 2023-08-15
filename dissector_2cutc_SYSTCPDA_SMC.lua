--[[
	2cUTC SYSTCPDA_SMC dissector
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

-- SYSTCPDA_SMC
local proto_systcpda_smc = Proto("systcpda_smc", "SMC Extension")

-- Fields that you can use in filters and coloring rules:
local systcpda_smc_extension_length = ProtoField.bytes("systcpda_smc.extension_length", "SMC extension length")
local systcpda_smc_extension_type = ProtoField.bytes("systcpda_smc.extension_type", "SMC extension type")
local systcpda_smc_extension_header = ProtoField.bytes("systcpda_smc.extension_header", "SMC extension header")

local systcpda_smc_con_lcl = ProtoField.uint32("systcpda_smc.con_lcl", "SMC Local ConnID", base.HEX)
local systcpda_smc_con_rmt = ProtoField.uint32("systcpda_smc.con_rmt", "SMC Remote ConnID", base.HEX)
local systcpda_smc_grp_lcl = ProtoField.uint64("systcpda_smc.grp_lcl", "SMC Local Gid", base.HEX)
local systcpda_smc_grp_rmt = ProtoField.uint64("systcpda_smc.grp_rmt", "SMC Remote Gid", base.HEX)
local systcpda_smc_qp_lcl = ProtoField.uint24("systcpda_smc.qp_lcl", "SMC Local QueuePair", base.HEX)
local systcpda_smc_qp_rmt = ProtoField.uint24("systcpda_smc.qp_rmt", "SMC Remote QueuePair", base.HEX)

local systcpda_smc_payload = ProtoField.bytes("systcpda_smc.payload", "SMC payload")

local systcpda_smc_payload_llc_func = ProtoField.uint8("systcpda_smc.llc_func", "SMC LLC Function")
local systcpda_smc_payload_llc_len = ProtoField.uint16("systcpda_smc.llc_len", "SMC LLC length")
local systcpda_smc_payload_llc_flg = ProtoField.uint8("systcpda_smc.flg", "SMC LLC flags")
local systcpda_smc_payload_llc_lnkid = ProtoField.uint8("systcpda_smc.lnkid", "SMC LLC LinkId")
local systcpda_smc_payload_llc_rsncd = ProtoField.uint32("systcpda_smc.rsncd", "SMC LLC Reasoncode", base.HEX)

proto_systcpda_smc.fields = {  
    systcpda_smc_extension_length,
    systcpda_smc_extension_type,
    systcpda_smc_extension_header,
 
    systcpda_smc_con_lcl,
    systcpda_smc_con_rmt,
    systcpda_smc_grp_lcl,
    systcpda_smc_grp_rmt,
    systcpda_smc_qp_lcl,
    systcpda_smc_qp_rmt,

    systcpda_smc_payload,

    systcpda_smc_llc_func,
    systcpda_smc_llc_len,
    systcpda_smc_llc_flg,
    systcpda_smc_llc_lnkid,
    systcpda_smc_llc_rsncd
}

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPDA_SMCD
function proto_systcpda_smc.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	local subtree = tree:add(proto_systcpda_smc, buffer)

	-- dissect
	-- add to subtree here
    subtree:add(systcpda_smc_extension_length, buffer(0, 2))

    subtree:add(systcpda_smc_extension_type, buffer(2, 2))

    local extension_length = buffer(0, 2):uint() - 4

    subtree:add(systcpda_smc_extension_header, buffer(4, extension_length))

    subtree:add(systcpda_smc_con_lcl, buffer(40, 4))
    subtree:add(systcpda_smc_con_rmt, buffer(44, 4))
    subtree:add(systcpda_smc_grp_lcl, buffer(64, 8))
    subtree:add(systcpda_smc_grp_rmt, buffer(48, 8))
    subtree:add(systcpda_smc_qp_lcl, buffer(83, 3))
    subtree:add(systcpda_smc_qp_rmt, buffer(80, 3))

    subtree:add(systcpda_smc_payload, buffer(4 + extension_length))

    local payload = buffer(4 + extension_length):tvb()

 --[[
    subtree:add(systcpda_smc_llc_func, payload(0, 1))
    subtree:add(systcpda_smc_llc_len, payload(1, 2))
    subtree:add(systcpda_smc_llc_flg, payload(3, 1))
    subtree:add(systcpda_smc_llc_lnkid, payload(4, 1))
    subtree:add(systcpda_smc_llc_rsncd, payload(5, 4))
]]
end
