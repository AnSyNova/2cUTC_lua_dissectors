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
local systcpda_smc_extension_header = ProtoField.bytes("systcpda_smc.extension_header", "**Extension header")

local systcpda_smc_con_lcl = ProtoField.uint32("systcpda_smc.con_lcl", "Local ConnID", base.HEX)
local systcpda_smc_con_rmt = ProtoField.uint32("systcpda_smc.con_rmt", "Remote ConnID", base.HEX)
local systcpda_smc_grp_lcl = ProtoField.uint64("systcpda_smc.grp_lcl", "Local Gid", base.HEX)
local systcpda_smc_grp_rmt = ProtoField.uint64("systcpda_smc.grp_rmt", "Remote Gid", base.HEX)
local systcpda_smc_qp_lcl = ProtoField.uint24("systcpda_smc.qp_lcl", "Local QueuePair", base.HEX)
local systcpda_smc_qp_rmt = ProtoField.uint24("systcpda_smc.qp_rmt", "Remote QueuePair", base.HEX)

local systcpda_smc_payload = ProtoField.bytes("systcpda_smc.payload", "**Payload")

local systcpda_smc_llc_func = ProtoField.uint8("systcpda_smc.llc_func", "LLC Function")
local systcpda_smc_llc_len = ProtoField.uint16("systcpda_smc.llc_len", "LLC length")
local systcpda_smc_llc_flg = ProtoField.uint8("systcpda_smc.llc_flg", "LLC flags")
local systcpda_smc_llc_lnkid = ProtoField.uint8("systcpda_smc.llc_lnkid", "LLC LinkId")
local systcpda_smc_llc_rsncd = ProtoField.uint32("systcpda_smc.llc_rsncd", "LLC Reasoncode", base.HEX)

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

-- setup getting the SYSTCPDA fields that we need from the SYSTCPDA dissector (that called us)
local systcpda_extensionlen = Field.new("systcpda.extensionlen")
local systcpda_payloadlen = Field.new("systcpda.payloadlen")
local systcpda_entid = Field.new("systcpda.entid")

local frame_interface_name = Field.new("frame.interface_name")

--DISSECTOR
--DISSECTOR
--DISSECTOR

-- SYSTCPDA_SMCD
function proto_systcpda_smc.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end

    pinfo.cols.protocol = proto_systcpda_smc.name
	
	local subtree = tree:add(proto_systcpda_smc, buffer())

    local extension_length = systcpda_extensionlen().value - 4
    local payload_length = systcpda_payloadlen().value

    local interface_name = frame_interface_name().value

    if string.sub(interface_name, 1, 6) == "EZAISM" then

	    -- dissect SMC-D
	    -- add to subtree here

        subtree:add("SMC-D")
        pinfo.cols.info:append("-D")

        -- Show the smc_extension_header as a big block (if desired)
        subtree:add(systcpda_smc_extension_header, buffer(0, extension_length))

        -- Dissect the smc_extension_header
        subtree:add(systcpda_smc_con_lcl, buffer(32, 4))
        subtree:add(systcpda_smc_con_rmt, buffer(36, 4))
        subtree:add(systcpda_smc_grp_lcl, buffer(56, 8))
        subtree:add(systcpda_smc_grp_rmt, buffer(40, 8))
        subtree:add(systcpda_smc_qp_lcl, buffer(75, 3))
        subtree:add(systcpda_smc_qp_rmt, buffer(72, 3))

   	    -- Show the smc_payload as a big block (if desired)
        subtree:add(systcpda_smc_payload, buffer(extension_length, payload_length))

        -- Dissect the smc_payload
        local payload = buffer( extension_length)

    elseif string.sub(interface_name, 1, 5) == "EZARI" then

   	    -- dissect SMC-R
	    -- add to subtree here

        subtree:add("SMC-R")
        pinfo.cols.info:append("-R")

        -- Show the smc_extension_header as a big block (if desired)
        subtree:add(systcpda_smc_extension_header, buffer(0, extension_length))

        -- Dissect the smc_extension_header
        subtree:add(systcpda_smc_con_lcl, buffer(32, 4))
        subtree:add(systcpda_smc_con_rmt, buffer(36, 4))
        subtree:add(systcpda_smc_grp_lcl, buffer(56, 8))
        subtree:add(systcpda_smc_grp_rmt, buffer(40, 8))
        subtree:add(systcpda_smc_qp_lcl, buffer(75, 3))
        subtree:add(systcpda_smc_qp_rmt, buffer(72, 3))

   	    -- Show the smc_payload as a big block (if desired)
        subtree:add(systcpda_smc_payload, buffer(extension_length, payload_length))

        -- Dissect the smc_payload
        local payload = buffer(extension_length)

        subtree:add(systcpda_smc_llc_func, payload(0, 1))
        subtree:add(systcpda_smc_llc_len, payload(1, 2))
        subtree:add(systcpda_smc_llc_flg, payload(3, 1))
        subtree:add(systcpda_smc_llc_lnkid, payload(4, 1))
        subtree:add(systcpda_smc_llc_rsncd, payload(5, 4))

    else

       	-- dissect SMC-R
    	-- add to subtree here

        subtree:add("SMC-?")

        -- Show the smc_extension_header as a big block (if desired)
        subtree:add(systcpda_smc_extension_header, buffer(0, extension_length))

       	-- Show the smc_payload as a big block (if desired)
        subtree:add(systcpda_smc_payload, buffer(extension_length, payload_length))

    end
    
end
