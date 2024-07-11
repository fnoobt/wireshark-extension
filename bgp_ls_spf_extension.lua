-- 注册BGP LinkState协议
-- =================================================
--     注册BGP LinkState协议,Proto.new（名称、描述）
-- =================================================
local proto_bgp_ls = Proto("bgp_ls", "BGP LinkState Protocol")

local BGP_MARKER_LEN = 16
local TYPE_AND_LENGTH_LEN = 4
local AFI_BGP_LS = 16388
local SAFI_BGP_LS_SPF = 80

-- =================================
--     tvbuff读取对象
-- =================================
readbuf = {}
readbuf.new = function(tvbuf, offset)
    local self = {}
    offset = offset or 0

    self.read = function(length)
        local r = tvbuf(offset, length)
        offset = offset + length
        return r
    end

    self.read_all = function()
        local r = tvbuf(offset, tvbuf:len() - offset)
        offset = tvbuf:len()
        return r
    end

    self.only_read = function(start_offset, length)
        local r = tvbuf(start_offset, length)
        return r
    end

    self.back = function(length)
        offset = offset - length
    end

    self.skip = function(length)
        offset = offset + length
    end

    self.reset = function()
        offset = 0
    end

    self.offset = function()
        return offset
    end

    self.remaining_length = function()
        return (tvbuf:len() - offset)
    end

    self.is_overflow = function(length)
        if ((tvbuf:len() - offset) < length) then
            return true
        else
            return false
        end
    end

    self.not_tlv_tail = function(start_offset, length)
        if ((offset - start_offset) < length) then
            return true
        else
            return false
        end
    end

    self.not_tail = function()
        if (offset < tvbuf:len()) then
            return true
        else
            return false
        end
    end
  
    return self
end

-- =================================
--     BGP LS SPF Message Format
-- =================================
fields = {}
-- header
fields['bgp_ls.marker'] = ProtoField.ubytes("bgp_ls.marker", "Marker")
fields['bgp_ls.length'] = ProtoField.uint16("bgp_ls.length", "Length")
fields['bgp_ls.type'] = ProtoField.uint8("bgp_ls.type", "Type")
fields['bgp_ls.witdrawn_routes.length'] = ProtoField.uint16("bgp_ls.witdrawn_routes.length", "Witdrawn Routes Length")
fields['bgp_ls.path_attributes.length'] = ProtoField.uint16("bgp_ls.path_attributes.length", "Path Attributes Length")
fields['bgp_ls.continuation'] = ProtoField.none("bgp_ls.continuation", "Continuation")

-- Path Attribute
fields['bgp_ls.path_attribute.flags'] = ProtoField.uint8("bgp_ls.path_attribute.flags", "Flags")
fields['bgp_ls.path_attribute.type_code'] = ProtoField.uint8("bgp_ls.path_attribute.type_code", "Type Code")
fields['bgp_ls.path_attribute.length'] = ProtoField.uint8("bgp_ls.path_attribute.length", "Length")
fields['bgp_ls.path_attribute.ext_length'] = ProtoField.uint16("bgp_ls.path_attribute.ext_length", "Length")
-- =================================
-- mp_[un]reach_nlri
fields['bgp_ls.path_attribute.afi'] = ProtoField.uint16("bgp_ls.path_attribute.afi", "Address family identifier")
fields['bgp_ls.path_attribute.safi'] = ProtoField.uint8("bgp_ls.path_attribute.safi", "Subsequent Address family identifier")
fields['bgp_ls.path_attribute.mp_reach_nlri.next_hop'] = ProtoField.ubytes("bgp_ls.path_attribute.mp_reach_nlri.next_hop", "Next hop")
fields['bgp_ls.path_attribute.mp_reach_nlri.next_hop.ipv6'] = ProtoField.ipv6("bgp_ls.path_attribute.mp_reach_nlri.next_hop.ipv6", "Ipv6 Address")
fields['bgp_ls.path_attribute.mp_reach_nlri.nbr_snpa'] = ProtoField.uint8("bgp_ls.path_attribute.mp_reach_nlri.nbr_snpa", "Number of Subnetwork points of attachment(SNPA)")
fields['bgp_ls.path_attribute.nlri_type'] = ProtoField.uint16("bgp_ls.path_attribute.nlri_type", "NLRI Type")
fields['bgp_ls.path_attribute.nlri_length'] = ProtoField.uint16("bgp_ls.path_attribute.nlri_length", "NLRI Length")
fields['bgp_ls.path_attribute.nlri'] = ProtoField.none("bgp_ls.path_attribute.nlri", "BGP-LS NLRI")
fields['bgp_ls.path_attribute.nlri.protocol_id'] = ProtoField.uint8("bgp_ls.path_attribute.nlri.protocol_id", "Protocol ID")
fields['bgp_ls.path_attribute.nlri.identifier'] = ProtoField.uint64("bgp_ls.path_attribute.nlri.identifier", "Identifier")
fields['bgp_ls.path_attribute.nlri.type'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.type", "Type")
fields['bgp_ls.path_attribute.nlri.length'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.length", "Length")
-- node descriptors
fields['bgp_ls.path_attribute.nlri.node'] = ProtoField.none("bgp_ls.path_attribute.nlri.node", "Node Descriptors")
fields['bgp_ls.path_attribute.nlri.node.as'] = ProtoField.none("bgp_ls.path_attribute.nlri.node.as", "Autonomous System TLV")
fields['bgp_ls.path_attribute.nlri.node.as.id'] = ProtoField.uint32("bgp_ls.path_attribute.nlri.node.as.id", "AS ID")
fields['bgp_ls.path_attribute.nlri.node.bgp_ls'] = ProtoField.none("bgp_ls.path_attribute.nlri.node.bgp_ls", "BGP-LS Identifier TLV")
fields['bgp_ls.path_attribute.nlri.node.bgp_ls.id'] = ProtoField.uint32("bgp_ls.path_attribute.nlri.node.bgp_ls.id", "BGP-LS ID")
fields['bgp_ls.path_attribute.nlri.node.igp'] = ProtoField.none("bgp_ls.path_attribute.nlri.node.igp", "IGP Router Identifier TLV")
fields['bgp_ls.path_attribute.nlri.node.igp.id'] = ProtoField.ubytes("bgp_ls.path_attribute.nlri.node.igp.id", "IGP ID")
-- link descriptors
fields['bgp_ls.path_attribute.nlri.link'] = ProtoField.none("bgp_ls.path_attribute.nlri.link", "Link Descriptors")
fields['bgp_ls.path_attribute.nlri.link.type'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.link.type", "Type")
fields['bgp_ls.path_attribute.nlri.link.length'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.link.length", "Length")
fields['bgp_ls.path_attribute.nlri.link.local_remote_id'] = ProtoField.none("bgp_ls.path_attribute.nlri.link.local_remote_id", "link Local/Remote Identifier TLV")
fields['bgp_ls.path_attribute.nlri.link.local_remote_id.local_id'] = ProtoField.uint32("bgp_ls.path_attribute.nlri.link.local_remote_id.local_id", "link Local Identifier")
fields['bgp_ls.path_attribute.nlri.link.local_remote_id.remote_id'] = ProtoField.uint32("bgp_ls.path_attribute.nlri.link.local_remote_id.remote_id", "link Remote Identifier")
fields['bgp_ls.path_attribute.nlri.link.ipv4_interface_address'] = ProtoField.none("bgp_ls.path_attribute.nlri.link.ipv4_interface_address", "IPV4 Interface Address TLV")
fields['bgp_ls.path_attribute.nlri.link.ipv4_interface_address.ipv4'] = ProtoField.ipv4("bgp_ls.path_attribute.nlri.link.ipv4_interface_address.ipv4", "IPV4 Interface Address")
fields['bgp_ls.path_attribute.nlri.link.ipv4_neighbor_address'] = ProtoField.none("bgp_ls.path_attribute.nlri.link.ipv4_neighbor_address", "IPV4 Neighbor Address TLV")
fields['bgp_ls.path_attribute.nlri.link.ipv4_neighbor_address.ipv4'] = ProtoField.ipv4("bgp_ls.path_attribute.nlri.link.ipv4_neighbor_address.ipv4", "IPV4 Neighbor Address")
fields['bgp_ls.path_attribute.nlri.link.ipv6_interface_address'] = ProtoField.none("bgp_ls.path_attribute.nlri.link.ipv6_interface_address", "IPV6 Interface Address TLV")
fields['bgp_ls.path_attribute.nlri.link.ipv6_interface_address.ipv6'] = ProtoField.ipv6("bgp_ls.path_attribute.nlri.link.ipv6_interface_address.ipv6", "IPV6 Interface Address")
fields['bgp_ls.path_attribute.nlri.link.ipv6_neighbor_address'] = ProtoField.none("bgp_ls.path_attribute.nlri.link.ipv6_neighbor_address", "IPV6 Neighbor Address TLV")
fields['bgp_ls.path_attribute.nlri.link.ipv6_neighbor_address.ipv6'] = ProtoField.ipv6("bgp_ls.path_attribute.nlri.link.ipv6_neighbor_address.ipv6", "IPV6 Neighbor Address")
fields['bgp_ls.path_attribute.nlri.link.addr_family'] = ProtoField.none("bgp_ls.path_attribute.nlri.link.addr_family", "Address Family TLV")
fields['bgp_ls.path_attribute.nlri.link.addr_family.value'] = ProtoField.uint8("bgp_ls.path_attribute.nlri.link.addr_family.value", "Address Family Value")
-- prefix descriptors
fields['bgp_ls.path_attribute.nlri.prefix'] = ProtoField.none("bgp_ls.path_attribute.prefix.link", "Prefix Descriptors")
fields['bgp_ls.path_attribute.nlri.prefix.type'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.prefix.type", "Type")
fields['bgp_ls.path_attribute.nlri.prefix.length'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.prefix.length", "Length")
fields['bgp_ls.path_attribute.nlri.prefix.mid'] = ProtoField.none("bgp_ls.path_attribute.nlri.prefix.mid", "Multi Topology Identifier TLV")
fields['bgp_ls.path_attribute.nlri.prefix.mid.id'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.prefix.mid.id", "Multi Topology ID")
fields['bgp_ls.path_attribute.nlri.prefix.ip_reachability'] = ProtoField.none("bgp_ls.path_attribute.nlri.prefix.ip_reachability", "IP Reachability Information TLV")
fields['bgp_ls.path_attribute.nlri.prefix.ip_reachability.prefix_length'] = ProtoField.uint8("bgp_ls.path_attribute.nlri.prefix.ip_reachability.prefix_length", "Reachability Prefix Length")
fields['bgp_ls.path_attribute.nlri.prefix.ip_reachability.prefix'] = ProtoField.ubytes("bgp_ls.path_attribute.nlri.prefix.ip_reachability.prefix", "Reachability Prefix")
-- srv6 descriptors
fields['bgp_ls.path_attribute.nlri.srv6'] = ProtoField.none("bgp_ls.path_attribute.prefix.srv6", "SRv6 Descriptors")
fields['bgp_ls.path_attribute.nlri.srv6.type'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.srv6.type", "Type")
fields['bgp_ls.path_attribute.nlri.srv6.length'] = ProtoField.uint16("bgp_ls.path_attribute.nlri.srv6.length", "Length")
fields['bgp_ls.path_attribute.nlri.srv6.sid_info'] = ProtoField.none("bgp_ls.path_attribute.nlri.srv6.sid_info", "SID Info TLV")
fields['bgp_ls.path_attribute.nlri.srv6.sid_info.sid'] = ProtoField.ipv6("bgp_ls.path_attribute.nlri.srv6.sid_info.sid", "SID")
-- =================================
-- bgp-ls attribute
fields['bgp_ls.path_attribute.attr'] = ProtoField.none("bgp_ls.path_attribute.attr", "Link State")
fields['bgp_ls.path_attribute.attr.type'] = ProtoField.uint16("bgp_ls.path_attribute.attr.type", "Type")
fields['bgp_ls.path_attribute.attr.length'] = ProtoField.uint16("bgp_ls.path_attribute.attr.length", "Length")
fields['bgp_ls.path_attribute.attr.metric'] = ProtoField.none("bgp_ls.path_attribute.attr.metric", "Metric TLV")
fields['bgp_ls.path_attribute.attr.metric.value'] = ProtoField.uint24("bgp_ls.path_attribute.attr.metric.value", "IGP Metric")
fields['bgp_ls.path_attribute.attr.node_msd'] = ProtoField.none("bgp_ls.path_attribute.attr.node_msd", "Node MSD TLV")
fields['bgp_ls.path_attribute.attr.node_msd.value'] = ProtoField.ubytes("bgp_ls.path_attribute.attr.node_msd.value", "Node MSD")
fields['bgp_ls.path_attribute.attr.link_msd'] = ProtoField.none("bgp_ls.path_attribute.attr.link_msd", "Link MSD TLV")
fields['bgp_ls.path_attribute.attr.link_msd.value'] = ProtoField.ubytes("bgp_ls.path_attribute.attr.link_msd.value", "Link MSD")
fields['bgp_ls.path_attribute.attr.prefix_metric'] = ProtoField.none("bgp_ls.path_attribute.attr.prefix_metric", "Prefix Metric TLV")
fields['bgp_ls.path_attribute.attr.prefix_metric.value'] = ProtoField.uint32("bgp_ls.path_attribute.attr.prefix_metric.value", "Prefix Metric")
fields['bgp_ls.path_attribute.attr.srv6_locator'] = ProtoField.none("bgp_ls.path_attribute.attr.srv6_locator", "SRv6 Locator TLV")
fields['bgp_ls.path_attribute.attr.srv6_locator.flags'] = ProtoField.uint8("bgp_ls.path_attribute.attr.srv6_locator.flags", "Flags")
fields['bgp_ls.path_attribute.attr.srv6_locator.algorithm'] = ProtoField.uint8("bgp_ls.path_attribute.attr.srv6_locator.algorithm", "Algorithm")
fields['bgp_ls.path_attribute.attr.srv6_locator.reserved'] = ProtoField.uint16("bgp_ls.path_attribute.attr.srv6_locator.reserved", "Reserved")
fields['bgp_ls.path_attribute.attr.srv6_locator.metric'] = ProtoField.uint32("bgp_ls.path_attribute.attr.srv6_locator.metric", "Metric")
fields['bgp_ls.path_attribute.attr.srv6_capabilities'] = ProtoField.none("bgp_ls.path_attribute.attr.srv6_capabilities", "SRv6 Capabilities TLV")
fields['bgp_ls.path_attribute.attr.srv6_capabilities.flags'] = ProtoField.uint16("bgp_ls.path_attribute.attr.srv6_capabilities.flags", "Flags")
fields['bgp_ls.path_attribute.attr.srv6_capabilities.reserved'] = ProtoField.uint16("bgp_ls.path_attribute.attr.srv6_capabilities.reserved", "Reserved")
fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior'] = ProtoField.none("bgp_ls.path_attribute.attr.srv6_endpoint_behavior", "SRv6 Endpoint_Behavior TLV")
fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior.endpoint_behavior'] = ProtoField.uint16("bgp_ls.path_attribute.attr.srv6_endpoint_behavior.endpoint_behavior", "Endpoint_Behavior")
fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior.flags'] = ProtoField.uint8("bgp_ls.path_attribute.attr.srv6_endpoint_behavior.flags", "Flags")
fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior.algorithm'] = ProtoField.uint8("bgp_ls.path_attribute.attr.srv6_endpoint_behavior.algorithm", "Algorithm")
fields['bgp_ls.path_attribute.attr.spf_status'] = ProtoField.none("bgp_ls.path_attribute.attr.spf_status", "SPF Status TLV")
fields['bgp_ls.path_attribute.attr.spf_status.value'] = ProtoField.uint8("bgp_ls.path_attribute.attr.spf_status.value", "SPF Status")
fields['bgp_ls.path_attribute.attr.seq_num'] = ProtoField.none("bgp_ls.path_attribute.attr.seq_num", "Sequence Number TLV")
fields['bgp_ls.path_attribute.attr.seq_num.value'] = ProtoField.uint64("bgp_ls.path_attribute.attr.seq_num.value", "Sequence Number")
-- =================================
-- origin
fields['bgp_ls.path_attribute.origin'] = ProtoField.uint8("bgp_ls.path_attribute.origin", "Origin")
-- =================================
-- as_path
fields['bgp_ls.path_attribute.as_path'] = ProtoField.uint16("bgp_ls.path_attribute.as_path", "AS_PATH")
-- =================================
-- multi_exit_disc
fields['bgp_ls.path_attribute.multi_exit_disc'] = ProtoField.uint32("bgp_ls.path_attribute.multi_exit_disc", "Multiple exit discriminator")
-- =================================
-- local_pref
fields['bgp_ls.path_attribute.local_pref'] = ProtoField.uint32("bgp_ls.path_attribute.local_pref", "Local preference")
-- =================================
-- originator_id
fields['bgp_ls.path_attribute.originator_id'] = ProtoField.ipv4("bgp_ls.path_attribute.originator_id", "Originator idntifier")
-- =================================
-- cluster_list
fields['bgp_ls.path_attribute.cluster_list'] = ProtoField.ubytes("bgp_ls.path_attribute.cluster_list", "Cluster List")
fields['bgp_ls.path_attribute.cluster_list.id'] = ProtoField.ipv4("bgp_ls.path_attribute.cluster_list.id", "Cluster id")

-- Register protocol fields
for _, v in pairs(fields) 
do 
    table.insert(proto_bgp_ls.fields, v)
end

nlri_type = {
    [1] = "Node NLRI",
    [2] = "LINK NLRI",
    [3] = "IPv4 prefix NLRI",
    [4] = "IPv6 prefix NLRI",
    [6] = "SRv6 NLRI",
}

path_attr_type = {
    [1] = "ORIGIN",
    [2] = "AS_PATH",
    [4] = "MULTI_EXIT_DISC",
    [5] = "LOCAL_PREF",
    [9] = "ORIGINATOR_ID",
    [10] = "CLUSTER_LIST",
    [14] = "MP_REACH_NLRI",
    [15] = "MP_UNREACH_NLRI",
    [29] = "BGP-LS Attribute",
}

-- 按位与
function And(num1,num2)
	local tmp1 = num1
	local tmp2 = num2
	local str = ""
	repeat
		local s1 = tmp1 % 2
		local s2 = tmp2 % 2
		if s1 == s2 then
			if s1 == 1 then
				str = "1"..str
			else
				str = "0"..str
			end
		else
			str = "0"..str
		end
		tmp1 = math.modf(tmp1/2)
		tmp2 = math.modf(tmp2/2)
	until(tmp1 == 0 and tmp2 == 0)
	return tonumber(str,2)
end

-- 轮询检查Continuation，返回Continuation的长度
function check_header_mark(reader)
    -- 解析BGP Update消息头部
    local marker = reader.read(BGP_MARKER_LEN):bytes():tohex()
    local Continuation_length = 0
    -- 遍历头，识别 Continuation
    if (marker ~= "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") then
        while (true)
        do
            local walk = reader.read(1):int()
            Continuation_length = Continuation_length + 1
            if(walk == 0xFF) then
                reader.back(1)
                marker = reader.read(BGP_MARKER_LEN):bytes():tohex()
                if(marker == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") then
                    break
                else
                    reader.back(BGP_MARKER_LEN - 1)
                end
            end
        end
    end
    reader.back(BGP_MARKER_LEN)
    return Continuation_length
end

-- 检查UPDATE消息的地址族address family，找到则返回true，否则返回false
function check_update_message_af(reader, pafi, psafi)
    local Continuation_length = check_header_mark(reader)
    -- 解析BGP Update消息头部
    local marker = reader.read(BGP_MARKER_LEN):bytes()
    local total_len = reader.read(2):uint()
    local message_type = reader.read(1):uint()
    -- 处理update包
    if (message_type == 2) then
        reader.skip(4)
        while ( reader.not_tail() )
        do
            local flags = reader.read(1):uint()
            local type_dode = reader.read(1):uint()
            local path_attr_length
            if (And(flags, 0X10) == 0X10) then
                path_attr_length = reader.read(2):uint()
            else
                path_attr_length = reader.read(1):uint()
            end
            -- 解析MP_[UN]REACH_NLRI
            if ((type_dode == 14) or (type_dode == 15)) then
                local afi = reader.read(2):uint()
                local safi = reader.read(1):uint()
                reader.skip(path_attr_length - 3)
                --检查safi
                if ( (afi == pafi) and (safi == psafi) ) then
                    reader.reset()
                    return true
                else
                    reader.reset()
                    return false
                end
            else
                reader.skip(path_attr_length)
            end
        end
    end
    reader.reset()
    return false
end


-- 解析nlri
function dissect_nlri(reader, tree)
    print("---- NLRI dissect start ----")

    local _nlri_type_range = reader.read(2)
    local _nlri_type = _nlri_type_range:uint()
    local _nlri_length_range = reader.read(2)
    local _nlri_length = _nlri_length_range:uint()
    local nlri_offset = reader.offset()

    tree:add(fields['bgp_ls.path_attribute.nlri'], reader.only_read(nlri_offset - TYPE_AND_LENGTH_LEN, _nlri_length + TYPE_AND_LENGTH_LEN))
    tree:add(fields['bgp_ls.path_attribute.nlri_type'], _nlri_type_range):append_text(" (" .. nlri_type[_nlri_type] .. ")")
    tree:add(fields['bgp_ls.path_attribute.nlri_length'], _nlri_length_range)

    local _protocol_id_range = reader.read(1)
    local _protocol_id = _protocol_id_range:uint()
    local _identifier_range = reader.read(8)
    local _identifier = _identifier_range:uint64()
    local _nlri_tlv_range = reader.only_read(nlri_offset, _nlri_length)
    tree:add(fields['bgp_ls.path_attribute.nlri'], _nlri_tlv_range)
    tree:add(fields['bgp_ls.path_attribute.nlri.protocol_id'], _protocol_id_range)
    tree:add(fields['bgp_ls.path_attribute.nlri.identifier'], _identifier_range)
    while( reader.not_tlv_tail(nlri_offset, _nlri_length) )
    do
        local _desc_type_range = reader.read(2)
        local _desc_type = _desc_type_range:uint()
        local _desc_length_range = reader.read(2)
        local _desc_length = _desc_length_range:uint()
        local desc_offset = reader.offset()
        local _desc_tlv_range = reader.only_read(desc_offset - TYPE_AND_LENGTH_LEN, _desc_length + TYPE_AND_LENGTH_LEN)
        -- node
        if ((_desc_type == 256) or (_desc_type == 257)) then
            tree:add(fields['bgp_ls.path_attribute.nlri.node'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            while ( reader.not_tlv_tail(desc_offset, _desc_length) )
            do
                local _subtlv_type_range = reader.read(2)
                local _subtlv_type = _subtlv_type_range:uint()
                local _subtlv_length_range = reader.read(2)
                local _subtlv_length = _subtlv_length_range:uint()
                local sub_offset = reader.offset()
                local _desc_sub_tlv_range = reader.only_read(sub_offset - TYPE_AND_LENGTH_LEN, _subtlv_length + TYPE_AND_LENGTH_LEN)
                if (_subtlv_type == 512) then
                    local _as_id_range = reader.read(_subtlv_length)
                    local _as_id = _as_id_range:uint()
                    tree:add(fields['bgp_ls.path_attribute.nlri.node.as'], _desc_sub_tlv_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.type'], _subtlv_type_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.length'], _subtlv_length_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.node.as.id'], _as_id_range)
                elseif (_subtlv_type == 513) then
                    local _bgp_ls_id_range = reader.read(_subtlv_length)
                    local _bgp_ls_id = _bgp_ls_id_range:uint()
                    tree:add(fields['bgp_ls.path_attribute.nlri.node.bgp_ls'], _desc_sub_tlv_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.type'], _subtlv_type_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.length'], _subtlv_length_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.node.bgp_ls.id'], _bgp_ls_id_range)
                elseif (_subtlv_type == 515) then
                    local _igp_id_range = reader.read(_subtlv_length)
                    local _igp_id = _igp_id_range:bytes()
                    tree:add(fields['bgp_ls.path_attribute.nlri.node.igp'], _desc_sub_tlv_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.type'], _subtlv_type_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.length'], _subtlv_length_range)
                    tree:add(fields['bgp_ls.path_attribute.nlri.node.igp.id'], _igp_id_range)
                end
            end
        -- link
        elseif (_desc_type == 258) then
            local _local_id_range = reader.read(4)
            local _local_id = _local_id_range:uint()
            local _remote_id_range = reader.read(4)
            local _remote_id = _remote_id_range:uint()
            tree:add(fields['bgp_ls.path_attribute.nlri.link.local_remote_id'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.local_remote_id.local_id'], _local_id_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.local_remote_id.remote_id'], _remote_id_range)
        elseif (_desc_type == 259) then
            local _ipv4_interface_address_range = reader.read(_desc_length)
            local _ipv4_interface_address = _ipv4_interface_address_range:ipv4()
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv4_interface_address'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv4_interface_address.ipv4'], _ipv4_interface_address_range)
        elseif (_desc_type == 260) then
            local _ipv4_neighbor_address_range = reader.read(_desc_length)
            local _ipv4_neighbor_address = _ipv4_neighbor_address_range:ipv4()
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv4_neighbor_address'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv4_neighbor_address.ipv4'], _ipv4_neighbor_address_range)
        elseif (_desc_type == 261) then
            local _ipv6_interface_address_range = reader.read(_desc_length)
            local _ipv6_interface_address = _ipv6_interface_address_range:ipv6()
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv6_interface_address'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv6_interface_address.ipv6'], _ipv6_interface_address_range)
        elseif (_desc_type == 262) then
            local _ipv6_neighbor_address_range = reader.read(_desc_length)
            local _ipv6_neighbor_address = _ipv6_neighbor_address_range:ipv6()
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv6_neighbor_address'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.ipv6_neighbor_address.ipv6'], _ipv6_neighbor_address_range)
        ---- ADDRESS FAMILY
        elseif (_desc_type == 266) then
            local _addr_family_range = reader.read(_desc_length)
            local _addr_family = _addr_family_range:uint()
            tree:add(fields['bgp_ls.path_attribute.nlri.link.addr_family'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.link.addr_family.value'], _addr_family_range)
        -- prefix
        elseif (_desc_type == 263) then
            local _mid_range = reader.read(_desc_length)
            local _mid_address = _mid_range:uint()
            tree:add(fields['bgp_ls.path_attribute.nlri.prefix.mid'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.prefix.mid.id'], _mid_range)
        elseif (_desc_type == 265) then
            local _ip_reach_length_range = reader.read(1)
            local _ip_reach_length = _ip_reach_length_range:uint()
            local _ip_reach_range = reader.read( _desc_length - 1 )
            local _ip_reach = _ip_reach_range:bytes()
            tree:add(fields['bgp_ls.path_attribute.nlri.prefix.ip_reachability'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.prefix.ip_reachability.prefix_length'], _ip_reach_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.prefix.ip_reachability.prefix'], _ip_reach_range)
        -- srv6
        elseif (_desc_type == 518) then
            local _sid_info_range = reader.read(_desc_length)
            local _sid_info = _sid_info_range:ipv6()
            tree:add(fields['bgp_ls.path_attribute.nlri.srv6.sid_info'], _desc_tlv_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.type'], _desc_type_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.length'], _desc_length_range)
            tree:add(fields['bgp_ls.path_attribute.nlri.srv6.sid_info.sid'], _sid_info_range)
        else
            print("---- WARN: No defind nlri tlv ----")
            reader.skip(_desc_length)
        end
    end
    print("---- NLRI dissect end ----")
end

-- 解析attr
function dissect_attr(reader, tree)
    local _attr_type_range = reader.read(2)
    local _attr_type = _attr_type_range:uint()
    local _attr_length_range = reader.read(2)
    local _attr_length = _attr_length_range:uint()
    local _attr_offset = reader.offset()
    local _attr_range = reader.only_read(_attr_offset - TYPE_AND_LENGTH_LEN, _attr_length + TYPE_AND_LENGTH_LEN)
    -- 解析attr tlv
    if (_attr_type == 1095) then
        local _metric_range = reader.read(_attr_length)
        local _metric = _metric_range:uint()
        tree:add(fields['bgp_ls.path_attribute.attr.metric'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.metric.value'], _metric_range)
    elseif (_attr_type == 266) then
        local _node_msd_range = reader.read(_attr_length)
        local _node_msd = _node_msd_range:bytes()
        tree:add(fields['bgp_ls.path_attribute.attr.node_msd'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.node_msd.value'], _node_msd_range)
    elseif (_attr_type == 267) then
        local _link_msd_range = reader.read(_attr_length)
        local _link_msd = _link_msd_range:bytes()
        tree:add(fields['bgp_ls.path_attribute.attr.link_msd'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.link_msd.value'], _link_msd_range)
    elseif (_attr_type == 1155) then
        local _prefix_metric_range = reader.read(_attr_length)
        local _prefix_metric = _prefix_metric_range:uint()
        tree:add(fields['bgp_ls.path_attribute.attr.prefix_metric'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.prefix_metric.value'], _prefix_metric_range)
    elseif (_attr_type == 1162) then
        local _srv6_locator_flags_range = reader.read(1)
        local _srv6_locator_algorithm_range = reader.read(1)
        local _srv6_locator_reserved_range = reader.read(2)
        local _srv6_locator_metric_range = reader.read(4)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_locator'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_locator.flags'], _srv6_locator_flags_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_locator.algorithm'], _srv6_locator_algorithm_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_locator.reserved'], _srv6_locator_reserved_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_locator.metric'], _srv6_locator_metric_range)
    elseif (_attr_type == 1038) then
        local _srv6_capabilities_flags_range = reader.read(2)
        local _srv6_capabilities_reserved_range = reader.read(2)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_capabilities'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_capabilities.flags'], _srv6_capabilities_flags_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_capabilities.reserved'], _srv6_capabilities_reserved_range)
    elseif (_attr_type == 1250) then
        local _srv6_endpoint_behavior_func_range = reader.read(2)
        local _srv6_endpoint_behavior_flags_range = reader.read(1)
        local _srv6_endpoint_behavior_algorithm_range = reader.read(1)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior.endpoint_behavior'], _srv6_endpoint_behavior_func_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior.flags'], _srv6_endpoint_behavior_flags_range)
        tree:add(fields['bgp_ls.path_attribute.attr.srv6_endpoint_behavior.algorithm'], _srv6_endpoint_behavior_algorithm_range)
    -- 解析Sequence Number
    elseif (_attr_type == 1181) then
        local _seq_num_range = reader.read(_attr_length)
        local _seq_num = _seq_num_range:uint64()
        tree:add(fields['bgp_ls.path_attribute.attr.seq_num'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.seq_num.value'], _seq_num_range)
    -- 解析SPF Status
    elseif (_attr_type == 1184) then
        local _spf_status_range = reader.read(_attr_length)
        local _spf_status = _spf_status_range:uint()
        tree:add(fields['bgp_ls.path_attribute.attr.spf_status'], _attr_range)
        tree:add(fields['bgp_ls.path_attribute.attr.type'], _attr_type_range)
        tree:add(fields['bgp_ls.path_attribute.attr.length'], _attr_length_range)
        tree:add(fields['bgp_ls.path_attribute.attr.spf_status.value'], _spf_status_range)
    else
        print("---- WARN: No defind bgp-ls attr ----")
        reader.skip(_attr_length)
    end
end


-- 解析BGP ls包
function dissect_bgp_ls(reader, pinfo, tree)
    print("BGP-LS Protocol dissector start")

    --遍历接收的数据包，处理多个BGP UPDATE Message
    while( reader.not_tail() )
    do
        -- 遍历头，识别 Continuation
        local continuation_length = check_header_mark(reader)
        if (continuation_length > 0) then
            print("-- BGP Continuation --")
            local continuation_offset = reader.offset() - continuation_length
            _continuation_range = reader.only_read(continuation_offset, continuation_length)
            tree:add(fields['bgp_ls.continuation'], _continuation_range)
        end
        -- 解析BGP Update消息头部
        local _marker_range = reader.read(BGP_MARKER_LEN)
        local _marker = _marker_range:bytes()
        print(_marker)
        local _total_len_range = reader.read(2)
        local _total_len = _total_len_range:uint()
        local _message_type_range = reader.read(1)
        local _message_type = _message_type_range:uint()

        tree:add(fields['bgp_ls.marker'], _marker_range)
        tree:add(fields['bgp_ls.length'], _total_len_range)
        tree:add(fields['bgp_ls.type'], _message_type_range)
        
        -- 处理update包
        if (_message_type == 2) then
            local _witdrawn_routes_length_range = reader.read(2)
            local _witdrawn_routes_length = _witdrawn_routes_length_range:uint()

            local _path_attributes_length_range = reader.read(2)
            local _path_attributes_length = _path_attributes_length_range:uint()
            local path_attributes_offset = reader.offset()

            tree:add(fields['bgp_ls.witdrawn_routes.length'], _witdrawn_routes_length_range)
            tree:add(fields['bgp_ls.path_attributes.length'], _path_attributes_length_range)
            -- 解析 path_attributes
            while ( reader.not_tlv_tail(path_attributes_offset, _path_attributes_length) and reader.not_tail() )
            do
                local _flags_range = reader.read(1)
                local _flags = _flags_range:uint()
                local _type_code_range = reader.read(1)
                local _type_code = _type_code_range:uint()

                tree:add(fields['bgp_ls.path_attribute.flags'], _flags_range)
                tree:add(fields['bgp_ls.path_attribute.type_code'], _type_code_range):append_text(" (" .. path_attr_type[_type_code] .. ")")

                local _length_range
                -- 判断拓展长度flag，确定length字段的字节数
                if (And(_flags, 0X10) == 0X10) then
                    _length_range = reader.read(2)
                    tree:add(fields['bgp_ls.path_attribute.ext_length'], _length_range)
                else
                    _length_range = reader.read(1)
                    tree:add(fields['bgp_ls.path_attribute.length'], _length_range)
                end
                local _length = _length_range:uint()
                local path_attr_offset = reader.offset()

                if (_length > 0) then
                    -- 解析 origin
                    if(_type_code == 1) then
                        print("-- ORIGIN dissect start --")
                        local _origin_range = reader.read(_length)
                        local _origin = _origin_range:uint()
                        tree:add(fields['bgp_ls.path_attribute.origin'], _origin_range)
                    -- 解析 as_path
                    elseif(_type_code == 2) then
                        print("-- AS_PATH dissect start --")
                        local _as_path_range = reader.read(_length)
                        local _as_path = _as_path_range:uint()
                        tree:add(fields['bgp_ls.path_attribute.as_path'], _as_path_range) 
                    -- 解析 multi_exit_disc
                    elseif(_type_code == 4) then
                        print("-- Multi Exit Disc dissect start --")
                        local _multi_exit_disc_range = reader.read(_length)
                        local _multi_exit_disc = _multi_exit_disc_range:uint()
                        tree:add(fields['bgp_ls.path_attribute.multi_exit_disc'], _multi_exit_disc_range) 
                    -- 解析 local_pref
                    elseif (_type_code == 5) then
                        print("-- Local Pref dissect start --")
                        local _local_pref_range = reader.read(_length)
                        local _local_pref = _local_pref_range:uint()
                        tree:add(fields['bgp_ls.path_attribute.local_pref'], _local_pref_range)
                    -- 解析 originator_id
                    elseif (_type_code == 9) then
                        print("-- Originator ID dissect start --")
                        local _originator_id_range = reader.read(_length)
                        local _originator_id = _originator_id_range:ipv4()
                        tree:add(fields['bgp_ls.path_attribute.originator_id'], _originator_id_range)
                    -- 解析 cluster_list
                    elseif (_type_code == 10) then
                        print("-- Cluster List dissect start --")
                        local _cluster_list_range = reader.only_read(path_attr_offset, _length)
                        local _cluster_list = _cluster_list_range:bytes()
                        tree:add(fields['bgp_ls.path_attribute.cluster_list'], _cluster_list_range)
                        while ( reader.not_tlv_tail(path_attr_offset, _length) ) 
                        do
                            local _cluster_list_id_range = reader.read(4)
                            local _cluster_list_id = _cluster_list_id_range:ipv4()
                            tree:add(fields['bgp_ls.path_attribute.cluster_list.id'], _cluster_list_id_range)
                        end
                    -- 解析MP_REACH_NLRI
                    elseif (_type_code == 14) then
                        print("-- MP_REACH_NLRI dissect start --")
                        local _reach_afi_range = reader.read(2)
                        local _reach_afi = _reach_afi_range:uint()
                        local _reach_safi_range = reader.read(1)
                        local _reach_safi = _reach_safi_range:uint()
                        local _reach_next_hop_range = reader.read(17)
                        local _reach_next_hop = _reach_next_hop_range:bytes()
                        local _reach_snpa_range = reader.read(1)
                        local _reach_snpa = _reach_snpa_range:uint()
                        tree:add(fields['bgp_ls.path_attribute.afi'], _reach_afi_range)
                        tree:add(fields['bgp_ls.path_attribute.safi'], _reach_safi_range)
                        tree:add(fields['bgp_ls.path_attribute.mp_reach_nlri.next_hop'], _reach_next_hop_range)
                        tree:add(fields['bgp_ls.path_attribute.mp_reach_nlri.nbr_snpa'], _reach_snpa_range)
                        -- 解析nlri
                        while( reader.not_tlv_tail(path_attr_offset, _length) ) 
                        do
                            --防止出现tvb溢出
                            if( reader.is_overflow(13) ) then
                                reader.skip(reader.remaining_length())
                                print("---- WARN: TVB overflow ----")
                                break
                            end
                            dissect_nlri(reader, tree)
                        end
                    -- 解析MP_UNREACH_NLRI
                    elseif (_type_code == 15) then
                        print("-- MP_UNREACH_NLRI dissect start --")
                        local _unreach_afi_range = reader.read(2)
                        local _unreach_afi = _unreach_afi_range:uint()
                        local _unreach_safi_range = reader.read(1)
                        local _unreach_safi = _unreach_safi_range:uint()
                        tree:add(fields['bgp_ls.path_attribute.afi'], _unreach_afi_range)
                        tree:add(fields['bgp_ls.path_attribute.safi'], _unreach_safi_range)
                        -- 解析nlri
                        while( reader.not_tlv_tail(path_attr_offset, _length) ) 
                        do
                            --防止出现tvb溢出
                            if( reader.is_overflow(13) ) then
                                reader.skip(reader.remaining_length())
                                print("---- WARN: TVB overflow ----")
                                break
                            end
                            dissect_nlri(reader, tree)
                        end
                    -- 解析BGP-LS Attribute
                    elseif(_type_code == 29) then
                        print("-- BGP-LS Attribute dissect start --")
                        while( reader.not_tlv_tail(path_attr_offset, _length) ) 
                        do
                            --防止出现tvb溢出
                            if( reader.is_overflow(4) ) then
                                reader.skip(reader.remaining_length())
                                print("---- WARN: TVB overflow ----")
                                break
                            end
                            dissect_attr(reader, tree)
                        end
                        print("-- BGP-LS Attribute dissect end --")
                    else
                        print("-- WARN: No defind PATH Attribute --")
                        reader.skip(_length)
                    end
                end
            end
            print("BGP UPDTATE Message dissect end")
        else
            print("WARN: NOT BGP UPDTATE Message")
        end
    end
    print("TVB dissect end")
end

proto_bgp_ls.fields.bgp_ls_update = ProtoField.none("bgp_ls.update", "UPDATE Message")

-- test BGP
function dissect_test(tvbuf, pinfo, tree)
    --local tvb_length = tvbuf:len()
    tree:add(proto_bgp_ls.fields.bgp_ls_update, tvbuf())
end

-- =================================================
--     注册BGP LS协议的解析器Dissector
-- =================================================
function proto_bgp_ls.dissector(tvbuf, pinfo, tree)
    local bgp_ls_tree = tree:add(proto_bgp_ls, tvbuf())

    -- 创建 tvbuff 读取对象
    local reader = readbuf.new(tvbuf)

    -- 检查是bgp-ls-spf协议的update消息时，用自己编写的解析器
    local check_af = check_update_message_af(reader, AFI_BGP_LS, SAFI_BGP_LS_SPF)
    print(check_af)
    if check_af then
        dissect_bgp_ls(reader, pinfo, bgp_ls_tree)
        --dissect_test(tvbuf, pinfo, bgp_ls_tree)
    else
        -- 获取wireshark BGP协议解析器
        local bgp_dissector = Dissector.get("bgp")
        -- 回调wireshark自带的bgp解析器
        bgp_dissector:call(tvbuf, pinfo, bgp_ls_tree)
    end
end

-- =================================================
--     加载BGP LS协议,BGP协议默认为179端口
-- =================================================
DissectorTable.get("tcp.port"):add(179, proto_bgp_ls)


--[[
-- 获取Dissector和DissectorTable 列表
print("Dissector list:")
local diss = Dissector.list()
for _,name in ipairs(diss) do
    print(name)
end
-- bgp, bgp.pdu

print("DissectorTable list:")
local dt = DissectorTable.list()
for _,name in ipairs(dt) do
    print(name)
end
]]