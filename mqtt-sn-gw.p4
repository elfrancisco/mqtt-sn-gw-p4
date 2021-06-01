/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> MQTTSN_ADVERTISE              = 0x00;
const bit<8> MQTTSN_SEARCHGW               = 0x01
const bit<8> MQTTSN_GWINFO                 = 0x02
const bit<8> MQTTSN_RESERVED_03            = 0x03
const bit<8> MQTTSN_CONNECT                = 0x04
const bit<8> MQTTSN_CONNACK                = 0x05
const bit<8> MQTTSN_WILLTOPICREQ           = 0x06
const bit<8> MQTTSN_WILLTOPIC              = 0x07
const bit<8> MQTTSN_WILLMSGREQ             = 0x08
const bit<8> MQTTSN_WILLMSG                = 0x09
const bit<8> MQTTSN_REGISTER               = 0x0A
const bit<8> MQTTSN_REGACK                 = 0x0B
const bit<8> MQTTSN_PUBLISH                = 0x0C
const bit<8> MQTTSN_PUBACK                 = 0x0D
const bit<8> MQTTSN_PUBCOMP                = 0x0E
const bit<8> MQTTSN_PUBREC                 = 0x0F
const bit<8> MQTTSN_PUBREL                 = 0x10
const bit<8> MQTTSN_RESERVED_11            = 0x11
const bit<8> MQTTSN_SUBSCRIBE              = 0x12
const bit<8> MQTTSN_SUBACK                 = 0x13
const bit<8> MQTTSN_UNSUBSCRIBE            = 0x14
const bit<8> MQTTSN_UNSUBACK               = 0x15
const bit<8> MQTTSN_PINGREQ                = 0x16
const bit<8> MQTTSN_PINGRESP               = 0x17
const bit<8> MQTTSN_DISCONNECT             = 0x18
const bit<8> MQTTSN_RESERVED_19            = 0x19
const bit<8> MQTTSN_WILLTOPICUPD           = 0x1A
const bit<8> MQTTSN_WILLTOPICRESP          = 0x1B
const bit<8> MQTTSN_WILLMSGUPD             = 0x1C
const bit<8> MQTTSN_WILLMSGRESP            = 0x1D
const bit<8> MQTTSN_ENCAPSULATED_MSG       = 0xFE
const bit<8> MQTT_CONNECT                  = 0x10
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> lenght;
    bit<16> checksum;
}

header mqtt_control_header_t {
    bit<8> ctrl_h; //Control Header
}    
    bit<32> plenght; //Packet Lenght 1-4 bytes
    varbit<256> vlh; //Variable Lenght Header


header mqttsn_lenght_h_t {
    bit<8> lenght; 
}

header mqttsn_lenght_long_h_t {
    bit<16> lenght_long; 
}

header mqttsn_type_t {
    bit<8> type; 
}

header mqttsn_connect_t {
    bit<1>  f_DUP;
    bit<2>  f_QoS;
    bit<1>  f_retain;
    bit<1>  f_will;
    bit<1>  f_clean_session;
    bit<2>  f_topicID_type;
    bit<8>  protocolID;
    bit<16> keepalive;
}

header mqttsn_register_t {
    bit<16> topicID;
    bit<16> msgID;  
}

header mqttsn_publish_t {
    bit<1>  f_DUP;
    bit<2>  f_QoS;
    bit<1>  f_retain;
    bit<1>  f_will;
    bit<1>  f_clean_session;
    bit<2>  f_topicID_type;
    bit<16> topicID;
    bit<16> msgID;
}



struct metadata {
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    udp_t                   udp;
    mqtt_t                  mqtt;
    mqttsn_lenght_h_t       mqttsn_lenght_h;
    mqttsn_lenght_long_h_t  mqttsn_lenght_long_h;
    mqttsn_type_t           mqttsn_type;
    mqttsn_connect_t        mqttsn_connect;
    mqttsn_register_t       mqttsn_register;
    mqttsn_publish_t        mqttsn_publish;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_mqttsn_lenght_h;
    }

    state parse_mqttsn_lenght_h {
        packet.extract(hdr.mqttsn_lenght_h);
        transition select(hdr.mqttsn_lenght_h.lenght) {
            1: parse_mqttsn_lenght_long_h;
            default: parse_mqttsn_type;
        }   
    }

    state parse_mqttsn_lenght_long_h {
        packet.extract(hdr.mqttsn_lenght_long_h);
        transition parse_mqttsn_type; 
        }   
    
    state parse_mqttsn_type {
        packet.extract(hdr.mqttsn_type);
        transition select(hdr.mqttsn_type.type) {
            MQTTSN_CONNECT:     parse_mqttsn_connect;
            MQTTSN_REGISTER:    parse_mqttsn_register;
            MQTTSN_PUBLISH:     parse_mqttsn_publish;
            MQTTSN_DISCONNECT:  accept;
            default: accept;
        }   
    }

    state parse_mqttsn_connect {
        packet.extract(hdr.mqttsn_connect);
        transition accept;   
    }

    state parse_mqttsn_connect {
        packet.extract(hdr.mqttsn_connect);
        transition accept;   
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_mqtt_control_header {
        packet.extract(hdr.mqtt_control_header);
        transition select(mqtt_control_header) {
            TYPE_IPV4:  parse_ipv4;
            default:    accept;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.mqtt);
    }
}    
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop(standard_metadata);
    }
        
    action mqttsn_ingress(bit<16> dst_id) {
        hdr.mqtt_header.setValid();
        hdr.mqtt.type = dst_id;
        hdr.mqtt.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_MYTUNNEL;
        ingressTunnelCounter.count((bit<32>) hdr.myTunnel.dst_id);
    }

    action myTunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action myTunnel_egress(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = hdr.myTunnel.proto_id;
        hdr.myTunnel.setInvalid();
        egressTunnelCounter.count((bit<32>) hdr.myTunnel.dst_id);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            myTunnel_ingress;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table myTunnel_exact {
        key = {
            hdr.myTunnel.dst_id: exact;
        }
        actions = {
            myTunnel_forward;
            myTunnel_egress;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.myTunnel.isValid()) {
            // Process only non-tunneled IPv4 packets.
            ipv4_lpm.apply();
        }

        if (hdr.myTunnel.isValid()) {
            // Process all tunneled packets.
            myTunnel_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);SN****************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.mqtt);
        packet.emit(hdr.mqttsn);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
