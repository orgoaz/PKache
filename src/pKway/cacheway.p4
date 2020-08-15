/* -*- P4_16 -*- */

/*
 * P4 Decision Tree
 */

#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
#define MAX_ENTRIES 16

/*
 * Define the headers the program will recognize
 */

/*
 * Standard Ethernet header 
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * This is a custom protocol header for the Decision Tree classifier. We'll use 
 * etherType 0x1234 for it (see parser)
 */
const bit<16> P4KWAY_ETYPE = 0x1234;
const bit<8>  P4KWAY_P     = 0x50;   // 'P'
const bit<8>  P4KWAY_4     = 0x34;   // '4'
const bit<8>  P4KWAY_VER   = 0x01;   // v0.1
const bit<8>  P4GET_VAL_LFU  = 0x46;   // 'F'
const bit<8>  P4GET_VAL_LRU  = 0x52;   // 'R'

header p4kway_t {
   bit<8>  p;
   bit<8>  four;
   bit<8>  ver;
   bit<8>  type;
   bit<8> k;
   bit<16> v;
   bit<8> cache;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    p4kway_t     p4kway;
}


/*
 * All metadata, globally used in the program, also  needs to be assembled 
 * into a single struct. As in the case of the headers, we only need to 
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
 
struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {    
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            P4KWAY_ETYPE : check_p4kway;
            default      : accept;
        }
    }
    
    state check_p4kway{
        transition select(packet.lookahead<p4kway_t>().p,
        packet.lookahead<p4kway_t>().four,
        packet.lookahead<p4kway_t>().ver) {
            (P4KWAY_P, P4KWAY_4, P4KWAY_VER) : parse_p4kway;
            default                          : accept;
        }
    }
    
    state parse_p4kway {
        packet.extract(hdr.p4kway);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

bit<16> load(in bit<8> k) {
    return (bit<16>)(k * k);
}

bit<8> max(in bit<8> scn1, in bit<8> scn2) {
    if (scn1 >= scn2){
        return scn1;
    }
    else{
        return scn2;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<64>>(MAX_ENTRIES) r_cache;

    action send_back() {
       bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
     action operation_search_lfu() {
        bit<8> requested_key = hdr.p4kway.k;
        bit<32> h = (bit<32>) (requested_key % MAX_ENTRIES);
        bit<64> element;

        r_cache.read(element, h);
        bit<32> element1 = element[63:32];
        bit<32> element2 = element[31:0];

        if (element1[31:24] == requested_key){
            hdr.p4kway.v = element1[23:8];
            element1[7:0] = element1[7:0] + 1;
            hdr.p4kway.cache = 1;
        }
        else if (element2[31:24] == requested_key){
            hdr.p4kway.v = element2[23:8];
            element2[7:0] = element2[7:0] + 1;
            hdr.p4kway.cache = 1;
        }
        else{
              hdr.p4kway.cache = 0;
              bit<16> loaded_val = load(requested_key);
              if (element1[7:0] > element2[7:0]){
                 element2[31:24] = requested_key;
                 element2[23:8] = loaded_val;
                 element2[7:0] = 1;

                 if (element1[7:0] > 0){
                    element1[7:0] = element1[7:0] - 1;
                 }
              }
              else{
                 element1[31:24] = requested_key;
                 element1[23:8] = loaded_val;
                 element1[7:0] = 1;

                 if (element2[7:0] > 0){
                    element2[7:0] = element2[7:0] - 1;
                 }
              }
              // TODO: Add shift to prevent overflow
              hdr.p4kway.v = loaded_val;
        }

        element = element1 ++ element2;
        r_cache.write(h, element);

        send_back();
    }

     action operation_search_lru() {
        bit<8> requested_key = hdr.p4kway.k;
        bit<32> h = (bit<32>) (requested_key % MAX_ENTRIES);
        bit<64> element;

        r_cache.read(element, h);
        bit<32> element1 = element[63:32];
        bit<32> element2 = element[31:0];

        bit<8> new_scn = max(element1[7:0], element2[7:0]) + 1;

        if (element1[31:24] == requested_key){
            hdr.p4kway.v = element1[23:8];
            element1[7:0] = new_scn;
            hdr.p4kway.cache = 1;
        }
        else if (element2[31:24] == requested_key){
            hdr.p4kway.v = element2[23:8];
            element2[7:0] = new_scn;
            hdr.p4kway.cache = 1;
        }
        else{
              hdr.p4kway.cache = 0;
              bit<16> loaded_val = load(requested_key);
              if (element1[7:0] > element2[7:0]){
                 element2[31:24] = requested_key;
                 element2[23:8] = loaded_val;
                 element2[7:0] = new_scn;
              }
              else{
                 element1[31:24] = requested_key;
                 element1[23:8] = loaded_val;
                 element1[7:0] = new_scn;
              }
              // TODO: Add shift to prevent overflow
              hdr.p4kway.v = loaded_val;
        }

        element = element1 ++ element2;
        r_cache.write(h, element);

        send_back();
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    table fetch_value_by_key {
        key = {
            hdr.p4kway.type        : exact;
        }
        actions = {
		operation_search_lfu;
		operation_search_lru;
		operation_drop;
        }
        const default_action = operation_drop();
        const entries = {
            P4GET_VAL_LFU: operation_search_lfu();
            P4GET_VAL_LRU: operation_search_lru();
        }
    }

    apply {
        if (hdr.p4kway.isValid()) {
            fetch_value_by_key.apply();
        } else {
            operation_drop();
        }
    }
}

/************************************************************
 ****************  REGISTER DEFINITIONS   *******************
 ************************************************************/



/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4kway);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
