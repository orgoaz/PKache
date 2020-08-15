/* -*- P4_16 -*- */

/*
 * P4 Decision Tree
 */

#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
#define MAX_ENTRIES 16
#define CONF_SIZE 1
#define LOG_REGISTER_SIZE 256
#define SCN_KEY 1

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
const bit<8>  P4GET_VAL  = 0x46; // 'F'
const bit<8>  P4UPDATE_LOG  = 0x55; // 'U'
const int<8>  INT_FACTOR  = 100;

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
    register<bit<80>>(MAX_ENTRIES) r_cache;
    register<bit<8>>(CONF_SIZE) r_conf;
    register<bit<16>>(LOG_REGISTER_SIZE) r_log;

    action send_back() {
       bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action get_hyperbolic_cache_pr(in bit<8> number_of_access, in bit<8> period, out bit<16> pr){
        bit<16> number_of_access_log;
        bit<16> period_log;

         r_log.read(number_of_access_log, (bit<32>)number_of_access);
         r_log.read(period_log, (bit<32>)period);

         pr = number_of_access_log - period_log;
    }

     action operation_search() {
        bit<8> requested_key = hdr.p4kway.k;
        bit<32> h = (bit<32>) (requested_key % MAX_ENTRIES);
        bit<80> element;
        bit<8> scn;
        r_conf.read(scn, SCN_KEY);
        scn = scn + 1;

        r_cache.read(element, h);
        bit<40> element1 = element[79:40];
        bit<40> element2 = element[39:0];

        bit<16> pr_1;
        bit<16> pr_2;
        // Conditional execution in actions is not supported on this target
        get_hyperbolic_cache_pr(element1[15:8], (scn - element1[7:0]), pr_1);
        get_hyperbolic_cache_pr(element2[15:8], (scn - element2[7:0]), pr_2);

        if (element1[39:32] == requested_key){
            hdr.p4kway.v = element1[31:16];
            element1[15:8] = element1[15:8] + 1;
            hdr.p4kway.cache = 1;
        }
        else if (element2[39:32] == requested_key){
            hdr.p4kway.v = element2[31:16];
            element2[15:8] = element2[15:8] + 1;
            hdr.p4kway.cache = 1;
        }
        else{
              hdr.p4kway.cache = 0;
              bit<16> loaded_val = load(requested_key);
              // bit<16> pr_1;
              // bit<16> pr_2;
              // Conditional execution in actions is not supported on this target
              // get_hyperbolic_cache_pr(element1[15:8], (scn - element1[7:0]), pr_1);
              // get_hyperbolic_cache_pr(element2[15:8], (scn - element2[7:0]), pr_2);

              if (pr_1 >= pr_2){
                 element2[39:32] = requested_key;
                 element2[31:16] = loaded_val;
                 element2[15:8] = 1;
                 element2[7:0] = scn;
              }
              else{
                 element1[39:32] = requested_key;
                 element1[31:16] = loaded_val;
                 element1[15:8] = 1;
                 element1[7:0] = scn;
              }
              // TODO: Add shift to prevent overflow
              hdr.p4kway.v = loaded_val;
        }

        element = element1 ++ element2;
        r_cache.write(h, element);
        r_conf.write(SCN_KEY, scn);

        send_back();
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    action operation_update_log() {
        r_log.write((bit<32>)hdr.p4kway.k, hdr.p4kway.v);
    }

    table fetch_value_by_key {
        key = {
            hdr.p4kway.type        : exact;
        }
        actions = {
		operation_search;
		operation_update_log;
		operation_drop;
        }
        const default_action = operation_drop();
        const entries = {
            P4GET_VAL: operation_search();
            P4UPDATE_LOG: operation_update_log();
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
