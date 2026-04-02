/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the open-source project hosted at:
 *     https://github.com/colocohen/dnssec-server
 */

function invertObject(obj) {
  var out = {};
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      out[obj[key]] = key;
    }
  }
  return out;
}

// Resource Record (RR) TYPEs
var type_to_code = {
  'A': 1,
  'NS': 2,
  'MD': 3,
  'MF': 4,
  'CNAME': 5,
  'SOA': 6,
  'MB': 7,
  'MG': 8,
  'MR': 9,
  'NULL': 10,
  'WKS': 11,
  'PTR': 12,
  'HINFO': 13,
  'MINFO': 14,
  'MX': 15,
  'TXT': 16,
  'RP': 17,
  'AFSDB': 18,
  'X25': 19,
  'ISDN': 20,
  'RT': 21,
  'NSAP': 22,
  'NSAP_PTR': 23,
  'SIG': 24,
  'KEY': 25,
  'PX': 26,
  'GPOS': 27,
  'AAAA': 28,
  'LOC': 29,
  'NXT': 30,
  'EID': 31,
  'NIMLOC': 32,
  'SRV': 33,
  'ATMA': 34,
  'NAPTR': 35,
  'KX': 36,
  'CERT': 37,
  'A6': 38,
  'DNAME': 39,
  'SINK': 40,
  'OPT': 41,
  'APL': 42,
  'DS': 43,
  'SSHFP': 44,
  'IPSECKEY': 45,
  'RRSIG': 46,
  'NSEC': 47,
  'DNSKEY': 48,
  'DHCID': 49,
  'NSEC3': 50,
  'NSEC3PARAM': 51,
  'TLSA': 52,
  'SMIMEA': 53,
  'HIP': 55,
  'NINFO': 56,
  'RKEY': 57,
  'TALINK': 58,
  'CDS': 59,
  'CDNSKEY': 60,
  'OPENPGPKEY': 61,
  'CSYNC': 62,
  'ZONEMD': 63,
  'SVCB': 64,
  'HTTPS': 65,
  'NID': 104,
  'L32': 105,
  'L64': 106,
  'LP': 107,
  'EUI48': 108,
  'EUI64': 109,
  'TKEY': 249,
  'TSIG': 250,
  'IXFR': 251,
  'AXFR': 252,
  'MAILB': 253,
  'MAILA': 254,
  'ANY': 255,
  'URI': 256,
  'CAA': 257,
  'TA': 32768,
  'DLV': 32769
};

// RCODEs (including EDNS extended)
var rcode_to_code = {
  'NOERROR': 0,
  'FORMERR': 1,
  'SERVFAIL': 2,
  'NXDOMAIN': 3,
  'NOTIMP': 4,
  'REFUSED': 5,
  'YXDOMAIN': 6,
  'YXRRSET': 7,
  'NXRRSET': 8,
  'NOTAUTH': 9,
  'NOTZONE': 10,
  'DSOTYPENI': 11,
  'RCODE_12': 12,
  'RCODE_13': 13,
  'RCODE_14': 14,
  'RCODE_15': 15,
  'BADVERS': 16,
  'BADSIG': 16,
  'BADKEY': 17,
  'BADTIME': 18,
  'BADMODE': 19,
  'BADNAME': 20,
  'BADALG': 21,
  'BADTRUNC': 22,
  'BADCOOKIE': 23
};

// OPCODEs
var opcode_to_code = {
  'QUERY': 0,
  'IQUERY': 1,
  'STATUS': 2,
  'OPCODE_3': 3,
  'NOTIFY': 4,
  'UPDATE': 5,
  'DSO': 6,
  'OPCODE_7': 7,
  'OPCODE_8': 8,
  'OPCODE_9': 9,
  'OPCODE_10': 10,
  'OPCODE_11': 11,
  'OPCODE_12': 12,
  'OPCODE_13': 13,
  'OPCODE_14': 14,
  'OPCODE_15': 15
};

// Classes
var class_to_code = {
  'IN': 1,
  'CS': 2,
  'CH': 3,
  'HS': 4,
  'NONE': 254,
  'ANY': 255
};

// EDNS Option Codes (per IANA)
var EDNS_OPT = {
  LLQ: 1,
  UL: 2,
  NSID: 3,
  DAU: 5,
  DHU: 6,
  N3U: 7,
  ECS: 8,
  EXPIRE: 9,
  COOKIE: 10,
  KEEPALIVE: 11,
  PADDING: 12,
  CHAIN: 13,
  KEYTAG: 14,
  EDE: 15
};

// SVCB/HTTPS SvcParamKeys (RFC 9460)
var SvcParamKeys = {
  mandatory: 0,
  alpn: 1,
  noDefaultAlpn: 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
  dohpath: 7,
  ohttp: 8,
  tlsSupportedGroups: 9,
};

// Inverse maps
var code_to_type = invertObject(type_to_code);
var code_to_rcode = invertObject(rcode_to_code);
var code_to_opcode = invertObject(opcode_to_code);
var code_to_class = invertObject(class_to_code);

export {
  type_to_code,
  code_to_type,
  rcode_to_code,
  code_to_rcode,
  opcode_to_code,
  code_to_opcode,
  class_to_code,
  code_to_class,
  EDNS_OPT,
  SvcParamKeys,
};
