(*
 * Copyright (c) Cloud Software Group, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

(* Tests for Lldp.parse_neighbors: parsing the JSON emitted by
   [lldpcli -f json show neighbors]. *)

let lldp_rx_testable =
  let open Network_stats in
  Alcotest.testable
    (fun ppf rx ->
      Fmt.pf ppf "{system_name=%a; port_id=%a; port_description=%a}"
        Fmt.(option string) rx.system_name Fmt.(option string) rx.port_id
        Fmt.(option string) rx.port_description
    )
    ( = )

let result_testable = Alcotest.(list (pair string lldp_rx_testable))

let rx ?system_name ?port_id ?port_description () =
  Network_stats.{system_name; port_id; port_description}

(* One interface with one neighbour (a Cisco Nexus switch). *)
let single_json =
  {|
  { "lldp": { "interface": [
    { "eno8303": {
        "via": "LLDP", "rid": "3",
        "chassis": { "NKG-ESWA07-2.eng.citrite.net": {
          "id": { "type": "mac", "value": "c4:ab:4d:f0:9b:d3" },
          "descr": "Cisco Nexus",
          "capability": [ { "type": "Bridge", "enabled": true } ]
        } },
        "port": {
          "id": { "type": "ifname", "value": "Ethernet1/28" },
          "descr": "nkg-dt16/idrac", "ttl": "120"
        }
    } }
  ] } }
  |}

(* One interface with two neighbours (wider multicast scope / repeater). *)
let multi_json =
  {|
  { "lldp": { "interface": [
    { "eno8303": {
        "rid": "1",
        "chassis": { "TOR-A-01": { "id": { "type": "mac", "value": "aa" } } },
        "port": { "id": { "type": "ifname", "value": "Eth1/8/3" },
                  "descr": "rack7-a" }
    } },
    { "eno8303": {
        "rid": "2",
        "chassis": { "TOR-B-02": { "id": { "type": "mac", "value": "bb" } } },
        "port": { "id": { "type": "ifname", "value": "Eth2/8/3" },
                  "descr": "rack7-b" }
    } }
  ] } }
  |}

let empty_json = {| { "lldp": { "interface": [] } } |}

let test_single () =
  Alcotest.check result_testable "single neighbour"
    [
      ( "eno8303"
      , rx ~system_name:"NKG-ESWA07-2.eng.citrite.net" ~port_id:"Ethernet1/28"
          ~port_description:"nkg-dt16/idrac" ()
      )
    ]
    (Lldp.parse_neighbors single_json)

let test_multi () =
  (* The parser returns all neighbours; picking one is done by the caller. *)
  Alcotest.check result_testable "two neighbours on one interface"
    [
      ("eno8303", rx ~system_name:"TOR-A-01" ~port_id:"Eth1/8/3" ~port_description:"rack7-a" ())
    ; ("eno8303", rx ~system_name:"TOR-B-02" ~port_id:"Eth2/8/3" ~port_description:"rack7-b" ())
    ]
    (Lldp.parse_neighbors multi_json)

let test_empty () =
  Alcotest.check result_testable "no neighbours" []
    (Lldp.parse_neighbors empty_json)

let test_malformed () =
  Alcotest.check result_testable "malformed JSON yields empty" []
    (Lldp.parse_neighbors "not json {")

let tests =
  [
    ( "lldp_parse_neighbors"
    , [
        ("single", `Quick, test_single)
      ; ("multi", `Quick, test_multi)
      ; ("empty", `Quick, test_empty)
      ; ("malformed", `Quick, test_malformed)
      ]
    )
  ]
