(*
 * Copyright (C) Citrix Systems Inc.
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

module D = Debug.Make (struct let name = "xapi_host_ntp" end)

open D

let dhclient_chrony_servers_prefix = "/var/lib/dhclient/chrony.servers."

let chrony_conf = "/etc/chrony.conf"

let get_dhclient_interfaces () =
  let extract_interface_name filename =
    try
      Scanf.sscanf filename "dhclient-%[^.].leases" (fun x ->
          debug "line %s, extract %s" filename x ;
          Some x
      )
    with _ -> None
  in
  Sys.readdir "/var/lib/xcp"
  |> Array.to_list
  |> List.filter_map extract_interface_name

let get_dhcp_ntp_server interface =
  let file_name = Printf.sprintf "/var/lib/xcp/dhclient-%s.leases" interface in
  Xapi_stdext_unix.Unixext.read_lines file_name
  (* todo: from the last to query *)
  |> List.find_map (fun line ->
         let line = String.trim line in
         try
           Scanf.sscanf line "option ntp-servers %[^;];" (fun x ->
               debug "line: %s, extract: %s" line x ;
               Some x
           )
         with _ -> None
     )

let add_dhcp_ntp_servers () =
  get_dhclient_interfaces ()
  |> List.iter (fun interface ->
         match get_dhcp_ntp_server interface with
         | Some server ->
             let line = Printf.sprintf "server %s iburst" server in
             Xapi_stdext_unix.Unixext.write_string_to_file
               (dhclient_chrony_servers_prefix ^ interface)
               line
         | None ->
             ()
     )

let remove_dhcp_ntp_servers () =
  Sys.readdir "/var/lib/dhclient/"
  |> Array.iter (fun file ->
         if String.starts_with ~prefix:"chrony.servers." file then (
           let file = Printf.sprintf "/var/lib/dhclient/%s" file in
           debug "Remove %s" file ; Sys.remove file
         )
     )

let restart_ntp_service () =
  Xapi_systemctl.restart ~wait_until_success:false "chronyd"

let parse_chrony_conf () =
  try
    Xapi_stdext_unix.Unixext.read_lines chrony_conf
    |> List.partition (String.starts_with ~prefix:"server ")
  with Sys_error _ -> ([], [])

let write_chrony_conf other servers =
  let lines = List.map (fun s -> Printf.sprintf "server %s iburst" s) servers in
  let all_lines = other @ lines in
  let write_lines fname lines =
    Xapi_stdext_unix.Unixext.write_string_to_file fname
      (String.concat "\n" lines)
  in
  write_lines chrony_conf all_lines

let set_servers_in_conf servers =
  let old, other = parse_chrony_conf () in
  debug "old: %s\n other: %s" (String.concat ", " old) (String.concat ", " other) ;
  write_chrony_conf other servers

let clear_servers_in_conf () = set_servers_in_conf []
