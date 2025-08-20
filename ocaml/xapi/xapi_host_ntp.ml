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

let dhclient_chrony_servers_prefix = "/var/lib/dhclient/chrony.servers"

let chrony_conf = "/etc/chrony.conf"

let get_dhclient_interfaces () =
  let extract_interface_name filename =
    try Scanf.sscanf filename "dhclient-%[^.].leases" (fun x -> Some x)
    with _ -> None
  in
  Sys.readdir "/var/lib/xcp"
  |> Array.to_list
  |> List.filter_map extract_interface_name

let get_dhcp_ntp_server interface =
  let file_name = Printf.sprintf "/var/lib/xcp/dhclient-%s.leases" interface in
  Xapi_stdext_unix.Unixext.read_lines file_name
  |> List.find_map (fun line ->
         let line = String.trim line in
         try Scanf.sscanf line "option ntp-servers %s;" (fun x -> Some x)
         with _ -> None
     )

let add_dhcp_ntp_server () =
  get_dhclient_interfaces ()
  |> List.iter (fun interface ->
         match get_dhcp_ntp_server interface with
         | Some server ->
             let line = Printf.sprintf "server %s iburst" server in
             Unixext.append_line
               (dhclient_chrony_servers_prefix ^ interface)
               line
         | None ->
             ()
     )

let remove_dhcp_ntp () =
  Forkhelpers.execute_command_get_output "rm"
    ["-r"; "/var/lib/dhclient/chrony.servers.*"]

let restart_ntp_service () =
  Xapi_systemctl.restart ~wait_until_success:false "chronyd"

let parse_chrony_conf () =
  try
    Xapi_stdext_unix.Unixext.read_lines chrony_conf
    |> List.partition (fun line -> String.starts_with line "server ")
  with Sys_error _ -> ([], [])

let write_chrony_conf other servers =
  let lines = List.map (fun s -> Printf.sprintf "server %s iburst" s) servers in
  let all_lines = other @ lines in
  Unixext.write_lines chrony_conf all_lines

let set_ntp_mode ~__context ~self mode =
  let current_mode = Db.Host.get_ntp_mode ~~context ~self in
  if mode = current_mode then
    ()
  else
    match (current_mode, mode) with
    | dhcp, custom ->
        remove_dhcp_ntp () ; add_custom_ntp_servers () ; restart_ntp_service ()
    | custom, dhcp ->
        remove_custom_ntp_servers () ;
        add_dhcp_ntp_server () ;
        restart_ntp_service ()
    | dhcp, default ->
        remove_dhcp_ntp () ;
        remove_custom_ntp_servers () ;
        restart_ntp_service ()
    | default, dhcp ->
        add_dhcp_ntp_server () ; restart_ntp_service ()
    | default, custom ->
        remove_custom_ntp_servers () ;
        restart_ntp_service ()
    | custom, default ->
        remove_custom_ntp_servers () ;
        add_default_ntp_servers () ;
        restart_ntp_service ()
