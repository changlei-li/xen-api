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

module D = Debug.Make (struct let name = "xapi_host_max_cstate" end)

open D

let xenpm_set value =
  let args =
    match value with
    | -1L ->
        ["set-max-cstate"; "unlimited"]
    | n when n >= 0L ->
        ["set-max-cstate"; Int64.to_string value; "0"]
    | _ ->
        raise
          Api_errors.(
            Server_error (invalid_value, ["value"; Int64.to_string value])
          )
  in
  let resp = Helpers.call_script !Xapi_globs.xenpm_bin args in
  (* Check runtime set max_cstate result *)
  let cstate =
    try Scanf.sscanf resp "max C-state set to %s" Fun.id
    with Scanf.Scan_failure _ ->
      error "Failed to parse max_cstate response: %s" resp ;
      raise Api_errors.(Server_error (invalid_value, ["value"; resp]))
  in
  let value_in_resp =
    match cstate with
    | "unlimited" ->
        -1L
    | s -> (
      try Scanf.sscanf s "C%Ld" Fun.id
      with Scanf.Scan_failure _ ->
        error "Failed to parse max_cstate response: %s" resp ;
        raise Api_errors.(Server_error (invalid_value, ["value"; resp]))
    )
  in
  if value_in_resp <> value then (
    error "Failed to set max_cstate: expected %Ld, got %Ld" value value_in_resp ;
    raise
      Api_errors.(
        Server_error
          ( invalid_value
          , [
              "value"
            ; Int64.to_string value_in_resp
            ; "expected"
            ; Int64.to_string value
            ]
          )
      )
  )

let xen_cmdline_set value =
  let args =
    match value with
    | -1L ->
        ["--delete-xen"; "max_cstate"]
    | n when n >= 0L ->
        ["--set-xen"; Printf.sprintf "max_cstate=%Ld,0" n]
    | _ ->
        raise
          Api_errors.(
            Server_error (invalid_value, ["value"; Int64.to_string value])
          )
  in
  Helpers.call_script !Xapi_globs.xen_cmdline_script args |> ignore

let xen_cmdline_get () =
  let args = ["--get-xen"; "max_cstate"] in
  try
    let ret =
      Helpers.call_script !Xapi_globs.xen_cmdline_script args |> String.trim
    in
    (* the ret may be
       "" -> unlimited
       "max_cstate=N" -> max cstate N
       "max_cstate=N,M" -> max cstate N, max c-sub-state M *)
    match Astring.String.fields ~is_sep:(fun c -> c = '=' || c = ',') ret with
    | [""] ->
        -1L
    | ["max_cstate"; state] | ["max_cstate"; state; _] ->
        Int64.of_string state
    | _ ->
        error "Failed to parse max_cstate response: %s" ret ;
        Helpers.internal_error "Failed to get max_cstate"
  with e ->
    error "Failed to get max_cstate: %s" (Printexc.to_string e) ;
    Helpers.internal_error "Failed to get max_cstate"
