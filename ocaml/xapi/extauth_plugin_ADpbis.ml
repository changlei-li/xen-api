(*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
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
(**
 * @group Access Control
*)

module D = Debug.Make (struct let name = "extauth_plugin_ADpbis" end)

open D
open Xapi_stdext_std.Xstringext

let ( let@ ) = ( @@ )

let finally = Xapi_stdext_pervasives.Pervasiveext.finally

let with_lock = Xapi_stdext_threads.Threadext.Mutex.execute

let lwsmd_service = "lwsmd"

module Lwsmd = struct
  (* This can be refined by Mtime.Span.hour when mtime is updated to 1.4.0 *)
  let restart_interval = Int64.mul 3600L 1000000000L |> Mtime.Span.of_uint64_ns

  let next_check_point =
    Mtime.add_span (Mtime_clock.now ()) restart_interval |> ref

  let is_ad_enabled ~__context =
    ( Helpers.get_localhost ~__context |> fun self ->
      Db.Host.get_external_auth_type ~__context ~self
    )
    |> fun x -> x = Xapi_globs.auth_type_AD

  let enable_nsswitch () =
    try
      ignore
        (Forkhelpers.execute_command_get_output
           !Xapi_globs.domain_join_cli_cmd
           ["configure"; "--enable"; "nsswitch"]
        )
    with e ->
      error "Fail to run %s with error %s"
        !Xapi_globs.domain_join_cli_cmd
        (ExnHelper.string_of_exn e)

  let stop ~timeout ~wait_until_success =
    Xapi_systemctl.stop ~timeout ~wait_until_success lwsmd_service

  let start ~timeout ~wait_until_success =
    Xapi_systemctl.start ~timeout ~wait_until_success lwsmd_service

  let restart ~timeout ~wait_until_success =
    Xapi_systemctl.restart ~timeout ~wait_until_success lwsmd_service

  let restart_on_error () =
    (* Only restart once within restart_interval *)
    let now = Mtime_clock.now () in
    match !next_check_point with
    | Some check_point ->
        if Mtime.is_later now ~than:check_point then (
          debug "Restart %s due to local server error" lwsmd_service ;
          next_check_point := Mtime.add_span now restart_interval ;
          restart ~timeout:0. ~wait_until_success:false
        )
    | None ->
        debug "next_check_point overflow"

  let init_service ~__context =
    (* This function is called during xapi start *)
    (* it will start lwsmd service if the host is authed with AD *)
    (* Xapi does not wait lwsmd service to boot up success as following reasons
     * 1. The waiting will slow down xapi bootup
     * 2. Xapi still needs to boot up even lwsmd bootup fail
     * 3. Xapi does not need to use lwsmd functionality during its bootup *)
    if is_ad_enabled ~__context then (
      restart ~wait_until_success:false ~timeout:5. ;
      (* Xapi help to enable nsswitch during bootup if it find the host is authed with AD
       * nsswitch will be automatically enabled with command domainjoin-cli
       * but this enabling is necessary when the host authed with AD upgrade
       * As it will not run the domainjoin-cli command again *)
      enable_nsswitch ()
    )
end

let match_error_tag (lines : string list) =
  let err_catch_list =
    [
      ("DNS_ERROR_BAD_PACKET", Auth_signature.E_LOOKUP)
    ; ("LW_ERROR_PASSWORD_MISMATCH", Auth_signature.E_CREDENTIALS)
    ; ("LW_ERROR_INVALID_ACCOUNT", Auth_signature.E_INVALID_ACCOUNT)
    ; ("LW_ERROR_ACCESS_DENIED", Auth_signature.E_DENIED)
    ; ("LW_ERROR_DOMAIN_IS_OFFLINE", Auth_signature.E_UNAVAILABLE)
    ; ("LW_ERROR_INVALID_OU", Auth_signature.E_INVALID_OU)
      (* More errors to be caught here *)
    ]
  in
  let split_to_words str =
    let seps = ['('; ')'; ' '; '\t'; '.'] in
    String.split_f (fun s -> List.exists (fun sep -> sep = s) seps) str
  in
  let rec has_err lines err_pattern =
    match lines with
    | [] ->
        false
    | line :: rest -> (
      try
        ignore (List.find (fun w -> w = err_pattern) (split_to_words line)) ;
        true
      with Not_found -> has_err rest err_pattern
    )
  in
  try
    let _, errtag =
      List.find
        (fun (err_pattern, _) -> has_err lines err_pattern)
        err_catch_list
    in
    errtag
  with Not_found -> Auth_signature.E_GENERIC

let extract_sid_from_group_list group_list =
  List.map
    (fun (_, v) ->
      let v = String.replace ")" "" v in
      let v = String.replace "sid =" "|" v in
      let vs = String.split_f (fun c -> c = '|') v in
      let sid = String.trim (List.nth vs 1) in
      debug "extract_sid_from_group_list get sid=[%s]" sid ;
      sid
    )
    (List.filter (fun (n, _) -> n = "") group_list)

let start_damon () =
  try Lwsmd.start ~timeout:5. ~wait_until_success:true
  with _ ->
    raise
      (Auth_signature.Auth_service_error
         ( Auth_signature.E_GENERIC
         , Printf.sprintf "Failed to start %s" lwsmd_service
         )
      )

module AuthADlw : Auth_signature.AUTH_MODULE = struct
  (*
   * External Authentication Plugin component
   * using AD/Pbis as a backend
   * v1 14Nov14 phus.lu@citrix.com
   *
   *)

  let user_friendly_error_msg =
    "The Active Directory Plug-in could not complete the command. Additional \
     information in the logs."

  let mutex_check_availability =
    Locking_helpers.Named_mutex.create "IS_SERVER_AVAILABLE"

  let splitlines s =
    String.split_f (fun c -> c = '\n') (String.replace "#012" "\n" s)

  let pbis_common_with_password (password : string) (pbis_cmd : string)
      (pbis_args : string list) =
    let debug_cmd =
      pbis_cmd ^ " " ^ List.fold_left (fun p pp -> p ^ " " ^ pp) " " pbis_args
    in
    try
      debug "execute %s" debug_cmd ;
      let env = [|"PASSWORD=" ^ password|] in
      let _ = Forkhelpers.execute_command_get_output ~env pbis_cmd pbis_args in
      []
    with
    | Forkhelpers.Spawn_internal_error (stderr, stdout, Unix.WEXITED n) ->
        error "execute %s exited with code %d [stdout = '%s'; stderr = '%s']"
          debug_cmd n stdout stderr ;
        let lines =
          List.filter
            (fun l -> String.length l > 0)
            (splitlines (stdout ^ stderr))
        in
        let errmsg = List.hd (List.rev lines) in
        let errtag = match_error_tag lines in
        raise (Auth_signature.Auth_service_error (errtag, errmsg))
    | e ->
        error "execute %s exited: %s" debug_cmd (ExnHelper.string_of_exn e) ;
        raise
          (Auth_signature.Auth_service_error
             (Auth_signature.E_GENERIC, user_friendly_error_msg)
          )

  let pbis_config (name : string) (value : string) =
    let pbis_cmd = "/opt/pbis/bin/config" in
    let pbis_args = [name; value] in
    let debug_cmd = pbis_cmd ^ " " ^ name ^ " " ^ value in
    try
      debug "execute %s" debug_cmd ;
      let _ = Forkhelpers.execute_command_get_output pbis_cmd pbis_args in
      ()
    with
    | Forkhelpers.Spawn_internal_error (stderr, stdout, Unix.WEXITED n) ->
        error "execute %s exited with code %d [stdout = '%s'; stderr = '%s']"
          debug_cmd n stdout stderr ;
        let lines =
          List.filter
            (fun l -> String.length l > 0)
            (splitlines (stdout ^ stderr))
        in
        let errmsg = List.hd (List.rev lines) in
        raise
          (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC, errmsg))
    | e ->
        error "execute %s exited: %s" debug_cmd (ExnHelper.string_of_exn e) ;
        raise
          (Auth_signature.Auth_service_error
             (Auth_signature.E_GENERIC, user_friendly_error_msg)
          )

  let ensure_pbis_configured () =
    pbis_config "SpaceReplacement" "+" ;
    pbis_config "CreateHomeDir" "false" ;
    pbis_config "SyncSystemTime" "false" ;
    pbis_config "LdapSignAndSeal" "true" ;
    pbis_config "CacheEntryExpiry" "300" ;
    ()

  let pbis_common ?(stdin_string = "") (pbis_cmd : string)
      (pbis_args : string list) =
    let debug_cmd =
      pbis_cmd ^ " " ^ List.fold_left (fun p pp -> p ^ " " ^ pp) " " pbis_args
    in
    let debug_cmd =
      if String.has_substr debug_cmd "--password" then
        "(omitted for security)"
      else
        debug_cmd
    in
    (* stuff to clean up on the way out of the function: *)
    let fds_to_close = ref [] in
    let files_to_unlink = ref [] in
    (* take care to close an fd only once *)
    let close_fd fd =
      if List.mem fd !fds_to_close then (
        Unix.close fd ;
        fds_to_close := List.filter (fun x -> x <> fd) !fds_to_close
      )
    in
    (* take care to unlink a file only once *)
    let unlink_file filename =
      if List.mem filename !files_to_unlink then (
        Unix.unlink filename ;
        files_to_unlink := List.filter (fun x -> x <> filename) !files_to_unlink
      )
    in
    (* guarantee to release all resources (files, fds) *)
    let finalize () =
      List.iter close_fd !fds_to_close ;
      List.iter unlink_file !files_to_unlink
    in
    let finally_finalize f = finally f finalize in
    let exited_code = ref 0 in
    let output = ref "" in
    finally_finalize (fun () ->
        let _ =
          try
            debug "execute %s" debug_cmd ;
            (* creates pipes between xapi and pbis process *)
            let in_readme, in_writeme = Unix.pipe () in
            fds_to_close := in_readme :: in_writeme :: !fds_to_close ;
            let out_tmpfile = Filename.temp_file "pbis" ".out" in
            files_to_unlink := out_tmpfile :: !files_to_unlink ;
            let err_tmpfile = Filename.temp_file "pbis" ".err" in
            files_to_unlink := err_tmpfile :: !files_to_unlink ;
            let out_writeme = Unix.openfile out_tmpfile [Unix.O_WRONLY] 0o0 in
            fds_to_close := out_writeme :: !fds_to_close ;
            let err_writeme = Unix.openfile err_tmpfile [Unix.O_WRONLY] 0o0 in
            fds_to_close := err_writeme :: !fds_to_close ;
            let pid =
              Forkhelpers.safe_close_and_exec (Some in_readme)
                (Some out_writeme) (Some err_writeme) [] pbis_cmd pbis_args
            in
            finally
              (fun () ->
                debug "Created process pid %s for cmd %s"
                  (Forkhelpers.string_of_pidty pid)
                  debug_cmd ;

                (* Insert this delay to reproduce the cannot write to stdin bug:
                   Thread.delay 5.; *)
                (* WARNING: we don't close the in_readme because otherwise in the case where the pbis
                   binary doesn't expect any input there is a race between it finishing (and closing the last
                   reference to the in_readme) and us attempting to write to in_writeme. If pbis wins the
                   race then our write will fail with EPIPE (Unix.error 31 in ocamlese). If we keep a reference
                   to in_readme then our write of "\n" will succeed.

                   An alternative fix would be to not write anything when stdin_string = "" *)

                (* push stdin_string to recently created process' STDIN *)
                try
                  (* usually, STDIN contains some sensitive data such as passwords that we do not want showing up in ps *)
                  (* or in the debug log via debug_cmd *)
                  let stdin_string = stdin_string ^ "\n" in
                  (*HACK:without \n, the pbis scripts don't return!*)
                  let (_ : int) =
                    Unix.write_substring in_writeme stdin_string 0
                      (String.length stdin_string)
                  in
                  close_fd in_writeme
                  (* we need to close stdin, otherwise the unix cmd waits forever *)
                with e ->
                  (* in_string is usually the password or other sensitive param, so never write it to debug or exn *)
                  debug "Error writing to stdin for cmd %s: %s" debug_cmd
                    (ExnHelper.string_of_exn e) ;
                  raise
                    (Auth_signature.Auth_service_error
                       (Auth_signature.E_GENERIC, ExnHelper.string_of_exn e)
                    )
              )
              (fun () ->
                match Forkhelpers.waitpid pid with
                | _, Unix.WEXITED n ->
                    exited_code := n ;
                    output :=
                      Xapi_stdext_unix.Unixext.string_of_file out_tmpfile
                      ^ Xapi_stdext_unix.Unixext.string_of_file err_tmpfile
                | _ ->
                    error "PBIS %s exit with WSTOPPED or WSIGNALED" debug_cmd ;
                    raise
                      (Auth_signature.Auth_service_error
                         (Auth_signature.E_GENERIC, user_friendly_error_msg)
                      )
              )
          with e ->
            error "execute %s exited: %s" debug_cmd (ExnHelper.string_of_exn e) ;
            raise
              (Auth_signature.Auth_service_error
                 (Auth_signature.E_GENERIC, user_friendly_error_msg)
              )
        in
        if !exited_code <> 0 then (
          error "execute '%s': exit_code=[%d] output=[%s]" debug_cmd
            !exited_code
            (String.replace "\n" ";" !output) ;
          let split_to_words s =
            String.split_f (fun c -> c = '(' || c = ')' || c = '.' || c = ' ') s
          in
          let revlines =
            List.rev
              (List.filter (fun l -> String.length l > 0) (splitlines !output))
          in
          let errmsg = List.hd revlines in
          let errcodeline =
            if List.length revlines > 1 then List.nth revlines 1 else errmsg
          in
          let errcode =
            List.hd
              (List.filter
                 (fun w -> String.starts_with ~prefix:"LW_ERROR_" w)
                 (split_to_words errcodeline)
              )
          in
          debug "Pbis raised an error for cmd %s: (%s) %s" debug_cmd errcode
            errmsg ;
          match errcode with
          | "LW_ERROR_INVALID_GROUP_INFO_LEVEL" ->
              raise
                (Auth_signature.Auth_service_error
                   (Auth_signature.E_GENERIC, errcode)
                )
              (* For pbis_get_all_byid *)
          | "LW_ERROR_NO_SUCH_USER"
          | "LW_ERROR_NO_SUCH_GROUP"
          | "LW_ERROR_NO_SUCH_OBJECT" ->
              raise Not_found (* Subject_cannot_be_resolved *)
          | "LW_ERROR_KRB5_CALL_FAILED"
          | "LW_ERROR_PASSWORD_MISMATCH"
          | "LW_ERROR_ACCOUNT_DISABLED"
          | "LW_ERROR_NOT_HANDLED" ->
              raise (Auth_signature.Auth_failure errmsg)
          | "LW_ERROR_INVALID_OU" ->
              raise
                (Auth_signature.Auth_service_error
                   (Auth_signature.E_INVALID_OU, errmsg)
                )
          | "LW_ERROR_INVALID_DOMAIN" ->
              raise
                (Auth_signature.Auth_service_error
                   (Auth_signature.E_GENERIC, errmsg)
                )
          | "LW_ERROR_ERRNO_ECONNREFUSED" ->
              (* CA-368806: Restart service to workaround pbis wedged *)
              Lwsmd.restart_on_error () ;
              raise
                (Auth_signature.Auth_service_error
                   (Auth_signature.E_GENERIC, errmsg)
                )
          | "LW_ERROR_LSA_SERVER_UNREACHABLE" | _ ->
              raise
                (Auth_signature.Auth_service_error
                   ( Auth_signature.E_GENERIC
                   , Printf.sprintf "(%s) %s" errcode errmsg
                   )
                )
        ) else
          debug "execute %s: output length=[%d]" debug_cmd
            (String.length !output) ;
        let lines =
          List.filter (fun l -> String.length l > 0) (splitlines !output)
        in
        let parse_line (acc, currkey) line =
          let slices = String.split ~limit:2 ':' line in
          debug "parse %s: currkey=[%s] line=[%s]" debug_cmd currkey line ;
          if List.length slices > 1 then (
            let key = String.trim (List.hd slices) in
            let value = String.trim (List.nth slices 1) in
            debug "parse %s: key=[%s] value=[%s] currkey=[%s]" debug_cmd key
              value currkey ;
            if String.length value > 0 then
              (acc @ [(key, value)], "")
            else
              (acc, key)
          ) else
            let key = currkey in
            let value = String.trim line in
            debug "parse %s: key=[%s] value=[%s] currkey=[%s]" debug_cmd key
              value currkey ;
            (acc @ [(key, value)], currkey)
        in
        let attrs, _ = List.fold_left parse_line ([], "") lines in
        attrs
    )

  (* assoc list for caching pbis_common results,
     item value is ((stdin_string, pbis_cmd, pbis_args), (unix_time, pbis_common_result))
  *)
  let cache_of_pbis_common :
      ((string * string * string list) * (float * (string * string) list)) list
      ref =
    ref []

  let cache_of_pbis_common_m = Mutex.create ()

  let pbis_common_with_cache ?(stdin_string = "") (pbis_cmd : string)
      (pbis_args : string list) =
    let expired = 120.0 in
    let now = Unix.time () in
    let cache_key = (stdin_string, pbis_cmd, pbis_args) in
    let f () =
      cache_of_pbis_common :=
        List.filter
          (fun (_, (ts, _)) -> now -. ts < expired)
          !cache_of_pbis_common ;
      try
        let _, result = List.assoc cache_key !cache_of_pbis_common in
        debug "pbis_common_with_cache hit \"%s\" cache." pbis_cmd ;
        result
      with Not_found ->
        let result = pbis_common ~stdin_string pbis_cmd pbis_args in
        cache_of_pbis_common :=
          !cache_of_pbis_common @ [(cache_key, (Unix.time (), result))] ;
        result
    in
    with_lock cache_of_pbis_common_m f

  let get_joined_domain_name () =
    Server_helpers.exec_with_new_task "obtaining joined-domain name"
      (fun __context ->
        let host = Helpers.get_localhost ~__context in
        (* the service_name always contains the domain name provided during domain-join *)
        Db.Host.get_external_auth_service_name ~__context ~self:host
    )

  (* CP-842: when resolving AD usernames, make joined-domain prefix optional *)
  let get_full_subject_name ?(use_nt_format = true) subject_name =
    (* CA-27744: always use NT-style names by default *)
    try
      (* tests if the UPN account name separator @ is present in subject name *)
      ignore (String.index subject_name '@') ;
      (* we only reach this point if the separator @ is present in subject_name *)
      (* nothing to do, we assume that subject_name already contains the domain name after @ *)
      subject_name
    with Not_found -> (
      try
        (* if no UPN username separator @ was found *)

        (* tests if the NT account name separator \ is present in subject name *)
        ignore (String.index subject_name '\\') ;
        (* we only reach this point if the separator \ is present in subject_name *)
        (* nothing to do, we assume that subject_name already contains the domain name before \ *)
        subject_name
      with Not_found ->
        if
          (* if neither the UPN separator @ nor the NT username separator \ was found *)
          use_nt_format
        then
          (* the default: NT names is unique, whereas UPN ones are not (CA-27744) *)
          (* we prepend the joined-domain name to the subjectname as an NT name: <domain.com>\<subjectname> *)
          get_joined_domain_name () ^ "\\" ^ subject_name
        (* obs: (1) pbis accepts a fully qualified domain name <domain.com> with both formats and *)
        (*      (2) some pbis commands accept only the NT-format, such as find-group-by-name *)
        else
          (* UPN format not the default format (CA-27744) *)
          (* we append the joined-domain name to the subjectname as a UPN name: <subjectname>@<domain.com> *)
          subject_name ^ "@" ^ get_joined_domain_name ()
    )

  (* Converts from UPN format (user@domain.com) to legacy NT format (domain.com\user) *)
  (* This function is a workaround to use find-group-by-name, which requires nt-format names) *)
  (* For anything else, use the original UPN name *)
  let convert_upn_to_nt_username subject_name =
    try
      (* test if the UPN account name separator @ is present in subject name *)
      let i = String.index subject_name '@' in
      (* we only reach this point if the separator @ is present in subject_name *)
      (* when @ is present, we need to convert the UPN name to NT format *)
      let user = String.sub subject_name 0 i in
      let domain =
        String.sub subject_name (i + 1) (String.length subject_name - i - 1)
      in
      domain ^ "\\" ^ user
    with Not_found ->
      (* if no UPN username separator @ was found *)
      (* nothing to do in this case *)
      subject_name

  let pbis_get_all_byid subject_id =
    try
      pbis_common_with_cache "/opt/pbis/bin/find-by-sid"
        ["--level"; "2"; subject_id]
    with
    | Auth_signature.Auth_service_error
        (Auth_signature.E_GENERIC, "LW_ERROR_INVALID_GROUP_INFO_LEVEL")
    ->
      pbis_common_with_cache "/opt/pbis/bin/find-by-sid"
        ["--level"; "1"; subject_id]

  let pbis_get_group_sids_byname _subject_name =
    let subject_name = get_full_subject_name _subject_name in
    (* append domain if necessary *)
    let subject_attrs =
      pbis_common_with_cache "/opt/pbis/bin/list-groups-for-user"
        ["--show-sid"; subject_name]
    in
    (* PBIS list-groups-for-user raw output like
        Number of groups found for user 'test@testdomain' : 2
        Group[1 of 2] name = testdomain\dnsadmins (gid = 580912206, sid = S-1-5-21-791009147-1041474540-2433379237-1102)
        Group[2 of 2] name = testdomain\domain+users (gid = 580911617, sid = S-1-5-21-791009147-1041474540-2433379237-513)
       And pbis_common will return subject_attrs as
       [("Number of groups found for user 'test@testdomain'", "2"), ("", line1), ("", line2) ... ("", lineN)]
    *)
    extract_sid_from_group_list subject_attrs

  (* general Pbis error *)

  let pbis_get_sid_byname _subject_name cmd =
    let subject_name = get_full_subject_name _subject_name in
    (* append domain if necessary *)
    let subject_attrs = pbis_common cmd ["--level"; "1"; subject_name] in
    (* find-user-by-name returns several lines. We ony need the SID *)
    if List.mem_assoc "SID" subject_attrs then
      List.assoc "SID" subject_attrs (* OK, return SID *)
    else
      (*no SID value returned*)
      (* this should not have happend, pbis didn't return an SID field!! *)
      let msg =
        Printf.sprintf "Pbis didn't return an SID field for user %s"
          subject_name
      in
      debug "Error pbis_get_sid_byname for subject name %s: %s" subject_name msg ;
      raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC, msg))

  (* general Pbis error *)

  (* subject_id get_subject_identifier(string subject_name)

      Takes a subject_name (as may be entered into the XenCenter UI when defining subjects --
      see Access Control wiki page); and resolves it to a subject_id against the external
      auth/directory service.
      Raises Not_found (*Subject_cannot_be_resolved*) if authentication is not succesful.
  *)
  let get_subject_identifier ~__context _subject_name =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in

    try
      (* looks up list of users*)
      let subject_name = get_full_subject_name _subject_name in
      (* append domain if necessary *)
      pbis_get_sid_byname subject_name "/opt/pbis/bin/find-user-by-name"
    with _ ->
      (* append domain if necessary, find-group-by-name only accepts nt-format names  *)
      let subject_name =
        get_full_subject_name ~use_nt_format:true
          (convert_upn_to_nt_username _subject_name)
      in
      (* looks up list of groups*)
      pbis_get_sid_byname subject_name "/opt/pbis/bin/find-group-by-name"

  (* subject_id Authenticate_username_password(string username, string password)

      Takes a username and password, and tries to authenticate against an already configured
      auth service (see XenAPI requirements Wiki page for details of how auth service configuration
      takes place and the appropriate values are stored within the XenServer Metadata).
      If authentication is successful then a subject_id is returned representing the account
      corresponding to the supplied credentials (where the subject_id is in a namespace managed by
      the auth module/service itself -- e.g. maybe a SID or something in the AD case).
      Raises auth_failure if authentication is not successful
  *)

  let authenticate_username_password ~__context username password =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in
    (* first, we try to authenticated user against our external user database *)
    (* pbis_common will raise an Auth_failure if external authentication fails *)
    let domain, user =
      match String.split_f (fun c -> c = '\\') username with
      | [domain; user] ->
          (domain, user)
      | [user] ->
          (get_joined_domain_name (), user)
      | _ ->
          raise
            (Auth_signature.Auth_service_error
               (Auth_signature.E_GENERIC, "Invalid username " ^ username)
            )
    in
    let (_ : (string * string) list) =
      pbis_common "/opt/pbis/bin/lsa"
        [
          "authenticate-user"
        ; "--user"
        ; user
        ; "--domain"
        ; domain
        ; "--password"
        ; password
        ]
    in
    (* no exception raised, then authentication succeeded, *)
    (* now we return the authenticated user's id *)
    get_subject_identifier ~__context (get_full_subject_name username)

  (* subject_id Authenticate_ticket(string ticket)

      As above but uses a ticket as credentials (i.e. for single sign-on)
  *)
  (* not implemented now, not needed for our tests, only for a *)
  (* future single sign-on feature *)
  let authenticate_ticket ~__context:_ _tgt =
    failwith "extauth_plugin authenticate_ticket not implemented"

  (* ((string*string) list) query_subject_information(string subject_identifier)

      Takes a subject_identifier and returns the user record from the directory service as
      key/value pairs. In the returned string*string map, there _must_ be a key called
      subject_name that refers to the name of the account (e.g. the user or group name as may
      be displayed in XenCenter). There is no other requirements to include fields from the user
      record -- initially qI'd imagine that we wouldn't bother adding anything else here, but
      it's a string*string list anyway for possible future expansion.
      Raises Not_found (*Subject_cannot_be_resolved*) if subject_id cannot be resolved by external auth service
  *)
  let query_subject_information ~__context subject_identifier =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in
    let unmap_lw_space_chars lwname =
      let defensive_copy = Bytes.of_string lwname in
      (* CA-29006: map chars in names back to original space chars in windows-names *)
      (* we use + as the pbis space-replacement because it's an invalid NT-username char in windows *)
      (* the space-replacement char used by pbis is defined at /etc/pbis/lsassd.conf *)
      let current_lw_space_replacement = '+' in
      String.iteri
        (fun i c ->
          if c = current_lw_space_replacement then
            Bytes.set defensive_copy i ' '
          else
            ()
        )
        lwname ;
      Bytes.unsafe_to_string defensive_copy
    in
    let get_value name ls =
      if List.mem_assoc name ls then List.assoc name ls else ""
    in
    let infolist = pbis_get_all_byid subject_identifier in
    let subject_is_group = get_value "Uid" infolist = "" in
    if subject_is_group then
      (* subject is group *)
      (* in this case, a few info fields are not available: UPN, Uid, Gecos, Account {disabled,expired,locked}, Password expired *)
      [
        ("subject-name", unmap_lw_space_chars (get_value "Name" infolist))
      ; ("subject-gid", get_value "Gid" infolist)
      ; ("subject-sid", get_value "SID" infolist)
      ; ("subject-is-group", "true")
        (*(* comma-separated list of subjects that are contained in this subject *)
          ("contains-byname", List.fold_left (fun (n,v) m ->m^","^v) "" (List.filter (fun (n,v)->n="Members") infolist));*)
      ]
    else (* subject is user *)
      let subject_name = unmap_lw_space_chars (get_value "Name" infolist) in
      let subject_gecos = get_value "Gecos" infolist in
      [
        ("subject-name", subject_name)
      ; ("subject-upn", get_value "UPN" infolist)
      ; ("subject-uid", get_value "Uid" infolist)
      ; ("subject-gid", get_value "Gid" infolist)
      ; ("subject-sid", get_value "SID" infolist)
      ; ("subject-gecos", subject_gecos)
      ; ( "subject-displayname"
        , if subject_gecos = "" || subject_gecos = "<null>" then
            subject_name
          else
            subject_gecos
        )
      ; (*("subject-homedir", get_value "Home dir" infolist);*)
        (*("subject-shell", get_value "Shell" infolist);*)
        ("subject-is-group", "false")
      ; ( "subject-account-disabled"
        , get_value "Account disabled (or locked)" infolist
        )
      ; ("subject-account-expired", get_value "Account Expired" infolist)
      ; ( "subject-account-locked"
        , get_value "Account disabled (or locked)" infolist
        )
      ; ("subject-password-expired", get_value "Password Expired" infolist)
      ]

  (* (string list) query_group_membership(string subject_identifier)

      Takes a subject_identifier and returns its group membership (i.e. a list of subject
      identifiers of the groups that the subject passed in belongs to). The set of groups returned
      _must_ be transitively closed wrt the is_member_of relation if the external directory service
      supports nested groups (as AD does for example)
  *)
  let query_group_membership ~__context subject_identifier =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in

    let subject_info =
      query_subject_information ~__context subject_identifier
    in
    if
      List.assoc "subject-is-group" subject_info = "true"
      (* this field is always present *)
    then
      (* subject is a group, so get_group_sids_byname will not work because pbis's list-groups *)
      (* doesnt work if a group name is given as input *)
      (* FIXME: default action for groups until workaround is found: return an empty list of membership groups *)
      []
    else
      (* subject is a user, list-groups and therefore get_group_sids_byname work fine *)
      let subject_name = List.assoc "subject-name" subject_info in
      (* CA-27744: always use NT-style names *)
      let subject_sid_membership_list =
        pbis_get_group_sids_byname subject_name
      in
      debug "Resolved %i group sids for subject %s (%s): %s"
        (List.length subject_sid_membership_list)
        subject_name subject_identifier
        (List.fold_left
           (fun p pp -> if p = "" then pp else p ^ "," ^ pp)
           "" subject_sid_membership_list
        ) ;
      subject_sid_membership_list

  (*
    In addition, there are some event hooks that auth modules implement as follows:
*)

  let _is_pbis_server_available ~__context max_tries =
    (* we _need_ to use a username contained in our domain, otherwise the following tests won't work.
       Microsoft KB/Q243330 article provides the KRBTGT account as a well-known built-in SID in AD
       Microsoft KB/Q229909 article says that KRBTGT account cannot be renamed or enabled, making
       it the perfect target for such a test using a username (Administrator account can be renamed) *)
    let krbtgt = "KRBTGT" in
    let try_clear_cache () =
      (* the primary purpose of this function is to clear the cache so that
         [ try_fetch_sid ] is forced to perform an end to end query to the
         AD server. as such, we don't care if krbtgt was not originally in
         the cache *)
      match get_full_subject_name krbtgt with
      | exception _ ->
          info
            "_is_pbis_server_available: failed to get full subject name for %s"
            krbtgt ;
          Error ()
      | full_username -> (
        match
          ignore
            (pbis_common "/opt/pbis/bin/ad-cache"
               ["--delete-user"; "--name"; full_username]
            )
        with
        | () | (exception Not_found) ->
            Ok ()
        | exception e ->
            debug "Failed to remove user %s from cache: %s" full_username
              (ExnHelper.string_of_exn e) ;
            Error ()
      )
    in
    let try_fetch_sid () =
      try
        let sid = get_subject_identifier ~__context krbtgt in
        debug
          "Request to external authentication server successful: user %s was \
           found"
          krbtgt ;
        let (_ : (string * string) list) =
          query_subject_information ~__context sid
        in
        debug
          "Request to external authentication server successful: sid %s was \
           found"
          sid ;
        Ok ()
      with
      | Not_found ->
          (* that means that pbis is responding to at least cached subject queries.
             in this case, KRBTGT wasn't found in the AD domain. this usually indicates that the
             AD domain is offline/inaccessible to pbis, which will cause problems, specially
             to the ssh python hook-script, so we need to try again until KRBTGT is found, indicating
             that the domain is online and accessible to pbis queries *)
          debug
            "Request to external authentication server returned KRBTGT \
             Not_found" ;
          Error ()
      | e ->
          debug
            "Request to external authentication server failed for reason: %s"
            (ExnHelper.string_of_exn e) ;
          Error ()
    in
    let rec go i =
      if i > max_tries then (
        info
          "Testing external authentication server failed after %i tries, \
           giving up!"
          max_tries ;
        false
      ) else (
        debug
          "Testing if external authentication server is accepting requests... \
           attempt %i of %i"
          i max_tries ;
        let ( >>= ) = Rresult.( >>= ) in
        (* if we don't remove krbtgt from the cache before
           query subject information about krbtgt, then
           [ try_fetch_sid ] would erroneously return success
           in the case that PBIS is running locally, but the
           AD domain is offline *)
        match try_clear_cache () >>= try_fetch_sid with
        | Error () ->
            Thread.delay 5.0 ;
            (go [@tailcall]) (i + 1)
        | Ok () ->
            true
      )
    in
    go 0

  let is_pbis_server_available ~__context max =
    Locking_helpers.Named_mutex.execute mutex_check_availability (fun () ->
        _is_pbis_server_available ~__context max
    )

  (* converts from domain.com\user to user@domain.com, in case domain.com is present in the subject_name *)
  let convert_nt_to_upn_username subject_name =
    try
      (* test if the NT account name separator \ is present in subject name *)
      let i = String.index subject_name '\\' in
      (* we only reach this point if the separator \ is present in subject_name *)
      (* when \ is present, we need to convert the NT name to UPN format *)
      let domain = String.sub subject_name 0 i in
      let user =
        String.sub subject_name (i + 1) (String.length subject_name - i - 1)
      in
      user ^ "@" ^ domain
    with Not_found ->
      (* if no NT username separator \ was found *)
      (* nothing to do in this case *)
      subject_name

  (* unit on_enable(((string*string) list) config_params)

      Called internally by xapi _on each host_ when a client enables an external auth service for the
      pool via the XenAPI [see AD integration wiki page]. The config_params here are the ones passed
      by the client as part of the corresponding XenAPI call.
      On receiving this hook, the auth module should:
      (i) do whatever it needs to do (if anything) to register with the external auth/directory
          service [using the config params supplied to get access]
      (ii) Write the config_params that it needs to store persistently in the XenServer metadata
          into the Pool.external_auth_configuration field. [Note - the rationale for making the plugin
          write the config params it needs long-term into the XenServer metadata itself is so it can
          explicitly filter any one-time credentials [like AD username/password for example] that it
          does not need long-term.]
  *)
  let on_enable ~__context config_params =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in
    (* but in the ldap plugin, we should 'join the AD/kerberos domain', i.e. we should*)
    (* basically: (1) create a machine account in the kerberos realm,*)
    (* (2) store the machine account password somewhere locally (in a keytab) *)
    start_damon () ;
    if
      not
        (List.mem_assoc "user" config_params
        && List.mem_assoc "pass" config_params
        )
    then
      raise
        (Auth_signature.Auth_service_error
           ( Auth_signature.E_GENERIC
           , "enable requires two config params: user and pass."
           )
        )
    else (* we have all the required parameters *)
      let hostname =
        Server_helpers.exec_with_new_task "retrieving hostname"
          (fun __context ->
            let host = Helpers.get_localhost ~__context in
            Db.Host.get_hostname ~__context ~self:host
        )
      in
      if
        String.fold_left (fun b ch -> b && ch >= '0' && ch <= '9') true hostname
      then
        raise
          (Auth_signature.Auth_service_error
             ( Auth_signature.E_GENERIC
             , Printf.sprintf "hostname '%s' cannot contain only digits."
                 hostname
             )
          )
      else
        let domain =
          let service_name =
            Server_helpers.exec_with_new_task
              "retrieving external_auth_service_name" (fun __context ->
                let host = Helpers.get_localhost ~__context in
                Db.Host.get_external_auth_service_name ~__context ~self:host
            )
          in
          if
            List.mem_assoc "domain" config_params
            (* legacy test: do we have domain name in config? *)
          then (* then config:domain must match service-name *)
            let _domain = List.assoc "domain" config_params in
            if service_name <> _domain then
              raise
                (Auth_signature.Auth_service_error
                   ( Auth_signature.E_GENERIC
                   , "if present, config:domain must match service-name."
                   )
                )
            else
              service_name
          else
            (* if no config:domain provided, we simply use the string in service_name for the domain name *)
            service_name
        in
        let _user = List.assoc "user" config_params in
        let pass = List.assoc "pass" config_params in
        let ou_conf, ou_params =
          if List.mem_assoc "ou" config_params then
            let ou = List.assoc "ou" config_params in
            ([("ou", ou)], ["--ou"; ou])
          else
            ([], [])
        in
        (* Adding the config parameter "config:disable_modules=X,Y,Z"
         * will disable the modules X, Y and Z in domainjoin-cli. *)
        let disabled_modules =
          try
            match List.assoc "disable_modules" config_params with
            | "" ->
                []
            | disabled_modules_string ->
                String.split_f (fun c -> c = ',') disabled_modules_string
          with Not_found -> []
        in
        let disabled_module_params =
          List.concat_map
            (fun disabled_module -> ["--disable"; disabled_module])
            disabled_modules
        in
        (* we need to make sure that the user passed to domaijoin-cli command is in the UPN syntax (user@domain.com) *)
        let user = convert_nt_to_upn_username _user in
        (* execute the pbis domain join cmd *)
        try
          let (_ : (string * string) list) =
            [
              ["join"]
            ; ou_params
            ; disabled_module_params
            ; ["--ignore-pam"; "--notimesync"; domain; user]
            ]
            |> List.concat
            |> pbis_common_with_password pass !Xapi_globs.domain_join_cli_cmd
          in
          let max_tries = 60 in
          (* tests 60 x 5.0 seconds = 300 seconds = 5minutes trying *)
          if not (is_pbis_server_available ~__context max_tries) then (
            let errmsg =
              Printf.sprintf
                "External authentication server not available after %i query \
                 tests"
                max_tries
            in
            debug "%s" errmsg ;
            raise
              (Auth_signature.Auth_service_error
                 (Auth_signature.E_UNAVAILABLE, errmsg)
              )
          ) ;
          (* OK SUCCESS, pbis has joined the AD domain successfully *)
          (* write persistently the relevant config_params in the host.external_auth_configuration field *)
          (* we should not store the user's (admin's) password !! *)
          let extauthconf = [("domain", domain); ("user", user)] @ ou_conf in
          Server_helpers.exec_with_new_task
            "storing external_auth_configuration" (fun __context ->
              let host = Helpers.get_localhost ~__context in
              Db.Host.set_external_auth_configuration ~__context ~self:host
                ~value:extauthconf ;
              debug "added external_auth_configuration for host %s"
                (Db.Host.get_name_label ~__context ~self:host)
          ) ;
          with_lock cache_of_pbis_common_m (fun _ -> cache_of_pbis_common := []) ;
          ensure_pbis_configured ()
        with e ->
          (*ERROR, we didn't join the AD domain*)
          debug
            "Error enabling external authentication for domain %s and user %s: \
             %s"
            domain user
            (ExnHelper.string_of_exn e) ;
          raise e

  (* unit on_disable()

      Called internally by xapi _on each host_ when a client disables an auth service via the XenAPI.
      The hook will be called _before_ the Pool configuration fields relating to the external-auth
      service are cleared (i.e. so you can access the config params you need from the pool metadata
      within the body of the on_disable method)
  *)
  let on_disable ~__context config_params =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in
    (* but in the ldap plugin, we should 'leave the AD/kerberos domain', i.e. we should *)
    (* (1) remove the machine account from the kerberos realm, (2) remove the keytab locally *)
    let pbis_failure =
      try
        ( if
            not
              (List.mem_assoc "user" config_params
              && List.mem_assoc "pass" config_params
              )
          then
            (* no windows admin+pass have been provided: leave the pbis host in the AD database *)
            (* execute the pbis domain-leave cmd *)
            (* this function will raise an exception if something goes wrong *)
            let (_ : (string * string) list) =
              pbis_common !Xapi_globs.domain_join_cli_cmd ["leave"]
            in
            ()
          else
            (* windows admin+pass have been provided: ask pbis to remove host from AD database *)
            let _user = List.assoc "user" config_params in
            let pass = List.assoc "pass" config_params in
            (* we need to make sure that the user passed to domaijoin-cli command is in the UPN syntax (user@domain.com) *)
            let user =
              convert_nt_to_upn_username
                (get_full_subject_name ~use_nt_format:false _user)
            in
            (* execute the pbis domain-leave cmd *)
            (* this function will raise an exception if something goes wrong *)
            let (_ : (string * string) list) =
              pbis_common_with_password pass
                !Xapi_globs.domain_join_cli_cmd
                ["leave"; user]
            in
            ()
        ) ;
        None (* no failure observed in pbis *)
      with e ->
        (* unexpected error disabling pbis *)
        debug "Internal Pbis error when disabling external authentication: %s"
          (ExnHelper.string_of_exn e) ;
        (* CA-27627: we should NOT re-raise the exception e here, because otherwise we might get stuck, *)
        (* without being able to disable an external authentication configuration, since the Pbis *)
        (* behavior is outside our control. For instance, Pbis raises an exception during domain-leave *)
        (* when the domain controller is offline, so it would be impossible to leave a domain that *)
        (* has already been deleted. *)
        (* Not re-raising an exception here is not too bad, because both ssh and xapi access to the AD/Pbis *)
        (* commands will be disabled anyway by host.disable_external_auth. So, even though access to the external *)
        (* authentication service might still be possible from Dom0 shell, it will not be possible *)
        (* to login as an external user via ssh or to call external-authentication services via xapi/xe. *)
        Some e
      (* CA-28942: stores exception returned by pbis for later *)
    in
    (* We always do a manual clean-up of pbis, in order to restore Dom0 to its pre-pbis state *)
    (* It doesn't matter if pbis succeeded or not *)
    (* This disables Pbis even from Dom0 shell *)
    debug "Doing a manual Pbis domain-leave cleanup..." ;
    (* When pbis raises an exception during domain-leave, we try again, using *)
    (* some of the command-line workarounds that Kyle describes in CA-27627: *)
    let pbis_force_domain_leave_script =
      "/opt/xensource/libexec/pbis-force-domain-leave"
    in
    ( try
        let output, stderr =
          Forkhelpers.execute_command_get_output pbis_force_domain_leave_script
            []
        in
        debug "execute %s: stdout=[%s],stderr=[%s]"
          pbis_force_domain_leave_script
          (String.replace "\n" ";" output)
          (String.replace "\n" ";" stderr)
      with e ->
        debug "exception executing %s: %s" pbis_force_domain_leave_script
          (ExnHelper.string_of_exn e)
    ) ;
    (* OK SUCCESS, pbis has left the AD domain successfully *)
    (* remove persistently the relevant config_params in the host.external_auth_configuration field *)
    Server_helpers.exec_with_new_task "removing external_auth_configuration"
      (fun __context ->
        let host = Helpers.get_localhost ~__context in
        Db.Host.set_external_auth_configuration ~__context ~self:host ~value:[] ;
        debug "removed external_auth_configuration for host %s"
          (Db.Host.get_name_label ~__context ~self:host)
    ) ;
    match pbis_failure with
    | None ->
        () (* OK, return unit*)
    | Some e ->
        raise e

  (* bubble up pbis failure *)

  (* unit on_xapi_initialize(bool system_boot)

      Called internally by xapi whenever it starts up. The system_boot flag is true iff xapi is
      starting for the first time after a host boot
  *)
  let on_xapi_initialize ~__context _system_boot =
    let@ __context = Context.with_tracing ~__context __FUNCTION__ in

    (* the AD server is initialized outside xapi, by init.d scripts *)

    (* this function is called during xapi initialization in xapi.ml *)

    (* make sure that the AD/LSASS server is responding before returning *)
    let max_tries = 12 in
    (* tests 12 x 5.0 seconds = 60 seconds = up to 1 minute trying *)
    if not (is_pbis_server_available ~__context max_tries) then (
      let errmsg =
        Printf.sprintf
          "External authentication server not available after %i query tests"
          max_tries
      in
      debug "%s" errmsg ;
      raise
        (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC, errmsg))
    ) ;
    ()

  (* unit on_xapi_exit()

      Called internally when xapi is doing a clean exit.
  *)
  let on_xapi_exit ~__context:_ () =
    (* nothing to do here in this unix plugin *)

    (* in the ldap plugin, we should remove the tgt ticket in /tmp/krb5cc_0 *)
    ()

  (* Implement the single value required for the module signature *)
  let methods =
    Auth_signature.
      {
        authenticate_username_password
      ; authenticate_ticket
      ; get_subject_identifier
      ; query_subject_information
      ; query_group_membership
      ; on_enable
      ; on_disable
      ; on_xapi_initialize
      ; on_xapi_exit
      }
end
