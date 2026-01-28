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
(* Copyright (C) 2007 XenSource Inc *)

module D = Debug.Make (struct let name = "stunnel" end)

open Printf
open Xapi_stdext_unix
open Safe_resources

exception Stunnel_binary_missing

exception Stunnel_error of string

exception Stunnel_verify_error of string list

(* Re-export types from Stunnel_log for convenience *)
type stunnel_error = Stunnel_log.stunnel_error =
  | Certificate_verify of string list
  | Stunnel of string
  | Unknown of string

let cached_stunnel_path = ref None

let stunnel_logger = ref ignore

let timeoutidle = ref None

let init_stunnel_path () =
  cached_stunnel_path :=
    Some
      ( match Sys.getenv_opt "XE_STUNNEL" with
      | Some "stunnel" ->
          "/usr/bin/stunnel"
      | Some "stunnel4" ->
          "/usr/bin/stunnel4"
      | _ ->
          if Sys.file_exists "/usr/bin/stunnel4" then
            "/usr/bin/stunnel4"
          else if Sys.file_exists "/usr/bin/stunnel" then
            "/usr/bin/stunnel"
          else
            "/usr/bin/stunnel"
      )

let crl_path = "/etc/stunnel/crl"

let stunnel_path () =
  (match !cached_stunnel_path with None -> init_stunnel_path () | Some _ -> ()) ;
  Option.get !cached_stunnel_path

module Unsafe = struct
  (** These functions are not safe in a multithreaded program *)

  (* Low-level (unsafe) function which forks, runs a 'pre_exec' function and
     	 then executes some other binary. It makes sure to catch any exception thrown by
     	 exec* so that we don't end up with two ocaml processes. *)
  let fork_and_exec ?(pre_exec = fun () -> ()) ?env argv0 (args : string list) =
    let args = Array.of_list (argv0 :: args) in
    let pid = Unix.fork () in
    if pid = 0 then
      try
        pre_exec () ;
        (* CA-18955: xapi now runs with priority -3. We then set his sons priority to 0. *)
        ignore (Unix.nice (-Unix.nice 0) : int) ;
        ignore (Unix.setsid () : int) ;
        match env with
        | None ->
            Unix.execv argv0 args
        | Some env ->
            Unix.execve argv0 args env
      with _ -> exit 1
    else
      pid

  (* File descriptor operations to be performed after a fork.
   * These are all safe in the presence of threads *)
  type fd_operation = Dup2 of Unix.file_descr * Unix.file_descr

  let do_fd_operation = function Dup2 (a, b) -> Unix.dup2 a b
end

type pid =
  | StdFork of int  (** we forked and exec'ed. This is the pid *)
  | FEFork of Forkhelpers.pidty  (** the forkhelpers module did it for us. *)
  | Nopid

let getpid ty =
  match ty with
  | StdFork pid ->
      pid
  | FEFork pid ->
      Forkhelpers.getpid pid
  | Nopid ->
      failwith "No pid!"

type verify = VerifyPeer | CheckHost

type verification_config = {
    sni: string option
  ; verify: verify
  ; cert_bundle_path: string
}

type t = {
    mutable pid: pid
  ; fd: Unixfd.t
  ; host: string
  ; port: int
  ; connected_time: float
  ; unique_id: int option
  ; mutable logfile: string
  ; verified: verification_config option
}

let appliance =
  {
    sni= None
  ; verify= CheckHost
  ; cert_bundle_path= "/etc/stunnel/xapi-stunnel-ca-bundle.pem"
  }

let pool =
  {
    sni= Some "pool"
  ; verify= VerifyPeer
  ; cert_bundle_path= "/etc/stunnel/xapi-pool-ca-bundle.pem"
  }

let external_host ext_host_cert_file =
  {sni= None; verify= VerifyPeer; cert_bundle_path= ext_host_cert_file}

let debug_conf_of_bool verbose : string =
  if verbose then
    "debug=authpriv.7"
  else
    "debug=authpriv.5"

let debug_conf_of_env () : string =
  Option.value (Sys.getenv_opt "debug_stunnel") ~default:""
  |> String.lowercase_ascii
  |> fun x -> List.mem x ["yes"; "true"; "1"] |> debug_conf_of_bool

let config_file ?(accept = None) config host port =
  ( match config with
  | None ->
      D.debug "client cert verification %s:%d: None" host port
  | Some {sni= Some x; cert_bundle_path; _} ->
      D.debug "client cert verification %s:%d: SNI=%s path=%s" host port x
        cert_bundle_path
  | Some {sni= None; cert_bundle_path; _} ->
      D.debug "client cert verification %s:%d: path=%s" host port
        cert_bundle_path
  ) ;
  let is_fips =
    Inventory.inventory_filename := "/etc/xensource-inventory" ;
    try bool_of_string (Inventory.lookup ~default:"false" "CC_PREPARATIONS")
    with _ -> false
  in
  String.concat "\n"
  @@ List.concat
       [
         [
           "client=yes"
         ; "foreground=yes"
         ; "socket = r:TCP_NODELAY=1"
         ; "socket = r:SO_KEEPALIVE=1"
         ; "socket = a:SO_KEEPALIVE=1"
         ; ( match !timeoutidle with
           | None ->
               ""
           | Some x ->
               Printf.sprintf "TIMEOUTidle = %d" x
           )
         ]
       ; ( if is_fips then
             ["fips=yes"]
           else
             ["fips=no"]
         )
       ; [debug_conf_of_env ()]
       ; ( match accept with
         | Some (`Local_host_port (h, p)) ->
             [
               "[client-proxy]"
             ; Printf.sprintf "accept=%s:%s" h (string_of_int p)
             ]
         | Some (`Unix_socket_path path) ->
             ["[client-proxy]"; Printf.sprintf "accept=%s" path]
         | None ->
             []
         )
       ; [Printf.sprintf "connect=%s:%d" host port]
       ; [
           "sslVersion = TLSv1.2"
         ; "ciphers = " ^ Constants.good_ciphersuites
         ; "curve = secp384r1"
         ]
       ; ( match config with
         | None ->
             []
         | Some {sni; verify; cert_bundle_path} ->
             List.rev_append
               ( match verify with
               | VerifyPeer ->
                   ["verifyPeer=yes"]
               | CheckHost ->
                   [sprintf "checkHost=%s" host; "verifyChain=yes"]
               )
               [
                 ""
               ; "# use SNI to request a specific cert. CAfile contains"
               ; "# public certs of all hosts in the pool and must contain"
               ; "# the cert of the server we connect to"
               ; (match sni with None -> "" | Some s -> sprintf "sni = %s" s)
               ; sprintf "CAfile=%s" cert_bundle_path
               ; ( match Sys.readdir crl_path with
                 | [||] ->
                     ""
                 | _ ->
                     sprintf "CRLpath=%s" crl_path
                 | exception _ ->
                     ""
                 )
               ]
         )
       ; [""]
       ]

let ignore_exn f x = try f x with _ -> ()

let disconnect_with_pid ?(wait = true) ?(force = false) pid =
  let do_disc waiter pid =
    let res =
      try waiter ()
      with Unix.Unix_error (Unix.ECHILD, _, _) -> (pid, Unix.WEXITED 0)
    in
    match res with
    | 0, _ when force -> (
      try Unix.kill pid Sys.sigkill
      with Unix.Unix_error (Unix.ESRCH, _, _) -> ()
    )
    | _ ->
        ()
  in
  match pid with
  | FEFork fpid ->
      let pid_int = Forkhelpers.getpid fpid in
      do_disc
        (fun () ->
          ( if wait then
              Forkhelpers.waitpid
            else
              Forkhelpers.waitpid_nohang
          )
            fpid
        )
        pid_int
  | StdFork pid ->
      do_disc
        (fun () ->
          ( if wait then
              Unix.waitpid []
            else
              Unix.waitpid [Unix.WNOHANG]
          )
            pid
        )
        pid
  | Nopid ->
      ()

let disconnect ?(wait = true) ?(force = false) x =
  ignore_exn Unixfd.safe_close x.fd ;
  disconnect_with_pid ~wait ~force x.pid ;
  (* make disconnect idempotent, need to do it here,
     due to the recursive call *)
  x.pid <- Nopid

(* With some probability, stunnel fails during its startup code before it reads
   the config data from us. Therefore we get a SIGPIPE writing the config data.
   Assuming SIGPIPE has been ignored, catch the failing write and throw this
   exception instead *)
exception Stunnel_initialisation_failed

(* Internal function which may throw Stunnel_initialisation_failed *)
let attempt_one_connect ?(use_fork_exec_helper = true)
    ?(write_to_log = fun _ -> ()) ?(extended_diagnosis = false) data_channel
    verify_cert host port =
  Unixfd.with_pipe () ~loc:__LOC__ @@ fun config_out config_in ->
  let config_out_uuid = Uuidx.(to_string (make ())) in
  let config_out_fd =
    string_of_int (Unixext.int_of_file_descr Unixfd.(!config_out))
  in
  let configs = [(config_out_uuid, Unixfd.(!config_out))] in
  let args =
    [
      "-fd"
    ; ( if use_fork_exec_helper then
          config_out_uuid
        else
          config_out_fd
      )
    ]
  in
  let start sock_of_stunnel config =
    Forkhelpers.with_logfile_fd "stunnel" ~delete:(not extended_diagnosis)
      (fun logfd ->
        let path = stunnel_path () in
        let fds_needed, fdops, sock =
          match sock_of_stunnel with
          | Some s ->
              ( [Unixfd.(!config_out); Unix.stdin; Unix.stdout; Unix.stderr]
              , [
                  Unsafe.Dup2 (Unixfd.(!s), Unix.stdin)
                ; Unsafe.Dup2 (Unixfd.(!s), Unix.stdout)
                ; Unsafe.Dup2 (logfd, Unix.stderr)
                ]
              , Some Unixfd.(!s)
              )
          | None ->
              ([], [], None)
        in
        let pid =
          if use_fork_exec_helper || Option.is_none sock_of_stunnel then
            FEFork
              (Forkhelpers.safe_close_and_exec sock sock (Some logfd) configs
                 path args
              )
          else
            StdFork
              (Unsafe.fork_and_exec
                 ~pre_exec:(fun _ ->
                   List.iter Unsafe.do_fd_operation fdops ;
                   Unixext.close_all_fds_except fds_needed
                 )
                 path args
              )
        in
        Unixfd.safe_close config_out ;
        (* The sock_of_stunnel has been passed to stunnel process. Close it in XAPI *)
        Option.iter (fun s -> Unixfd.safe_close s) sock_of_stunnel ;
        (* Catch the occasional initialisation failure of stunnel: *)
        try
          let len = String.length config in
          let n =
            Unix.write Unixfd.(!config_in) (Bytes.of_string config) 0 len
          in
          if n < len then (
            disconnect_with_pid ~wait:false ~force:true pid ;
            raise Stunnel_initialisation_failed
          ) ;
          Unixfd.safe_close config_in ;
          pid
        with Unix.Unix_error (err, fn, arg) ->
          write_to_log
            (Printf.sprintf
               "Caught Unix.Unix_error(%s, %s, %s); raising \
                Stunnel_initialisation_failed"
               (Unix.error_message err) fn arg
            ) ;
          disconnect_with_pid ~wait:false ~force:true pid ;
          raise Stunnel_initialisation_failed
    )
  in
  let result =
    match data_channel with
    | `Local_host_port (h, p) ->
        (* The stunnel will listen on a local host and port *)
        let config =
          config_file
            ~accept:(Some (`Local_host_port (h, p)))
            verify_cert host port
        in
        start None config
    | `Unix_socket s ->
        (* The stunnel will listen on a UNIX socket *)
        let config = config_file verify_cert host port in
        start (Some s) config
    | `Unix_socket_path path ->
        (* The stunnel will listen on a UNIX socket path *)
        let config =
          config_file
            ~accept:(Some (`Unix_socket_path path))
            verify_cert host port
        in
        start None config
  in
  (* Tidy up any remaining unclosed fds *)
  match result with
  | Forkhelpers.Success (log, pid) ->
      if extended_diagnosis then write_to_log "stunnel start" ;
      (pid, log)
  | Forkhelpers.Failure (log, exn) ->
      write_to_log ("stunnel abort: Log from stunnel: [" ^ log ^ "]") ;
      raise exn

(** To cope with a slightly unreliable stunnel, attempt to retry to make
    the connection a number of times. *)
let rec retry f = function
  | 0 ->
      raise Stunnel_initialisation_failed
  | n -> (
    try f ()
    with Stunnel_initialisation_failed ->
      (* Leave a few seconds between each attempt *)
      Thread.delay 3. ;
      retry f (n - 1)
  )

(** Establish a fresh stunnel to a (host, port)
    @param extended_diagnosis If true, the stunnel log file will not be
    deleted.  Instead, it is the caller's responsibility to delete it.  This
    allows the caller to use diagnose_failure below if stunnel fails.  *)
let with_connect ?unique_id ?use_fork_exec_helper ?write_to_log ~verify_cert
    ?(extended_diagnosis = false) host port f =
  let _ =
    match write_to_log with
    | Some logger ->
        stunnel_logger := logger
    | None ->
        ()
  in
  retry
    (fun () ->
      Unixfd.with_socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 ~loc:__LOC__
      @@ fun sock_of_stunnel sock_of_xapi ->
      let pid, logfile =
        attempt_one_connect ?use_fork_exec_helper ?write_to_log
          ~extended_diagnosis (`Unix_socket sock_of_stunnel) verify_cert host
          port
      in
      D.debug "Started a client (pid:%s): -> %s:%s"
        (string_of_int (getpid pid))
        host (string_of_int port) ;
      let t =
        {
          pid
        ; fd= sock_of_xapi
        ; host
        ; port
        ; connected_time= Unix.gettimeofday ()
        ; unique_id
        ; logfile
        ; verified= verify_cert
        }
      in
      f t
    )
    5

let with_client_proxy_systemd_service ~verify_cert ~remote_host ~remote_port
    ~local_host ~local_port ~service f =
  let cmd_path = stunnel_path () in
  let config =
    config_file
      ~accept:(Some (`Local_host_port (local_host, local_port)))
      verify_cert remote_host remote_port
  in
  let stop () = ignore (Fe_systemctl.stop ~service) in
  (* Try stopping anyway before starting it. *)
  ignore_exn stop () ;
  let conf_path, out = Filename.open_temp_file service ".conf" in
  let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
  finally
    (fun () ->
      finally (fun () -> output_string out config) (fun () -> close_out out) ;
      finally
        (fun () ->
          Fe_systemctl.start_transient ~service cmd_path [conf_path] ;
          f ()
        )
        (fun () -> ignore_exn stop ())
    )
    (fun () -> Unixext.unlink_safe conf_path)

(** Old exception-based function kept for public API compatibility. *)
let diagnose_failure st_proc =
  let module Scanner = Stunnel_log.Make (struct
    let logfile = st_proc.logfile

    let logger = fun _ -> ()
  end) in
  match Scanner.check_errors () with
  | Ok () ->
      ()
  | Error (Certificate_verify reasons) ->
      raise (Stunnel_verify_error reasons)
  | Error (Stunnel reason) ->
      raise (Stunnel_error reason)
  | Error (Unknown reason) ->
      failwith reason

let wait_for_init_done unix_socket_path logfile =
  let module Scanner = Stunnel_log.Make (struct
    let logfile = logfile

    let logger = fun _ -> ()
  end) in
  let patterns =
    Stunnel_log.Patterns.
      [
        configuration_successful
      ; configuration_failed
      ; certificate_verify_failed
      ; connection_refused
      ; no_host_resolved
      ; no_route_to_host
      ; invalid_argument
      ; address_in_use
      ]
  in
  let rec check ~max_retries cnt =
    Thread.delay 1.0 ;
    match
      (Sys.file_exists unix_socket_path, Scanner.scan_with_cert_context patterns)
    with
    | true, Ok (`Success _) ->
        Ok ()
    | _, Error err ->
        Error err
    | _, _ when cnt > max_retries ->
        Error (Stunnel "Timed out when initialising stunnel")
    | _, _ ->
        check ~max_retries (cnt + 1)
  in
  check ~max_retries:3 0

let wait_for_connection_done logfile =
  let module Scanner = Stunnel_log.Make (struct
    let logfile = logfile

    let logger = fun _ -> ()
  end) in
  let patterns =
    Stunnel_log.Patterns.
      [
        certificate_accepted
      ; rejected_by_cert
      ; connected_remote_server
      ; certificate_verify_failed
      ; connection_refused
      ; no_host_resolved
      ; no_route_to_host
      ; invalid_argument
      ; address_in_use
      ]
  in
  let rec check ~max_retries cnt =
    Thread.delay 0.5 ;
    match Scanner.scan_with_cert_context patterns with
    | Ok (`Success _) ->
        Ok ()
    | Error err ->
        Error err
    | _ when cnt > max_retries ->
        Error (Stunnel "Timed out waiting for connection attempt")
    | _ ->
        check ~max_retries (cnt + 1)
  in
  check ~max_retries:10 0

module UnixSocketProxy = struct
  (** Handle for a long-running stunnel proxy *)
  type t = {
      proxy_pid: pid
    ; proxy_socket_path: string
    ; proxy_logfile: string
    ; mutable last_checked_position: int
  }

  let socket_path handle = handle.proxy_socket_path

  (** Generate a unique UNIX socket path for the stunnel proxy *)
  let generate_socket_path ~remote_host ~remote_port =
    let uuid = Uuidx.(to_string (make ())) in
    Printf.sprintf "/tmp/stunnel-proxy-%s-%d-%s.sock" remote_host remote_port
      uuid

  (** Diagnose the status of a running stunnel proxy by checking its logfile.
      Only checks new log entries since the last call to diagnose.
      Updates the last_checked_position after checking.
      Returns Ok () if no errors found, Error with details otherwise. *)
  let diagnose handle =
    let start_pos = handle.last_checked_position in
    let current_size = (Unix.stat handle.proxy_logfile).Unix.st_size in

    if current_size <= start_pos then (
      D.debug "%s: no new log entries (position %d)" __FUNCTION__ start_pos ;
      Ok ()
    ) else (
      D.debug "%s: checking log from position %d to %d" __FUNCTION__ start_pos
        current_size ;
      (* Print new log content for debugging *)
      let fd = Unix.openfile handle.proxy_logfile [Unix.O_RDONLY] 0 in
      let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
      finally
        (fun () ->
          let _ = Unix.lseek fd start_pos Unix.SEEK_SET in
          let len = current_size - start_pos in
          let buf = Bytes.create len in
          let n = Unix.read fd buf 0 len in
          if n > 0 then
            D.debug "%s: new log content:\n%s" __FUNCTION__
              (Bytes.sub_string buf 0 n)
        )
        (fun () -> Unix.close fd) ;
      let module Scanner = Stunnel_log.Make (struct
        let logfile = handle.proxy_logfile

        let logger = fun _ -> ()
      end) in
      match Scanner.check_errors_from_position start_pos with
      | Ok () ->
          handle.last_checked_position <- current_size ;
          Ok ()
      | Error _ as e ->
          handle.last_checked_position <- current_size ;
          e
    )

  (** Start a long-running stunnel proxy listening on a UNIX socket.
      Returns Ok handle that must be explicitly stopped with [stop].
      The stunnel process will continue running until stopped, allowing
      multiple clients to connect to the UNIX socket over time.
      If [unix_socket_path] is not provided, a unique path will be generated.
      If [socket_mode] is provided (e.g., 0o600), the socket file permissions
      will be set accordingly after creation.

      This function performs initial certificate verification by making a test
      connection. If certificate verification fails, returns Error and the proxy
      is not started. If successful, subsequent connections by stubs will also
      be verified automatically by stunnel. *)
  let start ~verify_cert ~remote_host ~remote_port ?unix_socket_path
      ?socket_mode () =
    let ( let* ) = Result.bind in
    let unix_socket_path =
      match unix_socket_path with
      | Some path ->
          path
      | None ->
          generate_socket_path ~remote_host ~remote_port
    in
    Unixext.unlink_safe unix_socket_path ;
    let write_to_log = D.debug "%s: %s" __FUNCTION__ in

    (* Helper: convert exceptions to Results *)
    let try_result f =
      try Ok (f ()) with
      | Stunnel_initialisation_failed ->
          Error (Stunnel "Stunnel initialisation failed")
      | Stunnel_error reason ->
          Error (Stunnel reason)
      | Stunnel_verify_error reasons ->
          Error (Certificate_verify reasons)
      | exn ->
          Error (Unknown (Printexc.to_string exn))
    in

    (* Phase 0: Start stunnel process *)
    let* pid, logfile =
      try_result (fun () ->
          attempt_one_connect ~write_to_log ~extended_diagnosis:true
            (`Unix_socket_path unix_socket_path) verify_cert remote_host
            remote_port
      )
    in

    (* From here on, we must clean up if anything fails *)
    let cleanup_all () =
      disconnect_with_pid ~wait:false ~force:true pid ;
      Unixext.unlink_safe unix_socket_path ;
      Unixext.unlink_safe logfile
    in

    (* Phase 1: Wait for initialization *)
    let* () =
      wait_for_init_done unix_socket_path logfile
      |> Result.map_error (fun e ->
          D.debug "%s: stunnel initialization failed" __FUNCTION__ ;
          cleanup_all () ;
          e
      )
    in

    (* Set socket permissions if requested *)
    let* () =
      try_result (fun () ->
          Option.iter
            (fun mode ->
              D.debug "chmod %s to %o" unix_socket_path mode ;
              Unix.chmod unix_socket_path mode
            )
            socket_mode
      )
      |> Result.map_error (fun e -> cleanup_all () ; e)
    in

    D.debug "%s: started stunnel proxy (pid:%d):%s -> %s:%d log: %s"
      __FUNCTION__ (getpid pid) unix_socket_path remote_host remote_port logfile ;

    (* Create handle *)
    let handle =
      {
        proxy_pid= pid
      ; proxy_socket_path= unix_socket_path
      ; proxy_logfile= logfile
      ; last_checked_position= 0
      }
    in

    (* Phase 2: Test connection and wait for TLS handshake *)
    let* () =
      let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
      let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
      let result =
        finally
          (fun () ->
            Unix.connect sock (Unix.ADDR_UNIX unix_socket_path) ;
            wait_for_connection_done logfile
          )
          (fun () -> Unix.close sock)
      in
      result
      |> Result.map_error (fun e ->
          D.debug "%s: connection verification failed" __FUNCTION__ ;
          cleanup_all () ;
          e
      )
    in

    D.debug "%s: initial certificate verification passed" __FUNCTION__ ;
    Ok handle

  let print_log handle =
    let log = Unixext.string_of_file handle.proxy_logfile in
    D.debug "%s: stunnel proxy log:\n%s" __FUNCTION__ log

  (** Stop a running stunnel proxy and clean up resources.
      This kills the stunnel process and removes the socket and log files. *)
  let stop handle =
    print_log handle ;
    disconnect_with_pid ~wait:false ~force:true handle.proxy_pid ;
    Unixext.unlink_safe handle.proxy_socket_path ;
    Unixext.unlink_safe handle.proxy_logfile ;
    D.debug "%s: stopped stunnel proxy (pid:%d):%s" __FUNCTION__
      (getpid handle.proxy_pid) handle.proxy_socket_path

  (** Start a proxy, execute a function with it, and automatically stop it.
      The proxy is guaranteed to be stopped even if the function raises an exception.
      If [unix_socket_path] is not provided, a unique path will be generated.
      If [socket_mode] is provided, stunnel will set the socket file permissions.
      This is the preferred way to use the proxy for most use cases. *)
  let with_proxy ~verify_cert ~remote_host ~remote_port ?unix_socket_path
      ?socket_mode f =
    match
      start ~verify_cert ~remote_host ~remote_port ?unix_socket_path
        ?socket_mode ()
    with
    | Error _ as e ->
        e
    | Ok handle ->
        let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
        finally (fun () -> f handle) (fun () -> stop handle)
end

(** Fetch the server certificate from a remote host.
    Uses openssl s_client to connect and retrieve the certificate in PEM format.
    This is useful for TOFU (Trust-On-First-Use) scenarios. *)
let fetch_server_cert ~remote_host ~remote_port =
  try
    let openssl = !Constants.openssl_path in
    (* First get the certificate with s_client *)
    let s_client_args =
      [
        "s_client"
      ; "-connect"
      ; Printf.sprintf "%s:%d" remote_host remote_port
      ; "-showcerts"
      ]
    in
    let cert_output, _ =
      Forkhelpers.execute_command_get_output_send_stdin openssl s_client_args ""
    in
    (* Then parse it with x509 to get PEM format *)
    let x509_args = ["x509"; "-outform"; "PEM"] in
    let pem_output, _ =
      Forkhelpers.execute_command_get_output_send_stdin openssl x509_args
        cert_output
    in
    if
      String.length pem_output > 0
      && Astring.String.is_infix ~affix:"BEGIN CERTIFICATE" pem_output
    then
      Some (String.trim pem_output)
    else
      None
  with _ -> None

(* If we reach here the whole stunnel log should have been gone through
   (possibly printed/logged somewhere. No necessity to raise an exception,
   since when this function being called, there is usually some exception
   already existing in the caller's context, and it's not necessary always a
   stunnel error.
*)

let test host port =
  let counter = ref 0 in
  while true do
    with_connect ~write_to_log:print_endline host ~verify_cert:None port
      disconnect ;
    incr counter ;
    if !counter mod 100 = 0 then (
      Printf.printf "Ran stunnel %d times\n" !counter ;
      flush stdout
    )
  done

let move_out_exn t = {t with fd= Safe.move_exn t.fd}

let with_moved_exn t f =
  Safe.within (Safe.move_exn t.fd) @@ fun fd -> f {t with fd}

let safe_release t = disconnect ~wait:false ~force:true t
