(*
 * Copyright (C) 2025 Cloud Software Group
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

let test_unix_socket_path remote_host remote_port verify_cert timeout =
  let socket_path = "/tmp/test_stunnel_socket.sock" in
  Printf.printf "→ Connecting to %s:%d via unix socket %s\n" remote_host
    remote_port socket_path ;
  ( match verify_cert with
  | None ->
      Printf.printf "→ Certificate verification: DISABLED\n"
  | Some {Stunnel.sni; verify; cert_bundle_path} ->
      Printf.printf "→ Certificate verification: ENABLED\n" ;
      Printf.printf "  - SNI: %s\n"
        (match sni with Some s -> s | None -> "(none)") ;
      Printf.printf "  - Mode: %s\n"
        ( match verify with
        | Stunnel.VerifyPeer ->
            "VerifyPeer (pinning)"
        | Stunnel.CheckHost ->
            "CheckHost (chain validation)"
        ) ;
      Printf.printf "  - Cert bundle: %s\n" cert_bundle_path
  ) ;

  try
    Stunnel.with_client_proxy_unix_socket ~verify_cert ~remote_host ~remote_port
      ~unix_socket_path:socket_path (fun ~diagnose_stunnel ->
        Printf.printf "✓ Stunnel proxy started successfully\n" ;

        (* Try to send data through the socket *)
        if Sys.file_exists socket_path then (
          Printf.printf "→ Sending 'hello' through unix socket...\n" ;
          try
            let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
            Unix.connect sock (Unix.ADDR_UNIX socket_path) ;
            let msg = "hello\n" in
            let sent = Unix.send_substring sock msg 0 (String.length msg) [] in
            Printf.printf "✓ Sent %d bytes through socket\n" sent ;

            (* Try to read response *)
            let buf = Bytes.create 1024 in
            let _ = Unix.setsockopt_float sock Unix.SO_RCVTIMEO timeout in
            ( try
                let n = Unix.recv sock buf 0 1024 [] in
                if n > 0 then
                  Printf.printf "✓ Received %d bytes: %s\n" n
                    (Bytes.sub_string buf 0 n)
                else
                  Printf.printf "→ Connection closed by remote\n"
              with
              | Unix.Unix_error (Unix.EAGAIN, _, _)
              | Unix.Unix_error (Unix.EWOULDBLOCK, _, _)
              ->
                Printf.printf "→ No response received (timeout)\n"
            ) ;
            Unix.close sock
          with e ->
            Printf.printf "✗ Socket communication error: %s\n"
              (Printexc.to_string e)
        ) ;
        match diagnose_stunnel () with
        | Ok () ->
            Printf.printf "✓ Stunnel operation completed successfully\n"
        | Error (Stunnel.Certificate_verify reason) ->
            Printf.printf "✗ Certificate verification failed: %s\n" reason
        | Error (Stunnel.Stunnel reason) ->
            Printf.printf "✗ Stunnel error: %s\n" reason
        | Error (Stunnel.Unknown reason) ->
            Printf.printf "✗ Unknown error: %s\n" reason
    )
  with e -> Printf.printf "✗ Exception: %s\n" (Printexc.to_string e)

let () =
  let remote_host = ref "example.com" in
  let remote_port = ref 443 in
  let cert_bundle = ref None in
  let verify_mode = ref "none" in
  let sni = ref None in
  let timeout = ref 10.0 in

  let usage_msg =
    "test_stunnel [options]\n\
     Test stunnel unix socket proxy with optional certificate verification"
  in
  let speclist =
    [
      ( "--host"
      , Arg.Set_string remote_host
      , "Remote host (default: example.com)"
      )
    ; ("--port", Arg.Set_int remote_port, "Remote port (default: 443)")
    ; ( "--cert-bundle"
      , Arg.String (fun s -> cert_bundle := Some s)
      , "Path to PEM certificate bundle file"
      )
    ; ( "--verify"
      , Arg.Symbol (["none"; "peer"; "chain"], fun s -> verify_mode := s)
      , "Verification mode: none (default), peer (pinning), chain (with \
         --check-host)"
      )
    ; ( "--sni"
      , Arg.String (fun s -> sni := Some s)
      , "Server Name Indication hostname"
      )
    ; ( "--timeout"
      , Arg.Set_float timeout
      , "Socket receive timeout in seconds (default: 10.0)"
      )
    ]
  in

  Arg.parse speclist (fun _ -> ()) usage_msg ;

  let verify_cert =
    match (!verify_mode, !cert_bundle) with
    | "none", _ ->
        None
    | _, None ->
        Printf.eprintf
          "Error: --cert-bundle required when verification is enabled\n" ;
        exit 1
    | "peer", Some path ->
        Some
          {
            Stunnel.sni= !sni
          ; verify= Stunnel.VerifyPeer
          ; cert_bundle_path= path
          }
    | "chain", Some path ->
        Some
          {Stunnel.sni= !sni; verify= Stunnel.CheckHost; cert_bundle_path= path}
    | _ ->
        Printf.eprintf "Error: invalid verify mode\n" ;
        exit 1
  in

  test_unix_socket_path !remote_host !remote_port verify_cert !timeout
