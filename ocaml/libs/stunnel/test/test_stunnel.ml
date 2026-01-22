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

(** Test the new UnixSocketProxy API with auto-generated socket path *)
let test_unix_socket_proxy remote_host remote_port purpose timeout =
  Printf.printf "→ Testing UnixSocketProxy API\n" ;
  Printf.printf "→ Connecting to %s:%d with purpose '%s'\n" remote_host
    remote_port purpose ;

  try
    (* Test with_proxy (auto-generated path) *)
    let verify_cert = Stunnel_client.construct_cert_verification ~purpose in
    let result =
      Stunnel.UnixSocketProxy.with_proxy ~verify_cert ~remote_host ~remote_port
        (fun proxy ->
          let socket_path = Stunnel.UnixSocketProxy.socket_path proxy in
          Printf.printf "✓ Proxy started with auto-generated socket: %s\n"
            socket_path ;

          (* Try to send data through the socket *)
          if Sys.file_exists socket_path then (
            Printf.printf "→ Sending HTTP GET through unix socket...\n" ;
            try
              let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
              Unix.connect sock (Unix.ADDR_UNIX socket_path) ;
              let msg =
                Printf.sprintf "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" remote_host
              in
              let sent =
                Unix.send_substring sock msg 0 (String.length msg) []
              in
              Printf.printf "✓ Sent %d bytes through socket\n" sent ;

              (* Try to read response *)
              let buf = Bytes.create 1024 in
              let _ = Unix.setsockopt_float sock Unix.SO_RCVTIMEO timeout in
              ( try
                  let n = Unix.recv sock buf 0 1024 [] in
                  if n > 0 then
                    Printf.printf "✓ Received %d bytes: %s\n" n
                      (String.sub (Bytes.to_string buf) 0 (min n 100))
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
          Ok ()
      )
    in
    ( match result with
    | Ok () ->
        Printf.printf "✓ Test completed successfully\n"
    | Error _ ->
        Printf.printf "✗ Test completed with errors\n"
    ) ;
    Printf.printf "✓ Proxy stopped and cleaned up\n"
  with e -> Printf.printf "✗ Exception: %s\n" (Printexc.to_string e)

(** Test explicit start/stop lifecycle *)
let test_explicit_lifecycle remote_host remote_port purpose timeout =
  Printf.printf "\n→ Testing explicit start/stop lifecycle\n" ;

  (* Step 1: Fetch certificate and print *)
  Printf.printf "→ Step 1: Fetching server certificate from %s:%d\n" remote_host
    remote_port ;
  ( match Stunnel.fetch_server_cert ~remote_host ~remote_port with
  | None ->
      Printf.printf "✗ Failed to fetch certificate\n"
  | Some cert ->
      Printf.printf "✓ Certificate fetched successfully (%d bytes)\n"
        (String.length cert) ;
      let preview_len = min 200 (String.length cert) in
      Printf.printf "→ Certificate preview:\n%s\n"
        (String.sub cert 0 preview_len)
  ) ;

  (* Step 2: Starting proxy *)
  Printf.printf "\n→ Step 2: Starting proxy to %s:%d\n" remote_host remote_port ;
  let verify_cert = Stunnel_client.construct_cert_verification ~purpose in
  match
    Stunnel.UnixSocketProxy.start ~verify_cert ~remote_host ~remote_port ()
  with
  | Error err ->
      Printf.printf "✗ Failed to start proxy: %s\n"
        ( match err with
        | Stunnel.Certificate_verify reasons ->
            "Certificate_verify [" ^ String.concat "; " reasons ^ "]"
        | Stunnel.Stunnel reason ->
            "Stunnel: " ^ reason
        | Stunnel.Unknown reason ->
            "Unknown: " ^ reason
        )
  | Ok proxy -> (
      Printf.printf "✓ Proxy started at: %s\n"
        (Stunnel.UnixSocketProxy.socket_path proxy) ;

      (* Step 3: Send hello through socket *)
      Printf.printf "\n→ Step 3: Sending 'hello' through socket\n" ;
      let socket_path = Stunnel.UnixSocketProxy.socket_path proxy in
      ( try
          let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
          Unix.connect sock (Unix.ADDR_UNIX socket_path) ;
          let msg = "GET / HTTP/1.1\r\nHost: " ^ remote_host ^ "\r\n\r\n" in
          let sent = Unix.send_substring sock msg 0 (String.length msg) [] in
          Printf.printf "✓ Sent %d bytes through socket\n" sent ;

          (* Step 4: Receive response *)
          Printf.printf "\n→ Step 4: Receiving response\n" ;
          let buf = Bytes.create 1024 in
          Unix.setsockopt_float sock Unix.SO_RCVTIMEO timeout ;
          ( try
              let n = Unix.recv sock buf 0 1024 [] in
              if n > 0 then (
                let response = Bytes.sub_string buf 0 n in
                Printf.printf "✓ Received %d bytes\n" n ;
                let preview_len = min 200 (String.length response) in
                Printf.printf "→ Response preview:\n%s\n"
                  (String.sub response 0 preview_len)
              ) else
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

      (* Step 5: Diagnose proxy status *)
      Printf.printf "\n→ Step 5: Diagnosing proxy status\n" ;
      ( match Stunnel.UnixSocketProxy.diagnose proxy with
      | Ok () ->
          Printf.printf "✓ Proxy status OK (no errors in log)\n"
      | Error (Stunnel.Certificate_verify reasons) ->
          Printf.printf "✗ Certificate_verify [%s]\n"
            (String.concat "; " reasons)
      | Error (Stunnel.Stunnel reason) ->
          Printf.printf "✗ Stunnel error: %s\n" reason
      | Error (Stunnel.Unknown reason) ->
          Printf.printf "✗ Unknown error: %s\n" reason
      ) ;

      (* Step 6: Stop proxy *)
      Printf.printf "\n→ Step 6: Stopping proxy\n" ;
      Stunnel.UnixSocketProxy.stop proxy ;
      Printf.printf "✓ Proxy stopped\n" ;
      try
        if Sys.file_exists socket_path then
          Printf.printf "✗ Socket file still exists after cleanup!\n"
        else
          Printf.printf "✓ Socket file cleaned up\n"
      with _ -> ()
    )

(** Test certificate fetching *)
let test_fetch_cert remote_host remote_port =
  Printf.printf "\n→ Testing certificate fetching\n" ;
  Printf.printf "→ Fetching certificate from %s:%d\n" remote_host remote_port ;
  match Stunnel.fetch_server_cert ~remote_host ~remote_port with
  | None ->
      Printf.printf "✗ Failed to fetch certificate\n"
  | Some cert ->
      Printf.printf "✓ Certificate fetched successfully (%d bytes)\n"
        (String.length cert) ;
      Printf.printf "→ Certificate preview:\n%s\n"
        (String.sub cert 0 (min 200 (String.length cert)))

let () =
  let remote_host = ref "example.com" in
  let remote_port = ref 443 in
  let purpose = ref "testing" in
  let timeout = ref 10.0 in
  let test_mode = ref "all" in

  let usage_msg =
    "test_stunnel [options]\n\
     Test stunnel UnixSocketProxy API with automatic socket path generation"
  in
  let speclist =
    [
      ( "--host"
      , Arg.Set_string remote_host
      , "Remote host (default: example.com)"
      )
    ; ("--port", Arg.Set_int remote_port, "Remote port (default: 443)")
    ; ( "--purpose"
      , Arg.Set_string purpose
      , "Purpose string for certificate verification (default: testing)"
      )
    ; ( "--timeout"
      , Arg.Set_float timeout
      , "Socket receive timeout in seconds (default: 10.0)"
      )
    ; ( "--test"
      , Arg.Symbol
          (["all"; "proxy"; "lifecycle"; "fetch"], fun s -> test_mode := s)
      , "Test mode: all (default), proxy (with_proxy), lifecycle (start/stop), \
         fetch (certificate)"
      )
    ]
  in

  Arg.parse speclist (fun _ -> ()) usage_msg ;

  match !test_mode with
  | "all" | "proxy" ->
      test_unix_socket_proxy !remote_host !remote_port !purpose !timeout ;
      if !test_mode = "all" then (
        test_explicit_lifecycle !remote_host !remote_port !purpose !timeout ;
        test_fetch_cert !remote_host !remote_port
      )
  | "lifecycle" ->
      test_explicit_lifecycle !remote_host !remote_port !purpose !timeout
  | "fetch" ->
      test_fetch_cert !remote_host !remote_port
  | _ ->
      Printf.eprintf "Invalid test mode\n" ;
      exit 1
