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

open Stunnel_log_scanner

(** Path to test data directory - relative to where dune runs the test *)
let data_dir = "data"

(** Helper to build path to test log file *)
let log_path filename = Filename.concat data_dir filename

(** Collect logged lines for verification *)
let make_logger () =
  let lines = ref [] in
  let log line = lines := line :: !lines in
  (log, fun () -> List.rev !lines)

(** Test successful connection log *)
let test_successful_connection () =
  let logfile = log_path "successful_connection.log" in
  let logger, _get_lines = make_logger () in

  match check_stunnel_logfile_from_position logger logfile 0 with
  | End pos ->
      let size = Unix.(stat logfile).st_size in
      Alcotest.(check int) "Should reach end of file" size pos
  | ScanFound _ ->
      Alcotest.fail "Should not get ScanFound in successful log"
  | ScanError (e, _) ->
      Alcotest.fail
        ("Should not error on successful connection log: "
        ^ Stunnel_error.to_string e
        )

(** Test certificate verification failure *)
let test_certificate_verify_failed () =
  let logfile = log_path "certificate_verify_failed.log" in
  let logger, get_lines = make_logger () in

  match check_stunnel_logfile_from_position logger logfile 0 with
  | ScanError (Stunnel_error.Certificate_verify errors, pos) ->
      Alcotest.(check bool) "Position should be > 0" true (pos > 0) ;
      Alcotest.(check bool)
        "Should have CERT errors" true
        (List.length errors > 0) ;
      let has_cert_error =
        List.exists
          (fun e ->
            Astring.String.is_infix ~affix:"unable to get local issuer" e
            || Astring.String.is_infix ~affix:"unable to verify" e
          )
          errors
      in
      Alcotest.(check bool)
        "Should contain certificate error details" true has_cert_error ;
      let lines = get_lines () in
      Alcotest.(check bool)
        "Should have logged lines before error" true
        (List.length lines > 0)
  | _ ->
      Alcotest.fail "Should detect certificate verification failure"

(** Test connection refused error *)
let test_connection_refused () =
  let logfile = log_path "connection_refused.log" in
  let logger, _get_lines = make_logger () in

  match check_stunnel_logfile_from_position logger logfile 0 with
  | ScanError (Stunnel_error.Stunnel msg, pos) ->
      Alcotest.(check bool) "Position should be > 0" true (pos > 0) ;
      Alcotest.(check bool)
        "Error should contain 'Connection refused'" true
        (Astring.String.is_infix ~affix:"Connection refused" msg)
  | _ ->
      Alcotest.fail "Should detect connection refused error"

(** Test no host resolved error *)
let test_no_host_resolved () =
  let logfile = log_path "no_host_resolved.log" in
  let logger, _get_lines = make_logger () in

  match check_stunnel_logfile_from_position logger logfile 0 with
  | ScanError (Stunnel_error.Stunnel msg, pos) ->
      Alcotest.(check bool) "Position should be > 0" true (pos > 0) ;
      Alcotest.(check bool)
        "Error should contain 'No host resolved'" true
        (Astring.String.is_infix ~affix:"No host resolved" msg)
  | _ ->
      Alcotest.fail "Should detect no host resolved error"

(** Test configuration failed error *)
let test_configuration_failed () =
  let logfile = log_path "configuration_failed.log" in
  let logger, _get_lines = make_logger () in

  match check_stunnel_logfile_from_position logger logfile 0 with
  | ScanError (Stunnel_error.Stunnel msg, pos) ->
      Alcotest.(check bool) "Position should be > 0" true (pos > 0) ;
      Alcotest.(check bool)
        "Error should contain 'Configuration failed'" true
        (Astring.String.is_infix ~affix:"Configuration failed" msg)
  | _ ->
      Alcotest.fail "Should detect configuration failed error"

(** Test scanning from middle of file (position tracking) *)
let test_position_tracking () =
  let logfile = log_path "successful_connection.log" in
  let logger1, _get_lines1 = make_logger () in

  (* First scan from beginning *)
  match check_stunnel_logfile_from_position logger1 logfile 0 with
  | End pos1 -> (
      (* Second scan from middle should reach same end *)
      let mid_pos = pos1 / 2 in
      let logger2, _get_lines2 = make_logger () in
      match check_stunnel_logfile_from_position logger2 logfile mid_pos with
      | End pos2 ->
          Alcotest.(check int) "Should reach same end position" pos1 pos2
      | _ ->
          Alcotest.fail "Second scan should reach end"
    )
  | _ ->
      Alcotest.fail "First scan should reach end"

(** Test that logger is called for each line *)
let test_logger_called_for_each_line () =
  let logfile = log_path "successful_connection.log" in
  let call_count = ref 0 in
  let logger _line = incr call_count in

  match check_stunnel_logfile_from_position logger logfile 0 with
  | End _ ->
      Alcotest.(check bool)
        "Logger should be called multiple times" true (!call_count > 10)
  | _ ->
      Alcotest.fail "Should scan entire file"

let test_check_stunnel_log_until () =
  let logfile = log_path "successful_connection.log" in
  let check_line line =
    if Astring.String.is_infix ~affix:"Configuration successful" line then
      LineFound
    else
      Continue
  in
  match check_stunnel_log_until_found_or_error logfile check_line 0.1 2 0 with
  | ScanFound pos ->
      Alcotest.(check bool) "Should return positive pos" true (pos > 0) ;
      (* Verify we can read the next line from the returned position *)
      let fd = Unix.openfile logfile [Unix.O_RDONLY] 0 in
      let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
      finally
        (fun () ->
          let _ = Unix.lseek fd pos Unix.SEEK_SET in
          let ic = Unix.in_channel_of_descr fd in
          let line = input_line ic in
          (* The next line after "Configuration successful" should be about service accepting connection *)
          Alcotest.(check bool)
            "Next line should be about service accepted" true
            (Astring.String.is_infix ~affix:"Service [client-proxy] accepted"
               line
            )
        )
        (fun () -> Unix.close fd)
  | ScanError (e, _pos) ->
      Alcotest.fail ("Should find target line: " ^ Stunnel_error.to_string e)
  | End _ ->
      Alcotest.fail "Should not reach end without finding target line"

let tests =
  [
    ( "test_stunnel_log_scanner"
    , [
        Alcotest.test_case "successful_connection" `Quick
          test_successful_connection
      ; Alcotest.test_case "certificate_verify_failed" `Quick
          test_certificate_verify_failed
      ; Alcotest.test_case "connection_refused" `Quick test_connection_refused
      ; Alcotest.test_case "no_host_resolved" `Quick test_no_host_resolved
      ; Alcotest.test_case "configuration_failed" `Quick
          test_configuration_failed
      ; Alcotest.test_case "position_tracking" `Quick test_position_tracking
      ; Alcotest.test_case "logger_called_for_each_line" `Quick
          test_logger_called_for_each_line
      ; Alcotest.test_case "check_stunnel_log_until" `Quick
          test_check_stunnel_log_until
      ]
    )
  ]

let () = Alcotest.run "StunnelLogScanner" tests
