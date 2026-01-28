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
(** Stunnel log scanner with pattern matching *)

(** Module for reading and processing log files with position tracking and result types *)
module LogFile = struct
  type error = IO_error of string | Parse_error of string

  (** Pattern matching result indicator *)
  type 'a pattern_match =
    | Success of 'a  (** Operation succeeded *)
    | Failure of 'a  (** Operation failed (expected failure) *)
    | Error of 'a  (** Unexpected error occurred *)

  (** Pattern match type - defines accumulation behavior *)
  type 'ctx match_type =
    | Match  (** Simple match - no accumulation needed *)
    | AccumulateUntilMatch of {
          extract: string -> 'ctx option  (** Extract context from line *)
        ; combine: 'ctx -> 'ctx list -> 'ctx list
              (** Combine into accumulator *)
      }  (** Accumulate context until pattern matches *)

  (** A pattern with its metadata *)
  type ('a, 'ctx) pattern = {
      text: string  (** Pattern to search for *)
    ; result: 'a pattern_match  (** What it indicates when found *)
    ; match_type: 'ctx match_type  (** How to handle accumulation *)
  }

  (** Pattern database - list of patterns to check *)
  type ('a, 'ctx) pattern_db = ('a, 'ctx) pattern list

  (** Stream through file line-by-line with a fold function that returns results.
      Stops early if the accumulator function returns Error.
      Returns the final accumulated result. *)
  let stream_fold (f : 'a -> string -> ('a, error) result) (init : 'a)
      (filepath : string) : ('a, error) result =
    try
      let ic = open_in filepath in
      let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
      finally
        (fun () ->
          let rec loop acc =
            match input_line ic with
            | exception End_of_file ->
                Ok acc
            | line -> (
              match f acc line with Ok acc' -> loop acc' | Error _ as e -> e
            )
          in
          loop init
        )
        (fun () -> close_in ic)
    with
    | Sys_error msg ->
        Error (IO_error msg)
    | e ->
        Error (IO_error (Printexc.to_string e))

  (** Stream through lines from a specific position, applying function to each.
      Returns (result, new_position). Stops early on Error. *)
  let stream_from_position (filepath : string) (start_pos : int)
      (f : 'a -> string -> ('a, error) result) (init : 'a) :
      ('a * int, error) result =
    try
      let fd = Unix.openfile filepath [Unix.O_RDONLY] 0 in
      let finally = Xapi_stdext_pervasives.Pervasiveext.finally in
      finally
        (fun () ->
          let _ = Unix.lseek fd start_pos Unix.SEEK_SET in
          let ic = Unix.in_channel_of_descr fd in
          let rec loop acc =
            match input_line ic with
            | exception End_of_file ->
                let end_pos = (Unix.fstat fd).Unix.st_size in
                Ok (acc, end_pos)
            | line -> (
              match f acc line with Ok acc' -> loop acc' | Error _ as e -> e
            )
          in
          loop init
        )
        (fun () -> Unix.close fd)
    with
    | Unix.Unix_error (err, fn, arg) ->
        Error
          (IO_error (Printf.sprintf "%s: %s(%s)" (Unix.error_message err) fn arg)
          )
    | e ->
        Error (IO_error (Printexc.to_string e))

  (** Match line against pattern database. Returns first matching pattern. *)
  let match_patterns (patterns : ('a, 'ctx) pattern_db) (line : string) :
      ('a, 'ctx) pattern option =
    List.find_map
      (fun pattern ->
        if Astring.String.is_infix ~affix:pattern.text line then
          Some pattern
        else
          None
      )
      patterns
end

type stunnel_error =
  | Certificate_verify of string list
  | Stunnel of string
  | Unknown of string

(** Stunnel log pattern database *)
module Patterns = struct
  open LogFile

  (** All available patterns - add/remove patterns here *)
  let configuration_successful =
    {text= "Configuration successful"; result= Success "ok"; match_type= Match}

  let configuration_failed =
    {
      text= "Configuration failed"
    ; result= Error "config_failed"
    ; match_type= Match
    }

  let certificate_accepted =
    {text= "Certificate accepted"; result= Success "ok"; match_type= Match}

  let connected_remote_server =
    {
      text= "connected remote server from"
    ; result= Success "ok"
    ; match_type= Match
    }

  (* Helper for cert error accumulation *)
  let cert_accumulator =
    LogFile.AccumulateUntilMatch
      {
        extract=
          (fun line ->
            Astring.String.cut ~rev:true ~sep:"CERT: " line |> Option.map snd
          )
      ; combine= (fun err acc -> err :: acc)
      }

  let rejected_by_cert =
    {
      text= "Rejected by CERT"
    ; result= Failure "cert_rejected"
    ; match_type= cert_accumulator
    }

  let certificate_verify_failed =
    {
      text= "certificate verify failed"
    ; result= Error "cert_verify"
    ; match_type= cert_accumulator
    }

  let connection_refused =
    {
      text= "Connection refused"
    ; result= Error "conn_refused"
    ; match_type= Match
    }

  let no_host_resolved =
    {text= "No host resolved"; result= Error "no_host"; match_type= Match}

  let no_route_to_host =
    {text= "No route to host"; result= Error "no_route"; match_type= Match}

  let invalid_argument =
    {text= "Invalid argument"; result= Error "invalid_arg"; match_type= Match}

  let address_in_use =
    {
      text= "Address already in use"
    ; result= Error "addr_in_use"
    ; match_type= Match
    }

  (** Convert error string to stunnel_error *)
  let to_stunnel_error (cert_errors : string list) (err : string) :
      stunnel_error =
    match err with
    | "cert_verify" ->
        Certificate_verify cert_errors
    | "conn_refused" ->
        Stunnel "Connection refused"
    | "no_host" ->
        Stunnel "No host resolved"
    | "no_route" ->
        Stunnel "No route to host"
    | "config_failed" ->
        Stunnel "Configuration failed"
    | "invalid_arg" ->
        Stunnel "Invalid argument"
    | "addr_in_use" ->
        Stunnel "Address already in use"
    | msg ->
        Unknown msg
end

(** Configuration for scanner *)
module type Config = sig
  val logfile : string
  (** Path to the log file *)

  val logger : string -> unit
  (** Logger function called for each line *)
end

(** Scanner module signature *)
module type S = sig
  val scan :
       ?start_pos:int
    -> ('a, 'ctx) LogFile.pattern_db
    -> ([> `Failure of 'a | `Success of 'a | `Not_found], stunnel_error) result
  (** Scan log file with pattern matching *)

  val scan_with_cert_context :
       ?start_pos:int
    -> (string, string) LogFile.pattern_db
    -> ( [> `Failure of string | `Success of string | `Not_found]
       , stunnel_error
       )
       result
  (** Scan with cert error context (specialized for string patterns) *)

  val check_errors_from_position : int -> (unit, stunnel_error) result
  (** Check log from a position for errors *)

  val check_errors : unit -> (unit, stunnel_error) result
  (** Check log for errors from the beginning *)
end

(** Functor to create a scanner module *)
module Make (C : Config) : S = struct
  (** Scan log file with pattern matching.
      Scans from optional position (0 if not provided), handles accumulation
      based on pattern match_type. Returns Success/Failure/Error/None. *)
  let scan : type a ctx.
         ?start_pos:int
      -> (a, ctx) LogFile.pattern_db
      -> ([> `Success of a | `Failure of a | `Not_found], stunnel_error) result
      =
   fun ?(start_pos = 0) patterns ->
    let process_line (context, result) line =
      C.logger line ;
      match result with
      | Some matched_pattern -> (
        (* Already matched - check if we need to continue accumulating *)
        match matched_pattern.LogFile.match_type with
        | LogFile.Match ->
            Ok (context, result)
        | LogFile.AccumulateUntilMatch {extract; combine} -> (
          match extract line with
          | Some ctx ->
              Ok (combine ctx context, result)
          | None ->
              Ok (context, result)
        )
      )
      | None ->
          let pattern_result = LogFile.match_patterns patterns line in
          (* Accumulate for any active accumulation patterns, even before match *)
          let context' =
            List.fold_left
              (fun acc pattern ->
                match pattern.LogFile.match_type with
                | LogFile.Match ->
                    acc
                | LogFile.AccumulateUntilMatch {extract; combine} -> (
                  match extract line with
                  | Some ctx ->
                      combine ctx acc
                  | None ->
                      acc
                )
              )
              context patterns
          in
          Ok (context', pattern_result)
    in

    let scan_result =
      if start_pos = 0 then
        LogFile.stream_fold process_line ([], None) C.logfile
        |> Result.map (fun acc -> (acc, 0))
      else
        LogFile.stream_from_position C.logfile start_pos process_line ([], None)
    in

    match scan_result with
    | Ok ((_, Some pattern), _) -> (
      match pattern.LogFile.result with
      | LogFile.Success x ->
          Ok (`Success x)
      | LogFile.Failure x ->
          Ok (`Failure x)
      | LogFile.Error x ->
          (* Generic error without context *)
          Error (Unknown (Obj.magic x : string))
    )
    | Ok ((_, None), _) ->
        Ok `Not_found
    | Error (LogFile.IO_error msg) ->
        Error (Unknown msg)
    | Error (LogFile.Parse_error msg) ->
        Error (Unknown msg)

  (** Specialized scan for string patterns with cert error context *)
  let scan_with_cert_context ?(start_pos = 0) patterns =
    let process_line (context, result) line =
      C.logger line ;
      match result with
      | Some matched_pattern -> (
        (* Already matched - check if we need to continue accumulating *)
        match matched_pattern.LogFile.match_type with
        | LogFile.Match ->
            Ok (context, result)
        | LogFile.AccumulateUntilMatch {extract; combine} -> (
          match extract line with
          | Some ctx ->
              Ok (combine ctx context, result)
          | None ->
              Ok (context, result)
        )
      )
      | None ->
          let pattern_result = LogFile.match_patterns patterns line in
          (* Accumulate for any active accumulation patterns, even before match *)
          let context' =
            List.fold_left
              (fun acc pattern ->
                match pattern.LogFile.match_type with
                | LogFile.Match ->
                    acc
                | LogFile.AccumulateUntilMatch {extract; combine} -> (
                  match extract line with
                  | Some ctx ->
                      combine ctx acc
                  | None ->
                      acc
                )
              )
              context patterns
          in
          Ok (context', pattern_result)
    in

    let scan_result =
      if start_pos = 0 then
        LogFile.stream_fold process_line ([], None) C.logfile
        |> Result.map (fun acc -> (acc, 0))
      else
        LogFile.stream_from_position C.logfile start_pos process_line ([], None)
    in

    match scan_result with
    | Ok ((context, Some pattern), _) -> (
      match pattern.LogFile.result with
      | LogFile.Success x ->
          Ok (`Success x)
      | LogFile.Failure x ->
          Ok (`Failure x)
      | LogFile.Error err ->
          let stunnel_err = Patterns.to_stunnel_error context err in
          Error stunnel_err
    )
    | Ok ((_, None), _) ->
        Ok `Not_found
    | Error (LogFile.IO_error msg) ->
        Error (Unknown msg)
    | Error (LogFile.Parse_error msg) ->
        Error (Unknown msg)

  (** Check log from a position for errors.
      Returns Ok () if no errors, Error if error pattern found. *)
  let check_errors_from_position start_pos =
    let error_patterns =
      Patterns.
        [
          certificate_verify_failed
        ; connection_refused
        ; no_host_resolved
        ; no_route_to_host
        ; configuration_failed
        ; invalid_argument
        ; address_in_use
        ]
    in
    match scan_with_cert_context ~start_pos error_patterns with
    | Ok (`Success _) ->
        Ok ()
    | Ok (`Failure _) ->
        Ok ()
    | Ok `Not_found ->
        Ok ()
    | Error e ->
        Error e

  (** Check log for errors from the beginning *)
  let check_errors () = check_errors_from_position 0
end
