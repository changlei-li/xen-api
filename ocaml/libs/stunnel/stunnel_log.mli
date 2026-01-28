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

(** Module for reading and processing log files *)
module LogFile : sig
  type error = IO_error of string | Parse_error of string

  type 'a pattern_match = Success of 'a | Failure of 'a | Error of 'a

  type 'ctx match_type =
    | Match
    | AccumulateUntilMatch of {
          extract: string -> 'ctx option
        ; combine: 'ctx -> 'ctx list -> 'ctx list
      }

  type ('a, 'ctx) pattern = {
      text: string
    ; result: 'a pattern_match
    ; match_type: 'ctx match_type
  }

  type ('a, 'ctx) pattern_db = ('a, 'ctx) pattern list
end

type stunnel_error =
  | Certificate_verify of string list
  | Stunnel of string
  | Unknown of string

(** Stunnel log pattern database *)
module Patterns : sig
  val configuration_successful : (string, string) LogFile.pattern

  val configuration_failed : (string, string) LogFile.pattern

  val certificate_accepted : (string, string) LogFile.pattern

  val connected_remote_server : (string, string) LogFile.pattern

  val rejected_by_cert : (string, string) LogFile.pattern

  val certificate_verify_failed : (string, string) LogFile.pattern

  val connection_refused : (string, string) LogFile.pattern

  val no_host_resolved : (string, string) LogFile.pattern

  val no_route_to_host : (string, string) LogFile.pattern

  val invalid_argument : (string, string) LogFile.pattern

  val address_in_use : (string, string) LogFile.pattern
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
module Make (_ : Config) : S
