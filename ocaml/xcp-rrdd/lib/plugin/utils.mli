(*
 * Copyright (C) 2013 Citrix Systems Inc.
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

(** Utility functions useful for rrdd plugins. *)
val now : unit -> float
(** Return the current unix epoch as an int64. *)

val cut : string -> string list
(** Split a string into a list of strings as separated by spaces and/or
      	    tabs. *)

val list_directory_unsafe : string -> string list
(** List the contents of a directory, including . and .. *)

val list_directory_entries_unsafe : string -> string list
(** List the contents of a directory, not including . and .. *)

val exec_cmd :
     (module Debug.DEBUG)
  -> cmdstring:string
  -> read_out_line:(string -> 'a option)
  -> read_err_line:(string -> 'b option)
  -> 'a list * 'b list
(** [exec_cmd cmd out_line err_line] executes [cmd], applies [read_out_line] to
    each of the lines which [cmd] outputs on stdout, applies [read_err_line] to
    each of the lines which [cmd] outputs on stderr, and returns a tuple of
    list with each of the values that the [read_out_line] and [read_err_line]
    returned [Some value]. *)
