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
 * Verifying whether the current license is still valid
 * @group Licensing
*)

val serialize_expiry : Clock.Date.t option -> string
(** Get the string corresponding with the expiry that can be stored in xapi's
    DB *)

val get_expiry_date :
  __context:Context.t -> host:API.ref_host -> Clock.Date.t option
(** Returns (Some date) if the host's license has an expiry date,
 *  otherwise returns None. *)

val check_expiry : __context:Context.t -> host:API.ref_host -> unit
(** Raises {!Api_errors.license_expired} if the current license has expired. *)

val vm : __context:Context.t -> API.ref_VM -> unit
(** Raises {!Api_errors.license_expired} if the current license has expired.
 *  The consequence would be that the VM is not allowed to start. *)

val with_vm_license_check :
  __context:Context.t -> [`VM] Ref.t -> (unit -> 'b) -> 'b
(** Executes function [f] only if the current license has not yet expired.
 *  If it has expired, it raises {!Api_errors.license_expired}. *)
