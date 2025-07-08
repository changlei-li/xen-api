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

(** Host CPU C-state management functions.

    C-states are power management states for CPUs where higher numbered states
    represent deeper sleep modes with lower power consumption but higher wake-up
    latency. The max_cstate parameter controls the deepest C-state that CPUs
    are allowed to enter.

    Common C-state values:
    - C0: CPU is active (not a sleep state)
    - C1: CPU is halted but can wake up almost instantly
    - C2: CPU caches are flushed, slightly longer wake-up time
    - C3+: Deeper sleep states with progressively longer wake-up times

    Setting max_cstate=1 restricts CPUs to only use C0 and C1 states,
    which can improve performance for latency-sensitive workloads at the
    cost of higher power consumption.
*)

val xenpm_set : int64 -> unit
(** [xenpm_set value] sets the maximum C-state using the xenpm tool.
    This affects the runtime power management behavior immediately.
    
    @param value The maximum C-state value
    @raise Failure if the xenpm command fails *)

val xen_cmdline_set : int64 -> unit
(** [xen_cmdline_set value] sets the max_cstate parameter in the Xen command line.
    This setting will take effect on the next reboot.
    
    @param value The maximum C-state value
    @raise Failure if updating the command line fails *)

val xen_cmdline_get : unit -> int64
(** [xen_cmdline_get ()] retrieves the current max_cstate setting from the Xen command line.
    
    @return The current max_cstate value, or -1L if not configured
    @raise Failure if reading the command line fails or parsing fails *)
