/*
 * Copyright (C) Cloud Software Group.
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
 */

 // check if ntp_gettime maxerror smaller than the maximum value (16 seconds)
 // to see if system clock synchronized

#include <sys/timex.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/threads.h>

value stub_get_ntp_synced(value unit)
{
    CAMLparam1(unit);
    struct ntptimeval ntv;
    const long maximum_error_value = 16000000; // 16 seconds in microseconds

    caml_release_runtime_system();

    if (ntp_gettime(&ntv) < 0) {
        caml_acquire_runtime_system();
        CAMLreturn(Val_false);
    }

    caml_acquire_runtime_system();

    // check if maxerror is smaller than 16 seconds
    if (ntv.maxerror < maximum_error_value) {
        CAMLreturn(Val_true);
    } else {
        CAMLreturn(Val_false);
    }
}
