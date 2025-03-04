#!/usr/bin/python3

import atexit
import contextlib
from pprint import pprint, pformat

import XenAPI


# given a list of dictionaries, print selected keys in order from each one, nicely formatted with a title
def dictionary_list_partial_print(title, dictionary_list, keys):
    bar = "-" * len(title)
    print(bar, "\n", title, "\n", bar)
    print(
        "\n--\n".join(
            [
                "\n".join(["%s  : %s" % (k, pformat(d[k])) for k in keys])
                for d in dictionary_list
            ]
        )
    )
    print(bar)


# x, 'VM', 'guest_metrics' -> guest_metrics_record of the VM x
# catch the NULL if the record doesn't exist for some reason, and return the string 'NULL'
def fetch_metrics_record(sx, object_reference, type_string, metrics_name):
    record_reference = sx.__getattr__(type_string).__getattr__("get_" + metrics_name)(
        object_reference
    )
    if record_reference == "OpaqueRef:NULL":
        return "NULL"
    else:
        return sx.__getattr__(f"{type_string}_{metrics_name}").get_record(
            record_reference
        )


def fetch_rrd_records(sx, object_reference, type_string, data_owner):
    obj_class = sx.__getattr__(type_string)
    owner_class = sx.__getattr__(data_owner)
    belongs_to = obj_class.__getattr__(f"get_{data_owner}")(object_reference)
    device_number = obj_class.__getattr__("get_device")(object_reference)
    related_data_sources = [
        x
        for x in owner_class.get_data_sources(belongs_to)
        if x["name_label"].startswith(f"{type_string.lower()}_{device_number}")
    ]
    related_data_sources = {x["name_label"]: x["value"] for x in related_data_sources}
    return related_data_sources


# the names of the vbds are a little more complicated, because there is the possiblility that a VBD connects
# a VM to a CD drive, which may be empty, and thus not have a VDI to represent it.
def get_vbd_name(sx, vbd):
    if sx.VBD.get_type(vbd) == "CD" and sx.VBD.get_empty(vbd) == True:
        device_name = "empty cd drive"
    else:
        device_name = sx.VDI.get_name_label(sx.VBD.get_VDI(vbd))
    return f'VBD connecting "{sx.VM.get_name_label(sx.VBD.get_VM(vbd))}" to "{device_name}"'


def main():
    session = XenAPI.xapi_local()

    def logout():
        with contextlib.suppress(Exception):
            session.xenapi.session.logout()

    atexit.register(logout)

    session.xenapi.login_with_password("", "", "1.0", "metrics-script")
    sx = session.xenapi

    # first, we'll find all the hosts, and get the information we care about from each
    hosts = sx.host.get_all()
    host_metrics = [
        {
            "name_label": sx.host.get_name_label(x),
            "metrics": sx.host_metrics.get_record(sx.host.get_metrics(x)),
            "host_cpus": [sx.host_cpu.get_record(x) for x in sx.host.get_host_CPUs(x)],
        }
        for x in hosts
    ]

    # and print out the interesting bits
    dictionary_list_partial_print(
        "Host Metrics", host_metrics, ["name_label", "metrics", "host_cpus"]
    )

    # find all the virtual machines which are resident on the hosts
    resident_vms = set()
    for host in hosts:
        resident_vms.update(sx.host.get_resident_VMs(host))

    # get and print their info
    vm_metrics = [
        {
            "name_label": sx.VM.get_name_label(x),
            "metrics": fetch_metrics_record(sx, x, "VM", "metrics"),
            "guest_metrics": fetch_metrics_record(sx, x, "VM", "guest_metrics"),
        }
        for x in resident_vms
    ]

    dictionary_list_partial_print(
        "Virtual Machine Metrics",
        vm_metrics,
        ["name_label", "metrics", "guest_metrics"],
    )

    # from the list of resident VMs we can find all the active VIFs and VBDs
    # however these don't have useful names, so we have to make them up
    active_vifs = [
        vif for vif in sx.VIF.get_all() if sx.VIF.get_VM(vif) in resident_vms
    ]

    vif_metrics = [
        {
            "name_label": f'VIF connecting "{sx.network.get_name_label(sx.VIF.get_network(x))}" '
            f'to "{sx.VM.get_name_label(sx.VIF.get_VM(x))}"',
            "metrics": fetch_rrd_records(sx, x, "VIF", "VM"),
        }
        for x in active_vifs
    ]

    dictionary_list_partial_print("VIF metrics", vif_metrics, ["name_label", "metrics"])

    active_vbds = [
        vbd for vbd in sx.VBD.get_all() if sx.VBD.get_VM(vbd) in resident_vms
    ]

    vbd_metrics = [
        {
            "name_label": get_vbd_name(sx, x),
            "metrics": fetch_rrd_records(sx, x, "VBD", "VM"),
        }
        for x in active_vbds
    ]

    dictionary_list_partial_print("VBD Metrics", vbd_metrics, ["name_label", "metrics"])

    # from the VIFs we can find the active networks, which don't actually have any metrics
    active_networks = set()
    for vif in active_vifs:
        active_networks.add(sx.VIF.get_network(vif))

    network_metrics = [
        {"name_label": sx.network.get_name_label(x)} for x in active_networks
    ]
    dictionary_list_partial_print("Network Metrics", network_metrics, ["name_label"])

    # and from the active networks we can get all the relevant pifs
    active_pifs = set()
    for network in active_networks:
        active_pifs.update(sx.network.get_PIFs(network))

    pif_metrics = [
        {
            "name_label": f"{sx.PIF.get_device(x)} on "
            f"{sx.host.get_name_label(sx.PIF.get_host(x))}",
            "metrics": fetch_rrd_records(sx, x, "PIF", "host"),
        }
        for x in active_pifs
    ]

    dictionary_list_partial_print("PIF Metrics", pif_metrics, ["name_label", "metrics"])

    # finish off by printing out a concise list of all the active objects
    # awkward duplication instead of iterating over locals()[name] is so that
    # pytype does not complain
    print("Active Objects")
    for name, lst in [
        ("host_metrics", host_metrics),
        ("vm_metrics", vm_metrics),
        ("vif_metrics", vif_metrics),
        ("vbd_metrics", vbd_metrics),
        ("network_metrics", network_metrics),
        ("pif_metrics", pif_metrics),
    ]:
        print(name, [(y["name_label"]) for y in lst])


if __name__ == "__main__":
    main()
