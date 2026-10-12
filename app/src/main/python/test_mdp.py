# -*- coding: utf-8 -*-
"""Minimal MDP/NTLM protocol self-test for Android (Chaquopy).

Mirrors regress_apply.py: connect -> read NICs -> no-op write-back + renew on the
editable X1 adapter -> read back to confirm. Returns a plain-text log so the
Java UI can just print it.
"""
import sys
import traceback

import mdp_client


def run_test(host, user="Administrator", pw="1"):
    lines = []
    try:
        lines.append(">> connect %s (user=%s)" % (host, user))
        c = mdp_client.MdpClient(host, user, pw)

        nics = c.read_all_nic()
        lines.append("== NIC (%d) ==" % len(nics))
        for n in nics:
            lines.append("  %s | ipv4=%s subnet=%s gw=%s dhcp=%s" % (
                n.get("name"), n.get("ipv4"), n.get("subnet"),
                n.get("gateway"), n.get("dhcp")))

        t = c.read_time()
        if t:
            lines.append("== TIME ==  text=%s tz=%s" % (t.get("text_datetime"), t.get("timezone")))

        mods = c.nic_modules()
        if len(mods) != len(nics):
            lines.append("WARN: module/nics count mismatch")

        # Pick the editable adapter: prefer X1 (name ends with "X1"),
        # else the first non-X2 adapter.
        target = next((n for n in nics if n.get("name", "").strip().upper().endswith("X1")), None)
        if not target:
            target = next((n for n in nics if not n.get("name", "").strip().upper().endswith("X2")), None)

        if not target:
            lines.append("!! no editable NIC found")
            return "\n".join(lines)

        idx = nics.index(target)
        mod = mods[idx]
        ip = target.get("ipv4") or "0.0.0.0"
        subnet = target.get("subnet") or "0.0.0.0"
        gw = target.get("gateway") or "0.0.0.0"

        lines.append("\n[apply_nic] no-op write-back on %s (ipv4=%s, dhcp=%s)" % (
            target["name"], ip, target["dhcp"]))

        code = c.write_nic_service(mod, ip, subnet, gw)
        lines.append("  write_nic_service (no-op) code = %s  (0 = OK)" % code)

        rc = c.write_nic_renew(mod)
        lines.append("  write_nic_renew           code = %s  (0 = applied immediately)" % rc)

        n2 = c.read_nic(mod)
        lines.append("  read-back ipv4=%s subnet=%s gw=%s" % (
            n2.get("ipv4"), n2.get("subnet"), n2.get("gateway")))
        if n2.get("ipv4") != ip:
            lines.append("  WARN: IP changed unexpectedly!")

        if code == 0 and rc == 0:
            lines.append("\nRESULT: OK  (Set_IpAndSubnet=%s, Release/Renew=%s)" % (code, rc))
        else:
            lines.append("\nRESULT: NON-ZERO return code(s) — see above")

    except Exception as e:
        lines.append("!! EXCEPTION: %s" % e)
        lines.append(traceback.format_exc())
    return "\n".join(lines)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.8.165"
    print(run_test(host))
