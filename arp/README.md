# ARP Extension Guide for Teammates (RFC 826 / RFC 5227)

This directory is the dedicated integration module for the **Address Resolution Protocol (ARP)**. The DHCP client and GUI are already pre-wired to communicate with this module via clean event hooks.

---

## Architecture & Integration Points

The DHCP Client (`dhcp/client.py`) provides two clean integration hooks:

1. **Duplicate Address Detection (DAD) Hook:**
   - **Method:** `client.set_arp_checker(callback: Callable[[str], bool])`
   - **Purpose:** Before the DHCP client transitions to `BOUND`, it calls this hook with the candidate IP (`yiaddr`). If your ARP probe finds that another host answers for that IP, return `True`. The DHCP client will automatically transmit `DHCPDECLINE` and quarantine the collided IP.
2. **Gratuitous ARP Announcement Hook:**
   - **Method:** `client.set_gratuitous_arp_handler(callback: Callable[[str, str], None])`
   - **Purpose:** When the DHCP client reaches `BOUND`, it calls this hook with `(mac, ip)` so you can broadcast a Gratuitous ARP announcement to update neighbor caches.

---

## Files to Implement

1. **`arp/packet.py`**:
   - Class `ArpPacket` with RFC 826 28-byte wire format:
     `struct.Struct("!HHBBH6s4s6s4s")`
   - Functions: `new_arp_request`, `new_arp_reply`, `new_arp_probe`, `new_gratuitous_arp`.
2. **`arp/table.py`**:
   - Class `ArpTable` mapping IP $\to$ MAC with TTL expiration (`update()`, `lookup()`, `snapshot()`).
3. **`tests/test_arp.py`**:
   - Unit tests validating packet serialization, probe formatting, and cache TTL.
