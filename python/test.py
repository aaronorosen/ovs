import ovn_utils

print ovn_utils.parse_match('outport == "3b5ae6ae-ede7-44cc-a861-a8c2b26ac437" && ip4 && ip4.src == 10.0.0.0/24 && udp && udp.src == 67 && udp.dst == 68')
print ovn_utils.parse_match('outport == "3b5ae6ae-ede7-44cc-a861-a8c2b26ac437" && ip4 && ip4.src == 10.0.0.0/24 && udp && 6.src == 67 && udp.dst == 68')
