"""
If only knows only L (and not S or M), they can:
  - Extract every L-th bit starting from position 0.
  - This yields a candidate bitstream, but without knowing S they get the
    wrong starting offset.  With enough statistical analysis (chi-square on
    bit frequencies, entropy analysis of byte pairs) they could narrow down
    plausible values of S.
  - In 'cycling' mode knowledge of a single L value is insufficient; the
    attacker must also know the full period sequence.
  - The best practical attack is brute-force over (S, mode) pairs for fixed L,
    which is O(filesize × number_of_modes).
"""
 
from typing import List
 
 
def _get_bit(data: bytes, pos: int) -> int:
    byte_idx = pos >> 3          
    bit_idx  = 7 - (pos & 7)    
    return (data[byte_idx] >> bit_idx) & 1
 
 
def _set_bit(data: bytearray, pos: int, value: int) -> None:
    byte_idx = pos >> 3
    bit_idx  = 7 - (pos & 7)
    if value:
        data[byte_idx] |= (1 << bit_idx)
    else:
        data[byte_idx] &= ~(1 << bit_idx)
 
 
def _bit_positions(start_bit: int, period_list: List[int], mode: str, count: int) -> List[int]:
    positions = []
    if mode == 'cycling':
        period_cycle = period_list  
        pos = start_bit
        for i in range(count):
            p = period_cycle[i % len(period_cycle)]
            pos += p
            positions.append(pos)
    else:  # fixed
        L = period_list[0]
        for i in range(count):
            positions.append(start_bit + (i + 1) * L)
    return positions
 
 
def embed_message(carrier: bytes, message: bytes, start_bit: int, period_list: List[int], mode: str) -> bytes:

    if not carrier:
        raise ValueError("Carrier file is empty.")
    if not message:
        raise ValueError("Message file is empty.")
 
    payload_bits = len(message) * 8
    carrier_bits = len(carrier) * 8
    positions = _bit_positions(start_bit, period_list, mode, payload_bits)
 
    if positions and positions[-1] >= carrier_bits:
        raise ValueError(
            f"Message too large: need bit position {positions[-1]}, "
            f"but carrier only has {carrier_bits} bits. "
            f"Try a smaller message, a larger carrier, or a smaller period."
        )
 
    result = bytearray(carrier)
    for i, pos in enumerate(positions):
        byte_of_msg = i >> 3
        bit_in_byte = 7 - (i & 7)
        msg_bit = (message[byte_of_msg] >> bit_in_byte) & 1
        _set_bit(result, pos, msg_bit)
 
    return bytes(result)
 
 
def extract_message(carrier: bytes, start_bit: int, period_list: List[int],
                    mode: str, message_len_bits: int) -> bytes:
    positions = _bit_positions(start_bit, period_list, mode, message_len_bits)
    result = bytearray((message_len_bits + 7) // 8)
 
    for i, pos in enumerate(positions):
        bit = _get_bit(carrier, pos)
        byte_idx = i >> 3
        bit_idx  = 7 - (i & 7)
        if bit:
            result[byte_idx] |= (1 << bit_idx)
        else:
            result[byte_idx] &= ~(1 << bit_idx)
 
    return bytes(result)