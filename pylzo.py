import textwrap


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'{:02x} '.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


class pyLZO_Decompress:
    def __init__(self, compressed_msg):
        self.compressed_msg = compressed_msg
        self.uncompressed_msg = b''
        self.idx = 1
        self.state = 0
        self.size = compressed_msg[0]
        self.opcode = compressed_msg[1]

        self.decompress()

    def decompress(self):
        while self.idx < self.size:
            instruct = self.opcode >> 4
            # print(instruct)

            if instruct == 0:
                if self.state == 0:
                    self._0000LLLL()
                elif self.state in [1, 2, 3]:
                    self._0000DDSS()
                else:
                    self._0000DDSS4()

            elif instruct == 1:
                if self._0001HLLL():
                    break

            elif instruct > 7:
                self._1LLDDDSS()

            elif instruct > 3:
                self._01LDDDSS()
            else:
                self._001LLLLL()

            if self.state != 4:
                # print("copying {} literals".format(self.state))
                self.uncompressed_msg += self.compressed_msg[self.idx: self.idx + self.state]
                self.idx += self.state

            self.opcode = self.compressed_msg[self.idx]
            # print(format_multi_line('', self.uncompressed_msg))

    def _0000LLLL(self):
        """
         when 0 0 0 0 L L L L and state == 0
         Copy literal string
         length = 3 + (L ? L: 15 + (zero_btyes * 255 ) + non_zero_btye)
         state = 4 (no extra literals are copied)
        """
        length = 3 + self.compute_L(self.opcode, 15)
        self.state = 4

        self.idx += 1

        self.uncompressed_msg += self.compressed_msg[self.idx: self.idx + length]
        self.idx += length

    def _0000DDSS(self):
        """
         when 0 0 0 0 D D S S  (0..15)  state == 1,2,3
         copy 2 bytes from <= 1kB distance
         length = 2
         state = S (copy S literals after this block)
         Always followed by exactly one byte : H H H H H H H H
         distance = (H << 2) + D + 1
        """
        D = self.opcode >> 2 & 3
        S = self.opcode & 3

        length = 2
        self.state = S
        distance = (self.compressed_msg[self.idx + 1] << 2) + D + 1

        self.copy(distance, length)

        self.idx += 2

    def _0000DDSS4(self):
        """
         when 0 0 0 0 D D S S  (0..15) and state >= 4
         copy 3 bytes from 2..3 kB distance
         length = 3
         state = S (copy S literals after this block)
         Always followed by exactly one byte : H H H H H H H H
         distance = (H << 2) + D + 2049
        """
        D = self.opcode >> 2 & 3
        S = self.opcode & 3

        length = 3
        self.state = S
        distance = (self.compressed_msg[self.idx + 1]) << 2 + D + 2049

        self.copy(distance, length)

        self.idx += 2

    def _0001HLLL(self):
        """
         when 0 0 0 1 H L L L  (16..31)
         Copy of a block within 16..48kB distance (preferably less than 10B)
         length = 2 + (L ?: 7 + (zero_bytes * 255) + non_zero_byte)
         Always followed by exactly one LE16 :  D D D D D D D D : D D D D D D S S
         distance = 16384 + (H << 14) + D
         state = S (copy S literals after this block)
         End of stream is reached if distance == 16384
        """
        H = self.opcode >> 3 & 1
        length = 2 + self.compute_L(self.opcode & 3, 7)
        self.idx += 1

        D = (self.compressed_msg[self.idx] >> 2) + (self.compressed_msg[self.idx + 1] * 64)
        S = self.compressed_msg[self.idx] & 3
        self.idx += 2

        distance = 16384 + (H << 14) + D
        self.state = S

        self.copy(distance, length)

        if distance == 16384:
            return True
        else:
            return False

    def _001LLLLL(self):
        """
         when 0 0 1 L L L L L  (32..63)
         Copy of small block within 16kB distance (preferably less than 34B)
         length = 2 + (L ?: 31 + (zero_bytes * 255) + non_zero_byte)
         Always followed by exactly one LE16 :  D D D D D D D D (1): D D D D D D S S (0)
         distance = D + 1
         state = S (copy S literals after this block)
        """
        # print("idx :", self.idx)
        length = 2 + self.compute_L(self.opcode & 31, 31)
        self.idx += 1

        D = (self.compressed_msg[self.idx] >> 2) + (self.compressed_msg[self.idx + 1] * 64)
        S = self.compressed_msg[self.idx] & 3

        distance = D + 1
        self.state = S

        # print("({}, {}, {})".format(self.state, distance, length))

        self.copy(distance, length)
        self.idx += 2

    def _01LDDDSS(self):
        '''
         when 0 1 L D D D S S  (64..127)
         Copy 3-4 bytes from block within 2kB distance
         state = S (copy S literals after this block)
         length = 3 + L
         Always followed by exactly one byte : H H H H H H H H
         distance = (H << 3) + D + 1
        '''

        L = self.opcode >> 5 & 1
        D = self.opcode >> 2 & 3
        S = self.opcode & 3

        self.state = S
        length = 3 + L
        distance = (self.compressed_msg[self.idx + 1] << 3) + D + 1

        self.copy(distance, length)

        self.idx += 2

    def _1LLDDDSS(self):
        '''
         when 1 L L D D D S S  (128..255)
         Copy 5-8 bytes from block within 2kB distance
         state = S (copy S literals after this block)
         length = 5 + L
         Always followed by exactly one byte : H H H H H H H H
         distance = (H << 3) + D + 1
        '''

        L = self.opcode >> 5 & 3
        D = self.opcode >> 2 & 7
        S = self.opcode & 3

        self.state = S
        length = 5 + L
        distance = (self.compressed_msg[self.idx + 1] << 3) + D + 1

        self.copy(distance, length)

        self.idx += 2

    def zero_bytes(self):
        count = 0
        self.idx += 1
        # print("counting", self.compressed_msg[self.idx], self.idx)
        while self.compressed_msg[self.idx] == 0:
            self.idx += 1
            count += 1
            # print("next", self.compressed_msg[self.idx], self.idx)

        # print("count", count)
        return count

    def compute_L(self, L, offset):
        if L:
            return L
        else:
            count = self.zero_bytes()
            n = self.compressed_msg[self.idx]
            # print("hi", count, n)
            return offset + (count * 255) + n
            # return offset + (self.zero_bytes() * 255) + self.compressed_msg[self.idx]

    def copy(self, distance, length):
        d = len(self.uncompressed_msg) - distance          # number of places to go back
        self.uncompressed_msg += self.uncompressed_msg[d:] * (length // distance) \
                                 + self.uncompressed_msg[d: d + length % distance]

if __name__ == '__main__':
    # x1_msg = b'\x1b\x04\x11\x12\x11\x13\x14\x11\x14\x88\x00\x02\x12\x11\x12\x11\x13\x87\x01\x14\x14\x11\x39\x30\x00' \
    #          b'\x11\x00\x00'

    # x1_msg = b'\x18\x02\x11\x11\x11\x11\x11\x61\x00\x22\xe0\x00\x06\x33\x33\x33\x33\x33\x33\x33\x33\x33\x11\x00\x00'
    x1_msg = b'\x1b\x04\x11\x12\x11\x13\x14\x11\x14\x88\x00\x02\x12\x11\x12\x11\x13\x87\x01\x14\x14\x11\x2c\x30\x00\x11\x00\x00'
    pylzo = pyLZO_Decompress(x1_msg)

    print("Uncompressed Message : ")
    print(format_multi_line("\t", pylzo.uncompressed_msg))

