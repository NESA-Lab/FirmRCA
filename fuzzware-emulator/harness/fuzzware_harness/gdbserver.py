# Python based GDBServer implementation for fuzzware,
# loosely based on the implementation provided in avatar2

import logging
import binascii
import re
import socket
import xml.etree.ElementTree as ET
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET
from threading import Event, Thread
from time import sleep
import ast
from unicorn.arm_const import (UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC,
                               UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                               UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                               UC_ARM_REG_R12, UC_ARM_REG_SP)

logger = logging.getLogger("emulator")

chksum = lambda x: sum(x) & 0xff
match_hex = lambda m, s: [int(x, 16) for x in re.match(m, s).groups()]

TIMEOUT_TIME = 1.0


# as fuzzware is currently ARM only, directly include the arm-target.xml here
arm_target_xml = b'''<?xml version="1.0"?>
<!-- Copyright (C) 2008 Free Software Foundation, Inc.

     Copying and distribution of this file, with or without modification,
     are permitted in any medium without royalty provided the copyright
     notice and this notice are preserved.  -->



<target>
    <architecture>arm</architecture>
    <feature name="org.gnu.gdb.arm.core">
      <reg name="r0" bitsize="32"/>
      <reg name="r1" bitsize="32"/>
      <reg name="r2" bitsize="32"/>
      <reg name="r3" bitsize="32"/>
      <reg name="r4" bitsize="32"/>
      <reg name="r5" bitsize="32"/>
      <reg name="r6" bitsize="32"/>
      <reg name="r7" bitsize="32"/>
      <reg name="r8" bitsize="32"/>
      <reg name="r9" bitsize="32"/>
      <reg name="r10" bitsize="32"/>
      <reg name="r11" bitsize="32"/>
      <reg name="r12" bitsize="32"/>
      <reg name="sp" bitsize="32" type="data_ptr"/>
      <reg name="lr" bitsize="32"/>
      <reg name="pc" bitsize="32" type="code_ptr"/>

      <!-- The CPSR is register 25, rather than register 16, because
           the FPA registers historically were placed between the PC
           and the CPSR in the "g" packet.  -->
      <reg name="cpsr" bitsize="32" regnum="25"/>
    </feature>
</target>
'''

# taken from avatar2.archs.arm
unicorn_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                     'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                     'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                     'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                     'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                     'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}


class GDBServer(Thread):

    def __init__(self, uc, port=3333):
        super().__init__()
        self.unicorn = uc
        self.daemon=True
        self.sock = socket.socket(AF_INET, SOCK_STREAM)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        self.port = port
        self.conn = None
        self._packetsize=0x47FF
        self.bps = {}
        self._do_shutdown = Event()
        # We use two events here to express the state of the debuggee.
        # While those seem complementary at first, the reason for this is that
        # it allows to stop the debuggee from an external entity by clearing
        # the running event. _in_breakpoint is used for internal synchronization
        # (i.e., unicorn/sparkles) and resynchronization
        self._in_breakpoint = Event()
        self.running = Event()


        xml_regs = ET.fromstring(arm_target_xml).find('feature')
        self.registers = [reg.attrib for reg in xml_regs if reg.tag == 'reg']
        if len(self.registers) == 0:
            raise Exception("Unable to parse XML registers")

        self.handlers = {
            'q' : self.query,
            'v' : self.multi_letter_cmd,
            'H' : self.set_thread_op,
            '?' : self.halt_reason,
            'g' : self.read_registers,
            'G' : self.reg_write,
            'm' : self.mem_read,
            'M' : self.mem_write,
            'c' : self.cont,
            'C' : self.cont, #cond with signal, we don't care
            's' : self.step,
            'S' : self.step,
            'S' : self.step_signal,
            'Z' : self.insert_breakpoint,
            'z' : self.remove_breakpoint,
            'D' : self.detach,
        }


        self.start()

    def shutdown(self):
        self._do_shutdown.set()
        sleep(TIMEOUT_TIME*2)

    def run(self):

        logger.info(f'GDB server listening on port {self.port}, please connect')
        self.sock.bind(('', self.port))
        self.sock.settimeout(TIMEOUT_TIME)
        self.sock.listen(1)

        while not self._do_shutdown.isSet():
            try:
                self.conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            self.conn.settimeout(TIMEOUT_TIME)
            logger.info(f'Accepted connection from {addr}')

            #self.unicorn.emu_stop()
            while self.conn._closed is False:
                packet = self.receive_packet()
                if packet is None:
                    continue

                logger.debug(f'Received: {packet}')
                self.send_raw(b'+') # send ACK

                handler = self.handlers.get(chr(packet[0]),
                                                self.not_implemented)
                resp = handler(packet)
                if resp is not None:
                    self.send_packet(resp)
        self.sock.close()


    ### Handlers
    def not_implemented(self, pkt):
        logger.critical(f'Received not implemented packet: {pkt}')
        return b''

    def query(self, pkt):
        if pkt[1:].startswith(b'Supported') is True:
            feat = [b'PacketSize=%x' % self._packetsize,
                    b'qXfer:features:read+'
                   ]
            return b';'.join(feat)

        if pkt[1:].startswith(b'Attached') is True:
            return b'1'

        if pkt[1:].startswith(b'Xfer:features:read:target.xml') is True:
            off, length = match_hex('qXfer:features:read:target.xml:(.*),(.*)',
                                   pkt.decode())

            data = arm_target_xml
            resp_data = data[off:off+length]
            if len(resp_data) < length:
                prefix = b'l'
            else:
                prefix = b'm'
            return prefix+resp_data

        if pkt[1:].startswith(b'fThreadInfo') is True:
            return b'm1'
        if pkt[1:].startswith(b'sThreadInfo') is True:
            return b'l'

        if pkt[1:].startswith(b'Rcmd') is True: # Monitor commands
            try:
                cmd = re.match('qRcmd,(.*)',pkt.decode())[1]
                cmd = binascii.a2b_hex(cmd)
                logger.debug(f'Receiced cmd: {cmd}')
                res = ast.literal_eval(cmd)

                self.send_packet(b'O' \
                            + binascii.b2a_hex(repr(res).encode()) \
                            + b'0a')
                return b'OK'

            except Exception as e:
                self.send_packet(b'O' + b'ERROR: '.hex().encode())

                if hasattr(e, 'msg'):
                    self.send_packet(b'O' \
                                + e.msg.encode().hex().encode() \
                                + b'0a')
                elif hasattr(e, 'args'):
                    self.send_packet(b'O' \
                                + e.args[0].encode().hex().encode() \
                                + b'0a')

                return b'OK'

        return b''

    def multi_letter_cmd(self, pkt):
        if pkt[1:].startswith(b'vMustReplyEmpty') is True:
            return b''
        return b''

    def set_thread_op(self, pkt):
        return b'OK' # we don't implement threads yet

    def halt_reason(self, pkt):
        return b'S00' # we don't specify the signal yet

    def read_registers(self, pkt):
        resp = ''
        for reg in self.registers:

            bitsize = int(reg['bitsize'])
            assert bitsize % 8 == 0
            r_len = int(bitsize / 8)
            r_val = self.unicorn.reg_read(unicorn_registers[reg['name']])
            #logger.debug(f'{reg["name"]}, {r_val}, {r_len}')

            resp += r_val.to_bytes(r_len, 'little').hex()

        return resp.encode()

    def reg_write(self, pkt):
        idx = 1 # ignore the first char of pkt
        for reg in self.registers:
            bitsize = int(reg['bitsize'])
            r_len = int(bitsize / 8)
            r_val = pkt[idx: idx + r_len*2]
            r_raw = bytes.fromhex(r_val.decode())
            int_val =  int.from_bytes(r_raw, byteorder='little')

            self.unicorn.reg_write(unicorn_registers[reg['name']], int_val)
            idx += r_len*2
        return b'OK'


    def mem_read(self, pkt):
        try:
            addr, n = match_hex('m(.*),(.*)', pkt.decode())

            val = self.unicorn.mem_read(addr, n).hex()
            return val.encode()

        except Exception as e:
            logger.warn(f'Error in mem_read: {e}')
            return b'E00'


    def mem_write(self, pkt):
        try:
            addr, n, _ = match_hex('M(.*),(.*):(.*)', pkt.decode())

            self.unicorn.mem_write(addr, n)
            return b'OK'

        except Exception as e:
            logger.warn(f'Error in mem_write: {e}')
            return b'E00'


    def cont(self, pkt):
        self.running.set()
        return b'OK'

    def step(self, pkt):
        self.unicorn.step()
        return b'S00'

    def step_signal(self, pkt):
        self.unicorn.step()
        return pkt[1:]

    def insert_breakpoint(self, pkt):
        addr, _ = match_hex('Z0,(.*),(.*)', pkt.decode())
        bpno = self.unicorn.add_breakpoint(addr)
        self.bps[bpno] = addr
        return b'OK'

    def remove_breakpoint(self, pkt):
        addr, _ = match_hex('z0,(.*),(.*)', pkt.decode())
        matches = []
        for n, a in self.bps.items():
            if a == addr:
                matches.append(n)
        if len(matches) == 0:
            logger.warn(f'GDB tried to remove non existing bp for {addr}')
            logger.info(self.bps)
            return b'E00'

        self.unicorn.del_breakpoint(n)
        self.bps.pop(n)
        return b'OK'

    def detach(self, pkt):
        logger.info("Exiting GDB server")
        if not self.target.state & TargetStates.EXITED:
            for bpno in self.bps.items():
                self.target.remove_breakpoint(bpno)
            self.target.cont()
        if self.conn._closed is False:
            self.send_packet(b'OK')
            self.conn.close()

    ### Sending and receiving

    def send_packet(self, pkt):
        if isinstance(pkt, str):
            raise Exception("Packet require bytes, not strings")

        self.send_raw(b'$%b#%02x' % (pkt, chksum(pkt)))


    def send_raw(self, raw_bytes):
        logger.debug(f'Sending data: {raw_bytes}')
        self.conn.send(raw_bytes)


    def check_breakpoint_hit(self):
        if self.running.is_set() is False:
            self.send_packet(b'S05')


    def receive_packet(self):
        pkt_finished = False
        pkt_receiving = False
        while pkt_finished is False:
            try:
                c = self.conn.recv(1)
            except socket.timeout:
                if self._do_shutdown.isSet():
                    self.send_packet(b'S03')
                    self.conn.close()
                    return
                self.check_breakpoint_hit()
                continue
            except ConnectionResetError:
                logger.warn("Remote side disconnected, continuing target")
                self.running.set()
                break

            if c == b'\x03':
                self.running.clear()
                self.send_packet(b'S02')
            elif c == b'$': # start of package
                pkt = b''
                pkt_receiving = True
            elif c == b'#': # end of package
                checksum = self.conn.recv(2)
                if int(checksum, 16) == chksum(pkt):
                    return pkt
                raise Exception('Checksum Error')

            elif pkt_receiving:
                pkt += c
