"""ISO 11783-3 Extended Transport Protocol (ETP).

ETP transports destination-specific messages from 1786 bytes up to
117 440 505 bytes. The state machine mirrors the J1939-21 TP RTS/CTS flow but
adds a Data Packet Offset (DPO) message between each CTS and its DT burst so
that the 1-byte DT sequence number can index a 24-bit packet count.

See ISO 11783-3 (2018 / 2025 draft) section 6.11.
"""
import logging
import time

from .parameter_group_number import ParameterGroupNumber
from .message_id import MessageId

logger = logging.getLogger(__name__)


class ISO11783_ETP:
    # Lower bound: TP covers up to 1785 bytes (ISO 11783-3 6.10)
    MIN_MESSAGE_SIZE = 1786
    # Upper bound: (2^24 - 1) packets * 7 bytes (ISO 11783-3 6.11.3)
    MAX_MESSAGE_SIZE = 117440505
    MAX_PACKETS = 0xFFFFFF

    # PF assignments per ISO 11783-3 6.11.5 / 6.11.6
    PF_CM = 200  # PGN 51200 (0xC800)
    PF_DT = 199  # PGN 50944 (0xC700)

    class ControlByte:
        """Control bytes for ETP.CM messages."""
        RTS = 20
        CTS = 21
        DPO = 22
        EOM_ACK = 23
        ABORT = 255

    class AbortReason:
        """ETP.Conn_Abort reasons (ISO 11783-3 Table 14)."""
        BUSY = 1
        RESOURCES = 2
        TIMEOUT = 3
        CTS_WHILE_DT = 4
        MAX_RETRANSMIT = 5
        UNEXPECTED_DT = 6
        BAD_SEQUENCE = 7
        DUPLICATE_SEQUENCE = 8
        UNEXPECTED_DPO = 9
        UNEXPECTED_DPO_PGN = 10
        DPO_NUM_PACKETS_GT_CTS = 11
        BAD_DPO_OFFSET = 12
        UNEXPECTED_CTS_PGN = 14
        CTS_REQUESTED_PACKETS_EXCEEDS_SIZE = 15
        ANY_OTHER_REASON = 250

    class Timeout:
        """Timing per ISO 11783-3 6.11.4.1 (inherited from TP)."""
        Th = 0.500
        T1 = 0.750
        T2 = 1.250
        T3 = 1.250
        T4 = 1.050

    class SendState:
        WAITING_CTS = 0
        SENDING_DPO = 1
        SENDING_IN_CTS = 2
        TRANSMISSION_FINISHED = 3

    def __init__(self, send_message, job_thread_wakeup, notify_subscribers,
                 max_cmdt_packets, minimum_dt_interval):
        self._send_message = send_message
        self._job_thread_wakeup = job_thread_wakeup
        self._notify_subscribers = notify_subscribers
        self._max_cmdt_packets = max_cmdt_packets
        self._minimum_dt_interval = minimum_dt_interval

        self._snd_buffer = {}
        self._rcv_buffer = {}

    @staticmethod
    def _buffer_hash(src_address, dest_address):
        return ((src_address & 0xFF) << 8) | (dest_address & 0xFF)

    # --- Public API ---------------------------------------------------------

    def start_send(self, src_address, dest_address, priority, pgn_value, data):
        """Start an ETP send session.

        Returns True if the session was opened (RTS already sent). Returns
        False if the size is out of range or an ETP session is already active
        for this (src, dest) pair.
        """
        message_size = len(data)
        if message_size < self.MIN_MESSAGE_SIZE:
            return False
        if message_size > self.MAX_MESSAGE_SIZE:
            logger.error("Message size %d exceeds ETP limit (%d)",
                         message_size, self.MAX_MESSAGE_SIZE)
            return False
        buffer_hash = self._buffer_hash(src_address, dest_address)
        if buffer_hash in self._snd_buffer:
            return False
        # PGN field in CM messages carries PS=0 for peer-to-peer transfer
        cm_pgn = pgn_value & 0x3FF00
        num_packages = (message_size + 6) // 7
        self._snd_buffer[buffer_hash] = {
            'pgn': cm_pgn,
            'priority': priority,
            'message_size': message_size,
            'num_packages': num_packages,
            'data': data,
            'state': self.SendState.WAITING_CTS,
            'deadline': time.time() + self.Timeout.T3,
            'src_address': src_address,
            'dest_address': dest_address,
            'next_packet_to_send': 0,
            'next_wait_on_cts': 0,
            'data_packet_offset': 0,
        }
        self._send_rts(src_address, dest_address, priority, cm_pgn, message_size)
        return True

    def async_job_thread(self, now):
        """Drive ETP send-buffer states and check receive-buffer timeouts.

        Returns the time the caller's job thread should wake next.
        """
        next_wakeup = now + 5.0

        for bufid in list(self._rcv_buffer):
            buf = self._rcv_buffer[bufid]
            if buf['deadline'] == 0:
                continue
            if buf['deadline'] > now:
                if next_wakeup > buf['deadline']:
                    next_wakeup = buf['deadline']
                continue
            logger.info("ETP receive timeout src 0x%02X dst 0x%02X",
                        buf['src_address'], buf['dest_address'])
            self._send_abort(buf['dest_address'], buf['src_address'],
                             self.AbortReason.TIMEOUT, buf['pgn'])
            del self._rcv_buffer[bufid]

        for bufid in list(self._snd_buffer):
            buf = self._snd_buffer[bufid]
            if buf['deadline'] == 0:
                continue
            if buf['deadline'] > now:
                if next_wakeup > buf['deadline']:
                    next_wakeup = buf['deadline']
                continue
            state = buf['state']
            if state == self.SendState.WAITING_CTS:
                logger.info("ETP WAITING_CTS timeout src 0x%02X dst 0x%02X",
                            buf['src_address'], buf['dest_address'])
                self._send_abort(buf['src_address'], buf['dest_address'],
                                 self.AbortReason.TIMEOUT, buf['pgn'])
                del self._snd_buffer[bufid]
            elif state == self.SendState.SENDING_DPO:
                # Sequence numbers restart at 1 for each new DPO group
                # (ISO 11783-3 6.11.5.5).
                burst_count = buf['next_wait_on_cts'] - buf['next_packet_to_send'] + 1
                self._send_dpo(buf['src_address'], buf['dest_address'],
                               burst_count, buf['data_packet_offset'], buf['pgn'])
                buf['state'] = self.SendState.SENDING_IN_CTS
                buf['burst_seq'] = 0
                buf['deadline'] = time.time()
                if next_wakeup > buf['deadline']:
                    next_wakeup = buf['deadline']
            elif state == self.SendState.SENDING_IN_CTS:
                while buf['next_packet_to_send'] <= buf['next_wait_on_cts']:
                    package = buf['next_packet_to_send']
                    offset = package * 7
                    payload = buf['data'][offset:]
                    if len(payload) > 7:
                        payload = payload[:7]
                    else:
                        while len(payload) < 7:
                            payload.append(255)
                    buf['burst_seq'] += 1
                    payload.insert(0, buf['burst_seq'])
                    buf['next_packet_to_send'] += 1
                    should_break = False
                    if package == buf['next_wait_on_cts']:
                        buf['state'] = self.SendState.WAITING_CTS
                        buf['deadline'] = time.time() + self.Timeout.T3
                        should_break = True
                    elif self._minimum_dt_interval is not None:
                        buf['deadline'] = time.time() + self._minimum_dt_interval
                        should_break = True
                    self._send_dt(buf['src_address'], buf['dest_address'], payload)
                    if should_break:
                        break
                if next_wakeup > buf['deadline']:
                    next_wakeup = buf['deadline']
            elif state == self.SendState.TRANSMISSION_FINISHED:
                del self._snd_buffer[bufid]
            else:
                logger.critical("ETP unknown send state %d", state)
                del self._snd_buffer[bufid]

        return next_wakeup

    def process_cm(self, mid, dest_address, data, timestamp):
        """Process an incoming ETP.CM message."""
        control_byte = data[0]
        pgn_value = data[5] | (data[6] << 8) | (data[7] << 16)
        src_address = mid.source_address

        if control_byte == self.ControlByte.RTS:
            self._handle_rts(src_address, dest_address, data, pgn_value)
        elif control_byte == self.ControlByte.CTS:
            self._handle_cts(src_address, dest_address, data, pgn_value)
        elif control_byte == self.ControlByte.DPO:
            self._handle_dpo(src_address, dest_address, data, pgn_value)
        elif control_byte == self.ControlByte.EOM_ACK:
            self._handle_eom_ack(mid, src_address, dest_address, timestamp, data, pgn_value)
        elif control_byte == self.ControlByte.ABORT:
            self._handle_abort(src_address, dest_address)
        else:
            logger.warning("ETP.CM unknown control_byte %d", control_byte)

    def process_dt(self, mid, dest_address, data, timestamp):
        """Process an incoming ETP.DT message."""
        sequence_number = data[0]
        src_address = mid.source_address
        buffer_hash = self._buffer_hash(src_address, dest_address)
        if buffer_hash not in self._rcv_buffer:
            return
        rcv = self._rcv_buffer[buffer_hash]

        if rcv['expected_dpo']:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.UNEXPECTED_DT, rcv['pgn'])
            del self._rcv_buffer[buffer_hash]
            return

        rcv['burst_received'] += 1
        if sequence_number != rcv['burst_received']:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.BAD_SEQUENCE, rcv['pgn'])
            del self._rcv_buffer[buffer_hash]
            return

        # Absolute packet number = DPO + sequence; data lives at (abs-1)*7.
        absolute_packet = rcv['cts_dpo'] + sequence_number
        write_offset = (absolute_packet - 1) * 7
        if len(rcv['data']) < write_offset + 7:
            rcv['data'].extend([0xFF] * (write_offset + 7 - len(rcv['data'])))
        rcv['data'][write_offset:write_offset + 7] = list(data[1:8])

        if absolute_packet >= rcv['num_packages']:
            if rcv['burst_received'] == rcv['dpo_packets'] or absolute_packet * 7 >= rcv['message_size']:
                rcv['data'] = rcv['data'][:rcv['message_size']]
                self._send_eom_ack(dest_address, src_address, rcv['message_size'], rcv['pgn'])
                self._notify_subscribers(mid.priority, rcv['pgn'], src_address,
                                         dest_address, timestamp, rcv['data'])
                del self._rcv_buffer[buffer_hash]
                self._job_thread_wakeup()
                return

        if rcv['burst_received'] >= rcv['dpo_packets']:
            remaining = rcv['num_packages'] - absolute_packet
            burst = min(rcv['cts_num_packets'], remaining)
            rcv['cts_dpo'] = absolute_packet  # next CTS sends next=absolute+1, so DPO=next-1
            rcv['dpo_packets'] = burst
            rcv['burst_received'] = 0
            rcv['expected_dpo'] = True
            self._send_cts(dest_address, src_address, burst, absolute_packet + 1, rcv['pgn'])
            rcv['deadline'] = time.time() + self.Timeout.T2
            self._job_thread_wakeup()
            return

        rcv['deadline'] = time.time() + self.Timeout.T1
        self._job_thread_wakeup()

    # --- ETP.CM handlers ----------------------------------------------------

    def _handle_rts(self, src_address, dest_address, data, pgn_value):
        message_size = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24)
        buffer_hash = self._buffer_hash(src_address, dest_address)
        if buffer_hash in self._rcv_buffer:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.BUSY, pgn_value)
            return
        if message_size < self.MIN_MESSAGE_SIZE or message_size > self.MAX_MESSAGE_SIZE:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.ANY_OTHER_REASON, pgn_value)
            return
        num_packages = (message_size + 6) // 7
        burst = min(self._max_cmdt_packets, num_packages, 0xFF)
        self._rcv_buffer[buffer_hash] = {
            'pgn': pgn_value,
            'message_size': message_size,
            'num_packages': num_packages,
            'data': [],
            'deadline': time.time() + self.Timeout.T2,
            'src_address': src_address,
            'dest_address': dest_address,
            'cts_num_packets': burst,
            'cts_dpo': 0,
            'expected_dpo': True,
            'dpo_packets': 0,
            'burst_received': 0,
        }
        self._send_cts(dest_address, src_address, burst, 1, pgn_value)
        self._job_thread_wakeup()

    def _handle_cts(self, src_address, dest_address, data, pgn_value):
        num_packets = data[1]
        next_packet_number = data[2] | (data[3] << 8) | (data[4] << 16)
        buffer_hash = self._buffer_hash(dest_address, src_address)
        if buffer_hash not in self._snd_buffer:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.RESOURCES, pgn_value)
            return
        buf = self._snd_buffer[buffer_hash]
        if buf['pgn'] != pgn_value:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.UNEXPECTED_CTS_PGN, pgn_value)
            return
        if num_packets == 0:
            # Hold the connection open (ISO 11783-3 6.11.5.4)
            buf['deadline'] = time.time() + self.Timeout.Th
            self._job_thread_wakeup()
            return
        if next_packet_number < 1 or next_packet_number > buf['num_packages']:
            self._send_abort(buf['src_address'], buf['dest_address'],
                             self.AbortReason.CTS_REQUESTED_PACKETS_EXCEEDS_SIZE,
                             pgn_value)
            del self._snd_buffer[buffer_hash]
            return
        remaining = buf['num_packages'] - (next_packet_number - 1)
        if num_packets > remaining:
            num_packets = remaining
        buf['next_packet_to_send'] = next_packet_number - 1
        buf['next_wait_on_cts'] = buf['next_packet_to_send'] + num_packets - 1
        buf['data_packet_offset'] = next_packet_number - 1
        buf['state'] = self.SendState.SENDING_DPO
        buf['deadline'] = time.time()
        self._job_thread_wakeup()

    def _handle_dpo(self, src_address, dest_address, data, pgn_value):
        num_packets = data[1]
        data_packet_offset = data[2] | (data[3] << 8) | (data[4] << 16)
        buffer_hash = self._buffer_hash(src_address, dest_address)
        if buffer_hash not in self._rcv_buffer:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.UNEXPECTED_DPO, pgn_value)
            return
        rcv = self._rcv_buffer[buffer_hash]
        if rcv['pgn'] != pgn_value:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.UNEXPECTED_DPO_PGN, pgn_value)
            del self._rcv_buffer[buffer_hash]
            return
        if not rcv['expected_dpo']:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.UNEXPECTED_DPO, pgn_value)
            del self._rcv_buffer[buffer_hash]
            return
        if num_packets > rcv['cts_num_packets']:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.DPO_NUM_PACKETS_GT_CTS, pgn_value)
            del self._rcv_buffer[buffer_hash]
            return
        if data_packet_offset != rcv['cts_dpo']:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.BAD_DPO_OFFSET, pgn_value)
            del self._rcv_buffer[buffer_hash]
            return
        rcv['dpo_packets'] = num_packets
        rcv['burst_received'] = 0
        rcv['expected_dpo'] = False
        rcv['deadline'] = time.time() + self.Timeout.T1
        self._job_thread_wakeup()

    def _handle_eom_ack(self, mid, src_address, dest_address, timestamp, data, pgn_value):
        buffer_hash = self._buffer_hash(dest_address, src_address)
        if buffer_hash not in self._snd_buffer:
            self._send_abort(dest_address, src_address,
                             self.AbortReason.RESOURCES, pgn_value)
            return
        self._notify_subscribers(mid.priority, pgn_value, src_address,
                                 dest_address, timestamp, data)
        self._snd_buffer[buffer_hash]['state'] = self.SendState.TRANSMISSION_FINISHED
        self._snd_buffer[buffer_hash]['deadline'] = time.time()
        self._job_thread_wakeup()

    def _handle_abort(self, src_address, dest_address):
        # Either party may abort. Drop any matching session in either direction.
        snd_hash = self._buffer_hash(dest_address, src_address)
        rcv_hash = self._buffer_hash(src_address, dest_address)
        if snd_hash in self._snd_buffer:
            self._snd_buffer[snd_hash]['state'] = self.SendState.TRANSMISSION_FINISHED
            self._snd_buffer[snd_hash]['deadline'] = time.time()
        if rcv_hash in self._rcv_buffer:
            del self._rcv_buffer[rcv_hash]
        self._job_thread_wakeup()

    # --- ETP.CM and ETP.DT senders -----------------------------------------
    # Multi-byte fields are little-endian; PGN field carries PS=0.

    def _send_rts(self, src_address, dest_address, priority, pgn_value, message_size):
        pgn = ParameterGroupNumber(0, self.PF_CM, dest_address)
        mid = MessageId(priority=priority, parameter_group_number=pgn.value,
                        source_address=src_address)
        self._send_message(mid.can_id, True, [
            self.ControlByte.RTS,
            message_size & 0xFF, (message_size >> 8) & 0xFF,
            (message_size >> 16) & 0xFF, (message_size >> 24) & 0xFF,
            pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF,
        ])

    def _send_cts(self, src_address, dest_address, num_packets, next_packet, pgn_value):
        pgn = ParameterGroupNumber(0, self.PF_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value,
                        source_address=src_address)
        self._send_message(mid.can_id, True, [
            self.ControlByte.CTS,
            num_packets & 0xFF,
            next_packet & 0xFF, (next_packet >> 8) & 0xFF, (next_packet >> 16) & 0xFF,
            pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF,
        ])

    def _send_dpo(self, src_address, dest_address, num_packets, offset, pgn_value):
        pgn = ParameterGroupNumber(0, self.PF_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value,
                        source_address=src_address)
        self._send_message(mid.can_id, True, [
            self.ControlByte.DPO,
            num_packets & 0xFF,
            offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
            pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF,
        ])

    def _send_eom_ack(self, src_address, dest_address, message_size, pgn_value):
        pgn = ParameterGroupNumber(0, self.PF_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value,
                        source_address=src_address)
        self._send_message(mid.can_id, True, [
            self.ControlByte.EOM_ACK,
            message_size & 0xFF, (message_size >> 8) & 0xFF,
            (message_size >> 16) & 0xFF, (message_size >> 24) & 0xFF,
            pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF,
        ])

    def _send_abort(self, src_address, dest_address, reason, pgn_value):
        pgn = ParameterGroupNumber(0, self.PF_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value,
                        source_address=src_address)
        self._send_message(mid.can_id, True, [
            self.ControlByte.ABORT,
            reason, 0xFF, 0xFF, 0xFF,
            pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF,
        ])

    def _send_dt(self, src_address, dest_address, payload):
        pgn = ParameterGroupNumber(0, self.PF_DT, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value,
                        source_address=src_address)
        self._send_message(mid.can_id, True, payload)
