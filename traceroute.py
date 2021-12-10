# #################################################################################################################### #
# Imports                                                                                                              #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live
        __rtt = 0

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getRtt(self):
            return self.__rtt

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setRtt(self, rtt):
            self.__rtt = rtt

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            print("Sequence Number-Expected value: %d, Actual value: %d" % (self.getPacketSequenceNumber(), icmpReplyPacket.getIcmpSequenceNumber())) if self.__DEBUG_IcmpPacket else 0
            print("Packet Identifier-Expected value: %d, Actual value: %d" % (self.getPacketIdentifier(), icmpReplyPacket.getIcmpIdentifier())) if self.__DEBUG_IcmpPacket else 0
            print("Raw Data-Expected value: %s, Actual value: %s" % (self.getDataRaw(), icmpReplyPacket.getIcmpData())) if self.__DEBUG_IcmpPacket else 0
            a = False
            b = False
            c = False
            if (self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber()):
                a = True
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
            if (self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier()):
                b = True
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            if (self.getDataRaw() == icmpReplyPacket.getIcmpData()):
                c = True
                icmpReplyPacket.setIcmpDataRaw_isValid(True)
            if (a & b & c):
                icmpReplyPacket.setIsValidResponse(True)
        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    self.setRtt((timeReceived - pingStartTime) * 1000)
                    if icmpType == 11:                          # Time Exceeded
                        errors = [
                                    "Time to Live exceeded in Transit",
                                    "Fragment Reassembly Time Exceeded"
                                    ]
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    Description=%s    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    errors[icmpCode],
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:                         # Destination Unreachable
                        errors = [
                                    "Net Unreachable",
                                    "Host Unreachable",
                                    "Protocol Unreachable",
                                    "Port Unreachable",
                                    "Fragmentation Needed and Don't Fragment was Set",
                                    "Source Route Failed",
                                    "Destination Network Unknown",
                                    "Destination Host Unknown",
                                    "Source Host Isolated",
                                    "Communication with Destination Network is Administratively Prohibited",
                                    "Communication with Destination Host is Administratively Prohibited",
                                    "Destination Network Unreachable for Type of Service",
                                    "Destination Host Unreachable for Type of Service",
                                    "Communication Administratively Prohibited",
                                    "Host Precedence Violation",
                                    "Precedence cutoff in effect"
                                    ]
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    Description=%s    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      errors[icmpCode],
                                      addr[0]
                                  )
                              )

                    elif icmpType == 12:
                        errors = [
                                    "Pointer indicates the error",
                                    "Missing a Required Option",
                                    "Bad Length"
                                    ]
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    Description=%s    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      errors[icmpCode],
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self.getPacketIdentifier(), self.getPacketSequenceNumber(), self.getDataRaw())
                        return True      # Echo reply is the end and therefore should return
                        #the return value is used to determine if packet is received

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        #similar to sendEchoRequest except that it only traces all hops between source and destination
        def traceHops(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            MAX_HOPS = 30
            print("Traceroute to {} ({}), Max hops: 30".format(self.__icmpTarget, self.__destinationIpAddress))
            for i in range(MAX_HOPS):
                addr = None
                mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                mySocket.settimeout(self.__ipTimeout)
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', i))
                try:
                    mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                    timeLeft = 30
                    pingStartTime = time.time()
                    startedSelect = time.time()
                    whatReady = select.select([mySocket], [], [], timeLeft)
                    endSelect = time.time()
                    howLongInSelect = (endSelect - startedSelect)
                    if whatReady[0] == []:
                        print("  *        *        *        *        *    Request timed out.")
                    recvPacket, addr = mySocket.recvfrom(1024)
                    timeReceived = time.time()
                    timeLeft = timeLeft - howLongInSelect
                    if addr == None:
                        print("{} Address: * * * | rtt: {} ms".format(i, (timeReceived - pingStartTime) * 1000))
                    else:
                        print("{} Address: {} | rtt: {} ms".format(i, addr[0], (timeReceived - pingStartTime) * 1000))
                    if timeLeft <= 0:
                        print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    else:
                        #icmpType, icmpCode = recvPacket[20:22]
                        self.setRtt((timeReceived - pingStartTime) * 1000)
                except timeout:
                    print("  *        *        *        *        *    Request timed out (By Exception).")
                finally:
                    mySocket.close()
                if addr[0] == self.__destinationIpAddress:
                    break

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpDataRaw_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        # ############################################################################################################ #
        
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def getIcmpSequenceNumber_isvalid(self):
            return self.__IcmpSequenceNumber_isValid

        def getIcmpDataRaw_isValid(self):
            return self.__IcmpDataRaw_isValid

        def isValidResponse(self):
            return self.__isValidResponse

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        # ############################################################################################################ #
        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__IcmpSequenceNumber_isValid = booleanValue

        def setIcmpDataRaw_isValid(self, booleanValue):
            self.__IcmpDataRaw_isValid = booleanValue
        
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, origin_id, origin_sn, origin_rd):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            if (self.getIcmpIdentifier_isValid() == False):
                print("Identifier is invalid. Expected value: %d Actual value: %d" % (origin_id, self.getIcmpIdentifier()))
            if (self.getIcmpSequenceNumber_isvalid() == False):
                print("Sequence number is invalid. Expected value: %d Actual value: %d" % (origin_sn, self.getIcmpSequenceNumber()))
            if (self.getIcmpDataRaw_isValid() == False):
                print("Sequence number is invalid. Expected value: %s Actual value: %s" % (origin_rd, self.getIcmpData()))
            print("\n")

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # stores each rtt in a list and calculate the min, max, average after the loop
        # as well as packet loss rate
        rtt = []
        packet_loss = 4
        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            receive = icmpPacket.sendEchoRequest()                                                # Build IP
            if (receive == True):
                packet_loss -= 1
            rtt.append(icmpPacket.getRtt())

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
        min_rtt = min(rtt)
        max_rtt = max(rtt)
        avg_rtt = 0
        for t in rtt:
            avg_rtt += t
        avg_rtt /= 4
        packet_received = 4 - packet_loss
        loss_percent = packet_loss / 4 * 100
        print("Minimum RTT: %f    Maximum RTT: %f    Average RTT: %f" % (min_rtt, max_rtt, avg_rtt))
        print("4 packets transmitted, {} received, {}% packet loss".format(packet_received, loss_percent))
        print("\n")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # similar to __sendIcmpEchoRequest but calls traceHops instead
        icmpPacket = IcmpHelperLibrary.IcmpPacket()
        randomIdentifier = (os.getpid() & 0xffff)
        packetIdentifier = randomIdentifier
        icmpPacket.buildPacket_echoRequest(packetIdentifier, 0)
        icmpPacket.setIcmpTarget(host)
        icmpPacket.traceHops()

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)

# #################################################################################################################### #
# main()                                                                                                               #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("oregonstate.edu")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    icmpHelperPing.sendPing("www.baidu.com")
    icmpHelperPing.traceRoute("www.baidu.com")


if __name__ == "__main__":
    main()
