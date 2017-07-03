from pysnmp.hlapi import *

# project
from checks import AgentCheck, CheckException


class SnmpTopologyCheck(AgentCheck):
    INSTANCE_TYPE = "snmp_topology"

    # pysnmp default values
    DEFAULT_RETRIES = 5
    DEFAULT_TIMEOUT = 1

    # MIBs
    MIB_tcpConnTable = '1.3.6.1.2.1.6.13.1'
    MIB_tcpConnState = MIB_tcpConnTable + '.1'
    MIB_tcpConnLocalAddress = MIB_tcpConnTable + '.2'
    MIB_tcpConnLocalPort = MIB_tcpConnTable + '.3'
    MIB_tcpConnRemAddress = MIB_tcpConnTable + '.4'
    MIB_tcpConnRemPort = MIB_tcpConnTable + '.5'

    # tcpConnState values
    TCP_CONNECTION_STATE_ESTABLISHED = 5

    # snmp engine
    snmp_engine = SnmpEngine()

    def check(self, instance):
        # TODO service check?
        timeout = int(instance.get('timeout', self.DEFAULT_TIMEOUT))
        retries = int(instance.get('retries', self.DEFAULT_RETRIES))

        community_string = self.get_community_string(instance)
        (ip_address, transport_target) = self.get_transport_target(instance, timeout, retries)

        instance_key = {
            "type": self.INSTANCE_TYPE,
            "url": ip_address
        }

        # TODO can we chunk the responses?
        walk_iterator = nextCmd(self.snmp_engine,
                                CommunityData(community_string),
                                transport_target,
                                ContextData(),
                                ObjectType(ObjectIdentity(self.MIB_tcpConnState)),
                                lexicographicMode=False,
                                lookupMib=False)

        for (errorIndication, errorStatus, errorIndex, varBinds) in walk_iterator:
            if errorIndication:
                self.log.error(errorIndication)
                break
            elif errorStatus:
                self.log.error('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for varBind in varBinds:
                    (oid, tcpConnState) = varBind
                    self.log.debug("Received OID & tcpConnState %s" % ' = '.join([x.prettyPrint() for x in varBind]))
                    self.parse_tcpConnState(tcpConnState, str(oid), community_string, transport_target, instance_key)

    @classmethod
    def get_transport_target(cls, instance, timeout, retries):
        '''
        Generate a Transport target object based on the instance's configuration
        '''
        if "ip_address" not in instance:
            raise CheckException("An IP address needs to be specified")
        ip_address = instance["ip_address"]
        port = int(instance.get("port", 161)) # Default SNMP port
        return ip_address, UdpTransportTarget((ip_address, port), timeout=timeout, retries=retries)

    @classmethod
    def get_community_string(cls, instance):
        '''
        Get the Community String from the instance's configuration
        '''
        if "community_string" not in instance:
            raise CheckException("A community string needs to be specified")
        community_string = instance["community_string"]
        return community_string

    def parse_tcpConnState(self, state, oid, community_string, transport_target, instance_key):

        # we are only interested in established connections
        if state == self.TCP_CONNECTION_STATE_ESTABLISHED and str(oid).startswith(self.MIB_tcpConnState):
            stripped_oid = oid[len(self.MIB_tcpConnState):]  # remove tcpConnState prefix from the received OID

            local_address_oid = self.MIB_tcpConnLocalAddress + stripped_oid
            local_port_oid = self.MIB_tcpConnLocalPort + stripped_oid
            remote_address_oid = self.MIB_tcpConnRemAddress + stripped_oid
            remote_port_oid = self.MIB_tcpConnRemPort + stripped_oid

            # TODO investigate whether we can derive incoming and outgoing connections from local and remote ips.

            # TODO split off
            iter = getCmd(self.snmp_engine,
                          CommunityData(community_string),
                          transport_target,
                          ContextData(),
                          ObjectType(ObjectIdentity(local_address_oid)),
                          ObjectType(ObjectIdentity(local_port_oid)),
                          ObjectType(ObjectIdentity(remote_address_oid)),
                          ObjectType(ObjectIdentity(remote_port_oid)))

            for (errorIndication, errorStatus, errorIndex, varBinds) in iter:
                # TODO error handling

                # TODO check that is a tuple4
                # TODO remove magic numbers
                local_ip = IpAddress.prettyPrint(varBinds[0][1])
                local_port = varBinds[1][1]
                remote_ip = IpAddress.prettyPrint(varBinds[2][1])
                remote_port = varBinds[3][1]

                local = "%s:%d" % (local_ip, local_port)
                remote = "%s:%d" % (remote_ip, remote_port)

                self.relation(instance_key, local, remote, {"name": "uses"})
