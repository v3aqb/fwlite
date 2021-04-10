
import bisect
import ipaddress
import logging


logger = logging.getLogger('ipfilter')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class NetFilter:
    def __init__(self):
        # keep this list sorted
        self.net_list_4 = []
        self.net_list_6 = []

    def add(self, network):
        if not any([isinstance(network, ipaddress.IPv4Network),
                    isinstance(network, ipaddress.IPv6Network)]):
            network = ipaddress.ip_network(network)

        network_list = self.net_list_4 if network.version == 4 else self.net_list_6

        if not network_list:
            network_list.append(network)
            return
        # check for overlap
        if self.contains(network.network_address):
            logger.error('%r already in this filter.', network)
            return
        if network.network_address > network_list[-1].network_address:
            network_list.append(network)
        else:
            # find proper location for this network to insert
            index = bisect.bisect(network_list, network)
            network_list.insert(index, network)

    def contains(self, item):
        if not any([isinstance(item, ipaddress.IPv4Network),
                    isinstance(item, ipaddress.IPv6Network)]):
            item = ipaddress.ip_network(item)

        network_list = self.net_list_4 if item.version == 4 else self.net_list_6

        if not network_list:
            return False

        index = bisect.bisect(network_list, item)

        if item.network_address in network_list[index - 1]:
            return network_list[index - 1]
        return False

    def __contains__(self, item):
        if self.contains(item):
            return True
        return False
