#!/usr/bin/env python
"""Orb Status Packet Interface"""

import time
from datetime import datetime
from calendar import timegm

from twisted.python import log

from antelope import stock
from antelope import brttpkt

from antelope.orb import ORBNEWEST
from antelope.brttpkt import NoData
from kudu.twisted.orbreapthread import OrbreapThr
from antelope.Pkt import Packet, UnstuffError
from threading import Lock


pktno = 0
pktmutex = Lock()

# MonkeyPatch antelope.stock due to missing PfCompileError (BRTT #686)
# This should work around a NameError being raised during unstuff
class PfCompileError(stock.PfError):
    pass

stock.PfCompileError=PfCompileError
# End MonkeyPatch


class StatusPktSource(OrbreapThr):
    """Represents a datalogger status data source, i.e. an orb reap thread."""

    def pfstring_to_pfdict(self, pfstring):
        """Return a dictionary from the 'string' field of a status packet which
        contains a parameter file."""
        pfstring = pfstring.strip('\0')
        pfptr = stock.ParameterFile()
        pfptr.pfcompile(pfstring)
        pfdict = pfptr.pf2dict()
        return pfdict

    def pfmorph(self, pfdict, timestamp, srcname):
        """Apply arcane transformations to incoming status data."""
        rx_timestamp = str(int(timegm(datetime.utcnow().utctimetuple())))
        # TODO Would it be more appropriate for this to live in model.py?
        dls = dict()
        if pfdict.has_key('dls'):
            dls = pfdict['dls']
        for sta in dls.keys():
            if 'opt' in dls[sta] and dls[sta]['opt'] != "-":
                dls[sta]['acok'] = 1 if 'acok' in dls[sta]['opt'] else 0
                dls[sta]['api'] = 1 if 'api' in dls[sta]['opt'] else 0
                dls[sta]['isp1'] = 1 if 'isp1' in dls[sta]['opt'] else 0
                dls[sta]['isp2'] = 1 if 'isp2' in dls[sta]['opt'] else 0
                dls[sta]['ti'] = 1 if 'ti' in dls[sta]['opt'] else 0
            else:
                dls[sta]['acok'] = "-"
                dls[sta]['api']  = "-"
                dls[sta]['isp1'] = "-"
                dls[sta]['isp2'] = "-"
                dls[sta]['ti']   = "-"
        pfdict['dls'] = dls

        # More arcane transforms
        updated_stations=dict(dataloggers={}, metadata={})
        for stn,status in pfdict['dls'].items():
            net, sep, stnonly = stn.partition('_')
            updated_stations['dataloggers'][stn] = {
                        'name': stn,
                        'values': status,
                        'timestamp': timestamp,
                        'rx_timestamp': rx_timestamp,
                        'pktno': pktno,
                        'srcname': srcname,
                    }
        updated_stations['metadata']['timestamp'] = timestamp
        updated_stations['metadata']['rx_timestamp'] = rx_timestamp
        updated_stations['metadata']['pktno'] = pktno
        updated_stations['metadata']['srcname'] = srcname
        return updated_stations

    def on_get(self, r):
        """OrpReapThread.get callback method."""
        global pktno
        pktid, srcname, timestamp, raw_packet = r
        pktno += 1

        # orb.h defines STASH_PKTID as -16 so negative ids are ok
        #if pktid < 0:
        #    log.msg(
        #        "%r reap %r (pktid #%d): skipping packet due to negative pktid"\
        #        % (self.orbname, srcname, pktid))
        #    raise NoData()

        log.msg("%r reap %r (pktid #%d): %d bytes" % (self.orbname, srcname,
                                                      pktid, len(raw_packet)))

        # TODO Should this jazz be pushed down the callback chain?
        try:
            packet = Packet(srcname, timestamp, raw_packet)
        except (Exception) as e:
            log.msg("%r reap %r: unStuff failed for pktid #%d: %s" % (
                self.orbname, srcname, pktid, e))
            # Pause/Seek/Resume Not available until 5.4
            #self.pause(1)
            #self.seek(ORBNEWEST)
            #self.resume()
            raise NoData()

        pkttypename = packet.type.name
        if pkttypename not in ('st', 'pf', 'stash'):
            raise NoData()
        try:
            pfstring = packet.string
            if pfstring is not None and pfstring != '':
                pfdict = self.pfstring_to_pfdict(pfstring)
            else:
                pfdict = packet.pf.pf2dict()
        except (Exception) as e:
            log.msg(
                "%r reap %r: converting pkt to dict failed for pktid #%d: %s"
                % (self.orbname, srcname, pktid, e))
            raise NoData()
        updated_stations = self.pfmorph(pfdict, timestamp, srcname)
        return updated_stations


    def get(self):
        d = super(StatusPktSource, self).get()
        d.addCallback(self.on_get)
        return d

