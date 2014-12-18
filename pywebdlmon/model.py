#!/usr/bin/env python

from collections import defaultdict
import json

from twisted.python import log

from mako.exceptions import text_error_template

from kudu.twisted.util import ObservableDict

from antelope.brttpkt import NoData, Timeout
from antelope.orb import ORBOLDEST

from pywebdlmon.orb import StatusPktSource
import traceback

FORMATS = ('html', 'json')

REAP_TIMEOUT = 2.0


class UnknownInstance(Exception): pass

class UnknownStation(Exception): pass

class UnknownFormat(Exception): pass


class DataObject(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.template = cfg.templates.get_template(self.template_name)
        self.data = ObservableDict(html='', json='')

    def update(self, data, **kwargs):
        try:
            self.data['html'] = self.template.render(data=data, **kwargs).encode('utf-8')
        except Exception:
            log.err("Error rendering template")
            # twisted.log.msg munges the formatting; use print instead
            print text_error_template().render()
            raise
        #self.data['json'] = json.dumps(data, indent=4, sort_keys=True)
        self.data['json'] = json.dumps(data)

    def get_format(self, format, immediate):
        if self.data.has_key(format):
            return self.data.deferred_getitem(format, immediate)
        else:
            raise UnknownFormat(format)


class StationList(DataObject):
    template_name = 'stations.html'

    def __init__(self, instance_name, *args, **kwargs):
        self.instance_name = instance_name
        self.stations=set()
        super(StationList, self).__init__(*args, **kwargs)

    def update(self, updated_stations, dead_stations):
        self.stations -= dead_stations
        self.stations |= set(updated_stations['dataloggers'].iterkeys())
        data = {'station_list': list(self.stations)}
        super(StationList, self).update(data, instance=self.instance_name)


class StationStatus(DataObject):
    template_name = 'station_status.html'

    def __init__(self, instance_name, station_name, *args, **kwargs):
        self.instance_name = instance_name
        self.station_name = station_name
        super(StationStatus, self).__init__(*args, **kwargs)

    def update(self, station_status):
        data = dict(station_status=station_status)
        super(StationStatus, self).update(data, instance=self.instance_name, station=self.station_name)


class InstanceStatus(DataObject):
    template_name = 'instance_status.html'

    def __init__(self, instance_name, *args, **kwargs):
        self.instance_name = instance_name
        # Individual station statuses
        self.stations = dict()
        # Full instance status in
        self.status = dict(metadata=dict(), dataloggers=dict())
        super(InstanceStatus, self).__init__(*args, **kwargs)

    def since(self, pktno):
        """Returns a non-updating copy with only data logger records received
        since pktno."""
        # It's sort of inefficient b/c it also makes a whole new suite of
        # station objects; consider refactoring that code;
        new_self = InstanceStatus(self.instance_name, self.cfg)
        dataloggers = dict(((k,v) for (k,v) in self.status['dataloggers'].iteritems() if v['pktno'] > pktno))
        updated_stations = {
            'metadata': self.status['metadata'],
            'dataloggers': dataloggers
        }
        new_self.update(updated_stations)
        return new_self

    def update(self, updated_stations, dead_stations):
        # prune dead stations
        for stn in dead_stations:
            try:
                del self.status['dataloggers'][stn]
                del self.stations[stn]
            except (KeyError) as e:
                log.msg('model.update: key delete failed for %s: %s' % (stn, e))
        self.status['dataloggers'].update(updated_stations['dataloggers'])
        self.status['metadata'] = updated_stations['metadata']
        status = dict(metadata=self.status['metadata'], dataloggers=self.status['dataloggers'].values())
        data = dict(instance_status=status)
        super(InstanceStatus, self).update(data, instance=self.instance_name)
        # Now update my stations
        for station_name, station_status in updated_stations['dataloggers'].iteritems():
            try:
                station = self.stations[station_name]
            except KeyError:
                station = StationStatus(self.instance_name, station_name, self.cfg)
                self.stations[station_name] = station
            station.update(station_status)

    def get_station(self, station_name):
        try:
            return self.stations[station_name]
        except KeyError:
            raise UnknownStation(station_name)


class InstanceUpdate(DataObject):
    template_name = 'instance_update.html'

    def __init__(self, instance_name, *args, **kwargs):
        self.instance_name = instance_name
        super(InstanceUpdate, self).__init__(*args, **kwargs)

    def update(self, updated_stations):
        if len(updated_stations['dataloggers']) > 0:
            status = dict(updated_stations)
            status['dataloggers'] = status['dataloggers'].values()
            data = dict(instance_update=status)
            super(InstanceUpdate, self).update(data, instance=self.instance_name)


class Instance(DataObject):
    template_name = 'instance.html'

    def __init__(self, instance_name, sources, cfg, *args, **kwargs):
        self.live_stations = defaultdict(set)
        self.instance_name = instance_name
        #self.status_update = StatusUpdate()
        self.instance_status = InstanceStatus(instance_name, cfg)
        self.station_list = StationList(instance_name, cfg)
        self.instance_update = InstanceUpdate(instance_name, cfg)
        for source in sources:
            log.msg("connecting to src %r" % source.orbname)

            #try:
            #    # NOTE this is handy for debugging but maybe not for production
            #    log.msg("Rewinding to ORBOLDEST for src %r" % source.orbname)
            #    source.pause(1)
            #    source.seek(ORBOLDEST)
            #    source.resume()
            #except AttributeError:
            #    log.msg("This version of the Antelope bindings doesn't " + \
            #            "appear to support the seek method.")
            #    pass

            self.get(source)

        super(Instance, self).__init__(cfg, *args, **kwargs)

    def get(self, source):
        d = source.get()
        d.addCallbacks(self.on_get, errback=self.on_get_error,
                callbackKeywords=dict(source=source),
                errbackKeywords=dict(source=source), )
        return d

    def on_get_error(self, failure, source):
        failure.trap(Timeout, NoData)
        return self.get(source)

    def on_get(self, pfdict, source):
        r=None
        try:
            r = self.update(pfdict)
        except (Exception) as e:
            log.msg("Unknown error occurred during update:", traceback.format_exc())
        self.get(source)
        return r

    def update(self, updated_stations):
        # build list of dead stations to prune
        srcname = updated_stations['metadata']['srcname']
        live_stations = set([n for n in updated_stations['dataloggers'].iterkeys()])
        dead_stations = self.live_stations[srcname] - live_stations
        self.live_stations[srcname] = live_stations

        self.instance_status.update(updated_stations, dead_stations)
        self.station_list.update(updated_stations, dead_stations)
        self.instance_update.update(updated_stations)
        return
        # NOTE not sure yet what if any data instance should export. Probably
        # none. Some metadata would be handy though.
        data = dict()
        data['name'] = self.instance_name
        super(Instance, self).update(data)


class InstanceCollection(DataObject):
    template_name = 'instances.html'

    def __init__(self, cfg):
        super(InstanceCollection, self).__init__(cfg)
        instances = self.instances = {}
        for instance_name, srcs in cfg.instances.iteritems():
            sources = []
            for (srcname, srccfg) in srcs.iteritems():
                source = StatusPktSource(srcname, select=srccfg.match,
                                                         reject=srccfg.reject,
                                                         timeout=1)
                source.orbname = srcname
                sources.append(source)
            instance = Instance(instance_name, sources, cfg)
            instances[instance_name] = instance
            log.msg("New dlmon instance: %s" % instance_name)
        self.update()

    def update(self):
        data = dict(instances=self.instances.keys())
        super(InstanceCollection, self).update(data)

    def get_instance(self, instance_name):
        try:
            return self.instances[instance_name]
        except KeyError, e:
            raise UnknownInstance(instance_name)

