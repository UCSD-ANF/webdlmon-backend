#!/usr/bin/env python

import json
import os.path

from twisted.python import log
from twisted.web import server
from twisted.web.static import File as StaticFile

from txroutes import Dispatcher

from autobahn.websocket import WebSocketServerFactory

from mako import exceptions

from pywebdlmon.model import UnknownInstance, UnknownStation, UnknownFormat
from pywebdlmon import wsmagic
from pywebdlmon.ws import RequestishProtocol
from pywebdlmon import orb


class UnknownTransport(Exception): pass

class WebsocketsError(Exception): pass

def is_sync(transport):
    if transport == 'http':
        return True
    elif transport == 'ws':
        return False
    raise UnknownTransport(transport)

class Controller(object):
    def __init__(self, cfg, instances):
        self.cfg = cfg
        self.instances = instances
        self._ws_factory = WebSocketServerFactory("ws://%s:%d" % (cfg.bind_address, cfg.port))
        self._ws_factory.protocol = RequestishProtocol

    def _error(self, request, format, code, msg):
        # TODO return JSON error object for json queries
        request.setHeader("content-type", "text/html")
        request.setHeader("response-code", code)
        if format == 'json':
            err = dict(error=dict(code=code, msg=msg))
            buffer = json.dumps(err)
        else:
            template = self.cfg.templates.get_template('error.html')
            buffer = str(template.render(cfg=self.cfg, code=code, msg=msg))
        request.write(buffer)
        request.finish()
        return server.NOT_DONE_YET

    def root(self, request):
        return self.cfg.templates.get_template('index.html').render().encode('utf-8')

    def static(self, request, file):
        # TODO santize file
        return StaticFile(os.path.join('static', file)).render(request)

    def _handler_helper(inner_func):
        def wrapper_func(self, request, format, transport, *args, **kwargs):
            if not isinstance(request, RequestishProtocol):
                if request.getHeader('Upgrade') == 'websocket':
                    # Change the connection from HTTP to websockets.
                    request = wsmagic.upgrade(request, self._ws_factory)
            if not hasattr(request, 'repeat'):
                # Handlers can query this flag to change their behavior for the
                # first request, e.g. to send the current state first then
                # subsequent updates.
                request.repeat = False
            try:
                deferred = inner_func(self, request, format, transport, *args, **kwargs)
                if deferred is server.NOT_DONE_YET:
                    return deferred
            except UnknownInstance, e:
                return self._error(request, format, 404, "Unknown DLMon Instance '%s'" % e)
            except UnknownStation, e:
                return self._error(request, format, 404, "Unknown Station: '%s'" % e)
            except UnknownFormat, e:
                return self._error(request, format, 400, "Unknown Format: '%s'" % e)
            except UnknownTransport, e:
                return self._error(request, format, 400, "Unknown Transport: '%s'" % e)
            request.repeat = True
            def cb(buffer):
                assert buffer is not None
                request.setHeader("response-code", 200)
                if format == 'json':
                    request.setHeader("content-type", "application/json")
                    # JSONP magic
                    if request.args.has_key('callback'):
                            request.setHeader("content-type", "application/javascript")
                            buffer = request.args['callback'][0] + '(' + buffer + ')'
                elif format == 'html':
                    request.setHeader("content-type", "text/html")
                else:
                    return self._error(request, format, 400, "Unknown Format: '%s'" % format)
                request.write(buffer)
                if isinstance(request, RequestishProtocol):
                    wrapper_func(self, request, format, transport, *args, **kwargs)
                else:
                    request.finish()
                    return server.NOT_DONE_YET
            deferred.addCallback(cb)
            return server.NOT_DONE_YET
        return wrapper_func

    @_handler_helper
    def station_list(self, request, format, transport, instance):
        instance = self.instances.get_instance(instance)
        if request.repeat:
            deferred = instance.station_list.get_format(format, immediate=is_sync(transport))
        else:
            deferred = instance.station_list.get_format(format, immediate=True)
        return deferred

    @_handler_helper
    def station_status(self, request, format, transport, instance, station):
        instance = self.instances.get_instance(instance)
        station = instance.instance_status.get_station(station)
        if request.repeat:
            deferred = station.get_format(format, immediate=is_sync(transport))
        else:
            # Send full status immediately.
            deferred = station.get_format(format, immediate=True)
        return deferred

    @_handler_helper
    def instances_handler(self, request, format, transport):
        # This data is static during runtime.
        deferred = self.instances.get_format(format, immediate=True)
        return deferred

    @_handler_helper
    def instance_status(self, request, format, transport, instance):
        instance = self.instances.get_instance(instance)
        if request.repeat:
            deferred = instance.instance_update.get_format(format, immediate=is_sync(transport))
        elif 'since' in request.args:
            try:
                since = int(request.args['since'][0])
            except ValueError, e:
                return self._error(request, format, 400, "Cannot convert since to int: '%s'" % e)
            if since > orb.pktno:
                return self._error(request, format, 400, "Since value in future: '%s'" % since)
            deferred = instance.instance_status.since(since).get_format(format, immediate=True)
        else:
            # Send full status immediately.
            deferred = instance.instance_status.get_format(format, immediate=True)
        return deferred


def get_dispatcher(cfg, instances):
    c = Controller(cfg, instances)
    d = Dispatcher()
    def connect(name, url):
        d.connect(name, url, c, action=name)
    connect('root',              '/')
    connect('static',            '/static/{file}')
    connect('instances_handler', '/{transport}/dlmon/instances{.format}')
    connect('instance_status',   '/{transport}/dlmon/instances/{instance}/status{.format}')
    connect('station_list',      '/{transport}/dlmon/instances/{instance}/stations{.format}')
    connect('station_status',    '/{transport}/dlmon/instances/{instance}/stations/{station}/status{.format}')
    return d

