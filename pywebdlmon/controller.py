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
        self._ws_factory = WebSocketServerFactory("ws://0.0.0.0:6999")
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
        return self.index(request, 'html')

    def static(self, request, file):
        # TODO santize file
        return StaticFile(os.path.join('static', file)).render(request)

    def index(self, request, format):
        data = dict(
                    formats=dict(
                        html='/html',
                        json='/json',
                    ),
                   resources=dict(
                       instances=dict(
                           html='/html/instances',
                           json='/json/instances'
                           )
                       )
                   )
        return self._render(request, format, template='index', data=data)

    def _handler_helper(inner_func):
        def wrapper_func(self, request, format, transport, *args, **kwargs):
            if not isinstance(request, RequestishProtocol):
                if request.getHeader('Upgrade') == 'websocket':
                    # This magically changes the connection from HTTP to
                    # websockets.
                    request = wsmagic.upgrade(request, self._ws_factory)
            try:
                deferred = inner_func(self, request, format, transport, *args, **kwargs)
            except UnknownInstance, e:
                return self._error(request, format, 404, "Unknown DLMon Instance '%s'" % e)
            except UnknownStation, e:
                return self._error(request, format, 404, "Unknown Station: '%s'" % e)
            except UnknownFormat, e:
                return self._error(request, format, 400, "Unknown Format: '%s'" % e)
            except UnknownTransport, e:
                return self._error(request, format, 400, "Unknown Transport: '%s'" % e)
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
    def instance_status(self, request, format, transport, instance):
        instance = self.instances.get_instance(instance)
        deferred = instance.instance_status.get_format(format, immediate=is_sync(transport))
        return deferred

    @_handler_helper
    def station_list(self, request, format, transport, instance):
        instance = self.instances.get_instance(instance)
        deferred = instance.station_list.get_format(format, immediate=is_sync(transport))
        return deferred

    @_handler_helper
    def station_status(self, request, format, transport, instance, station):
        instance = self.instances.get_instance(instance)
        station = instance.instance_status.get_station(station)
        deferred = station.get_format(format, immediate=is_sync(transport))
        return deferred

    @_handler_helper
    def instances_handler(self, request, format, transport):
        deferred = self.instances.get_format(format, immediate=is_sync(transport))
        return deferred

    @_handler_helper
    def instance_update(self, request, format, transport, instance):
        instance = self.instances.get_instance(instance)
        deferred = instance.instance_update.get_format(format, immediate=is_sync(transport))
        return deferred


def get_dispatcher(cfg, instances):
    c = Controller(cfg, instances)
    d = Dispatcher()
    def connect(name, url):
        d.connect(name, url, c, action=name)
#    connect('root',            '/')
    connect('static',          '/static/{file}')
#    connect('index',           '/{format}')
    connect('instances_handler',       '/{transport}/dlmon/instances{.format}')
    connect('instance_status', '/{transport}/dlmon/instances/{instance}/status{.format}')
    connect('instance_update', '/{transport}/dlmon/instances/{instance}/update{.format}')
    connect('station_list',    '/{transport}/dlmon/instances/{instance}/stations{.format}')
    connect('station_status',  '/{transport}/dlmon/instances/{instance}/stations/{station}/status{.format}')
    return d
