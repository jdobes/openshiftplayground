import ujson
import falcon
import errata

DB_HOSTNAME = "postgresql-slave"
EXAMPLE_MSG = "Example:\ncurl http://<FQDN>/errata?pkg=<nvrea>\n"

cursor = errata.init_db(errata.DEFAULT_DB_NAME, errata.DEFAULT_DB_USER, errata.DEFAULT_DB_PASSWORD,
                        DB_HOSTNAME, errata.DEFAULT_DB_PORT)


class Test(object):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = "%s" % EXAMPLE_MSG

class Errata(object):
    def on_get(self, req, resp):
        parameters = req.params
        if not "pkg" in parameters:
            resp.status = falcon.HTTP_400
            resp.body = "Package not specified.\n%s" % EXAMPLE_MSG
        elif isinstance(parameters["pkg"], list):
            resp.status = falcon.HTTP_400
            resp.body = "Multiple packages specified.\n%s" % EXAMPLE_MSG
        else:
            resp.status = falcon.HTTP_200
            resp.body = ujson.dumps(errata.process(parameters["pkg"], cursor))

application = falcon.API()
application.add_route('/test', Test())
application.add_route('/errata', Errata())

