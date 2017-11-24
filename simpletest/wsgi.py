import falcon

class ApiCallOne(object):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = "[one]"

class ApiCallTwo(object):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = "[two]"

application = falcon.API()
application.add_route('/one', ApiCallOne())
application.add_route('/two', ApiCallTwo())

