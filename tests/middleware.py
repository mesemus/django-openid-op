import traceback


class RequestLoggerMiddleware(object):

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _body_to_log = request.body
        response = None
        error = None
        try:
            response = self.get_response(request)
        except BaseException as e:
            error = e
        finally:
            print("-------------------------------------")
            print('Request: ')
            print('    path    :', request.path)
            print('    method  :', request.method)
            print('    AUTH    :', request.META.get('HTTP_AUTHORIZATION'))
            print('    GET     :', request.GET)
            print('    POST    :', request.POST)
            if _body_to_log:
                print('    BODY    :', _body_to_log.decode('utf-8', errors='ignore').replace('\n', '                ')[:200])
            if response:
                print('Response:')
                print('    status  :', response.status_code)
                print('    headers :')
                for h in response.items():
                    print('             ', h)
                if response.content:
                    print('    content :', response.content.decode('utf-8', errors='ignore').replace('\n', '                ')[:200])

                return response

            if error:
                print('Error:', traceback.format_exc().replace('\n', '                '))
