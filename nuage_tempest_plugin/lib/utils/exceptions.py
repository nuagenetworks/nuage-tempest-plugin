#
#
#    -----------------------WARNING----------------------------
#     This file is present to support Legacy Test Code only.
#     DO not use this file for writing the new tests.
#    ----------------------------------------------------------
#
#

from tempest.lib import exceptions
import testtools


class NuageRestClientException(exceptions.TempestException,
                               testtools.TestCase.failureException):
    pass


class MultipleChoices(NuageRestClientException):
    message = "Multiple choices"


class InvalidHttpSuccessCode(NuageRestClientException):
    message = "The success code is different than the expected one"


class NotFound(NuageRestClientException):
    message = "Object not found"


class Unauthorized(NuageRestClientException):
    message = 'Unauthorized'


class TimeoutException(NuageRestClientException):
    message = "Request timed out"


class BadRequest(NuageRestClientException):
    message = "Bad request"


class UnprocessableEntity(NuageRestClientException):
    message = "Unprocessable entity"


class ServerFault(NuageRestClientException):
    message = "Got server fault"


class Conflict(NuageRestClientException):
    message = "An object with that identifier already exists"


class ServerUnreachable(NuageRestClientException):
    message = "The server is not reachable via the configured network"


class TearDownException(NuageRestClientException):
    message = "CleanUp operation failed"


class ResponseWithNonEmptyBody(NuageRestClientException):
    message = ("RFC Violation! Response with %(status)d HTTP Status Code "
               "MUST NOT have a body")


class InvalidHTTPResponseBody(NuageRestClientException):
    message = "HTTP response body is invalid json or xml"


class UnexpectedResponseCode(NuageRestClientException):
    message = "Unexpected response code received"
