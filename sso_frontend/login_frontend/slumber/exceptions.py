class SlumberBaseException(Exception): # pragma: no cover
    """
    All Slumber exceptions inherit from this exception.
    """


class SlumberHttpBaseException(SlumberBaseException): # pragma: no cover
    """
    All Slumber HTTP Exceptions inherit from this exception.
    """

    def __init__(self, *args, **kwargs):
        for key, value in kwargs.iteritems():
            setattr(self, key, value)
        super(SlumberHttpBaseException, self).__init__(*args)


class HttpClientError(SlumberHttpBaseException): # pragma: no cover
    """
    Called when the server tells us there was a client error (4xx).
    """


class HttpServerError(SlumberHttpBaseException): # pragma: no cover
    """
    Called when the server tells us there was a server error (5xx).
    """


class SerializerNoAvailable(SlumberBaseException): # pragma: no cover
    """
    There are no available Serializers.
    """


class SerializerNotAvailable(SlumberBaseException): # pragma: no cover
    """
    The chosen Serializer is not available.
    """


class ImproperlyConfigured(SlumberBaseException): # pragma: no cover
    """
    Slumber is somehow improperly configured.
    """
