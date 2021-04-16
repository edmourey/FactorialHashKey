# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from enum import Enum


class UnsupportedAlgorithm(Exception):
    def __init__(self, message, reason=None):
        super(UnsupportedAlgorithm, self).__init__(message)
        self._reason = reason


class AlreadyFinalized(Exception):
    pass


class AlreadyUpdated(Exception):
    pass


class NotYetFinalized(Exception):
    pass


class InvalidTag(Exception):
    pass


class InvalidSignature(Exception):
    pass


class InvalidMessageHash(Exception):
    pass


class InternalError(Exception):
    def __init__(self, msg, err_code):
        super(InternalError, self).__init__(msg)
        self.err_code = err_code


class InvalidKey(Exception):
    pass