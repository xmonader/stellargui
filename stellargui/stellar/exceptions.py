
class TemporaryProblem(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return self.message


class NoTrustLine(Exception):
    def __init__(self):
        super().__init__("Receiver has no trustline")

    def __str__(self):
        return "Receiver has no trustline"


class UnAuthorized(Exception):
    def __init__(self, transaction_xdr):
        self.transaction_xdr = transaction_xdr
        super().__init__("Unauthorized or not enough signatures")

    def __str__(self):
        return f"Unauthorized or not enough signatures for transaction envelope {self.transaction_xdr}"


class TooLate(TemporaryProblem):
    def __init__(self):
        super().__init__("The transaction failed to be submitted to the network in time")
