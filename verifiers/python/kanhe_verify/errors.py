# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Errors raised while verifying."""


class VerifyError(Exception):
    """The evidence does not verify. The message says why, for people."""


class UsageError(Exception):
    """The command line or an input file given beside the bundle is wrong."""


class ApprovalError(VerifyError):
    """An approval, an approval rule, or a guardian setting that the ledger
    refuses (spec v0.20, sections 5.1 and 5.2). `why` names the rule broken,
    as the test vectors do."""

    def __init__(self, why: str, message: str):
        super().__init__(message)
        self.why = why
