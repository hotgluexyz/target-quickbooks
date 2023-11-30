"""QuickBooks target class."""

from singer_sdk import typing as th
from target_hotglue.target import TargetHotglue

from target_quickbooks.sinks import (
    BillSink,
    ItemSink,
    InvoiceSink,
    TaxRateSink,
    CustomerSink,
    CreditNoteSink,
    DepartmentSink,
    PaymentTermSink,
    JournalEntrySink,
    PaymentMethodSink,
    SalesReceiptSink,
    DepositsSink
)
import io
import json


class TargetQuickBooks(TargetHotglue):
    """Sample target for QuickBooks."""

    name = "target-quickbooks"
    target_counter = {}
    MAX_PARALLELISM = 1
    config_jsonschema = th.PropertiesList(
        th.Property("client_id", th.StringType, required=True),
        th.Property("client_secret", th.StringType, required=True),
        th.Property("refresh_token", th.StringType, required=True),
        th.Property("access_token", th.StringType, required=True),
        th.Property("redirect_uri", th.StringType, required=True),
        th.Property("realmId", th.StringType, required=True),
        th.Property("is_sanbox", th.BooleanType, required=False),
    ).to_dict()
    SINK_TYPES = [
        BillSink,
        ItemSink,
        InvoiceSink,
        TaxRateSink,
        CustomerSink,
        CreditNoteSink,
        DepartmentSink,
        PaymentTermSink,
        JournalEntrySink,
        PaymentMethodSink,
        SalesReceiptSink,
        DepositsSink
    ]

    def _process_lines(self, file_input):
        """
        Custom _process_lines method that enables single sink processing,
        adding a counter dictionary to the target.

        This dictionary is accessed on the client.py, is_full() method, where
        we get the _total_records_read and compare with the target_counter.

        If we have the same number on both, we know that we have processed all
        and we are good to send the request.
        """
        lines = []
        for line in file_input:
            lines.append(line)
            line_dict = json.loads(line)
            if line_dict.get("type") != "RECORD":
                continue
            self.target_counter[line_dict["stream"]] = self.target_counter.get(
                line_dict["stream"], 0
            ) + 1

        super()._process_lines(lines)


if __name__ == "__main__":
    TargetQuickBooks.cli()
