from os import environ
import requests
import json
from singer_sdk.sinks import BatchSink
from datetime import datetime
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes
from singer_sdk.plugin_base import PluginBase
from typing import Any, Dict, List, Mapping, Optional, Union
import re

from target_quickbooks.mapper import customer_from_unified, item_from_unified, invoice_from_unified


class QuickBooksSink(BatchSink):
    """QuickBooks target sink class."""

    max_size = 30  # Max records to write in one batch

    def __init__(
        self,
        target: PluginBase,
        stream_name: str,
        schema: Dict,
        key_properties: Optional[List[str]],
    ) -> None:
        super().__init__(target, stream_name, schema, key_properties)

        # Save config for refresh_token saving
        self.config_file = target.config_file

        # Instantiate Client
        self.instantiate_client()

        # Get reference data
        self.get_reference_data()

    def instantiate_client(self):
        self.last_refreshed = None
        self.access_token = self.config.get("access_token")
        self.refresh_token = self.config.get("refresh_token")

        client_id = self.config.get("client_id")
        client_secret = self.config.get("client_secret")
        redirect_uri = self.config.get("redirect_uri")

        if self.config.get("is_sandbox"):
            environment = "sandbox"
        else:
            environment = "production"

        self.auth_client = AuthClient(
            client_id, client_secret, redirect_uri, environment
        )

        if not self.is_token_valid():
            self.update_access_token()

        realm = self.config.get("realmId")

        if self.config.get("is_sandbox"):
            self.base_url = (
                f"https://sandbox-quickbooks.api.intuit.com/v3/company/{realm}"
            )
        else:
            self.base_url = f"https://quickbooks.api.intuit.com/v3/company/{realm}"

    def get_reference_data(self):
        self.accounts = self.get_entities("Account", key="AcctNum")
        self.customers = self.get_entities("Customer", key="DisplayName")
        self.items = self.get_entities("Item", key="Name")
        self.classes = self.get_entities("Class")

    def update_access_token(self):
        self.auth_client.refresh(self.config.get("refresh_token"))
        self.access_token = self.auth_client.access_token
        self.refresh_token = self.auth_client.refresh_token
        self._config["refresh_token"] = self.refresh_token
        self._config["access_token"] = self.access_token
        self._config["last_update"] = round(datetime.now().timestamp())

        with open(self.config_file, "w") as outfile:
            json.dump(self._config, outfile, indent=4)

    def is_token_valid(self):
        last_update = self.config.get("last_update")
        if not last_update:
            return False
        if round(datetime.now().timestamp()) - last_update > 3300:  # 1h - 5min
            return False
        return True

    @property
    def authenticator(self):
        auth_credentials = {"Authorization": f"Bearer {self.access_token}"}
        return auth_credentials

    @property
    def get_url_params(self):
        params = {}
        params["minorversion"] = 40  # minorversion=40
        return params

    def start_batch(self, context: dict) -> None:
        if not self.is_token_valid():
            # If the token is invalid, refresh the access token
            self.update_access_token()

    def get_entities(
        self, entity_type, key="Name", fallback_key="Name", check_active=True
    ):
        access_token = self.access_token
        offset = 0
        max = 100
        entities = {}

        while True:
            query = f"select * from {entity_type}"
            if check_active:
                query = query + " where Active=true"
            query = query + f" STARTPOSITION {offset} MAXRESULTS {max}"
            url = f"{self.base_url}/query?query={query}&minorversion=40"

            self.logger.info(f"Fetch {entity_type}; url={url}; query {query}")

            r = requests.get(
                url,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
            )

            response = r.json()

            # Establish number of records returned.
            count = response["QueryResponse"].get("maxResults")

            # No results - exit loop.
            if not count or count == 0:
                break

            # Parse the results
            records = response["QueryResponse"][entity_type]

            if not records:
                records = []

            # Append the results
            for record in records:
                entity_key = record.get(key, record.get(fallback_key))
                # Ignore None keys
                if entity_key is None:
                    self.logger.warning(f"Failed to parse record f{json.dumps(record)}")
                    continue

                entities[entity_key] = record

            # We're done - exit loop
            if count < max:
                break

            offset += max

        self.logger.debug(f"[get_entities]: Found {len(entities)} {entity_type}.")

        return entities

    def process_record(self, record: dict, context: dict) -> None:
        if not context.get("records"):
            context["records"] = []

        # Get the journal entry id
        je_id = record["id"]
        self.logger.info(f"Mapping {je_id}...")
        line_items = []

        if self.stream_name == "Customers":

            customer = customer_from_unified(record)

            if customer["DisplayName"] in self.customers:
                old_customer = self.customers[customer["DisplayName"]]
                customer["Id"] = old_customer["Id"]
                customer["SyncToken"] = old_customer["SyncToken"]
                entry = ["Customer",customer,"update"]
            else:
                entry = ["Customer",customer,"create"]

        if self.stream_name == "Invoices":

            invoice = invoice_from_unified(record,self.customers,self.items)

            entry = ["Invoice",invoice,"create"]

        if self.stream_name == "Items":

            item = item_from_unified(record)

            # Setting IncomeAccountRef.value and ExpenseAccountRef.value
            # based on account name from self.accounts

            IncomeAccountRef = item.get("IncomeAccountRef").get('value')
            ExpenseAccountRef = item.get("ExpenseAccountRef").get('value')

            if IncomeAccountRef and IncomeAccountRef in self.accounts: 
                IncomeAccountRef= self.accounts[IncomeAccountRef]["Id"]

            if ExpenseAccountRef and ExpenseAccountRef in self.accounts: 
                ExpenseAccountRef = self.accounts[ExpenseAccountRef]["Id"]

            if IncomeAccountRef or ExpenseAccountRef: 
                self.logger.warning(
                        f"AccontRef missing on Item {je_id}! Name={item['Name']} \n Skipping Item ..."
                        )
                return 

            if item["Name"] in self.items:
                old_item = self.items[item["Name"]]
                item["Id"] = old_item["Id"]
                item["SyncToken"] = old_item["SyncToken"]
                entry = ["Item",item,"update"]
            else:
                entry = ["Item",item,"create"]

        elif self.stream_name == "JournalEntries":

            # Create line items
            for row in record["lines"]:
                # Create journal entry line detail
                je_detail = {"PostingType": row["postingType"]}

                # Get the Quickbooks Account Ref
                acct_num = str(row["accountNumber"])
                acct_name = row["accountName"]
                acct_ref = self.accounts.get(
                    acct_num, self.accounts.get(acct_name, {})
                ).get("Id")

                if acct_ref is not None:
                    je_detail["AccountRef"] = {"value": acct_ref}
                else:
                    errored = True
                    self.logger.error(
                        f"Account is missing on Journal Entry {je_id}! Name={acct_name} No={acct_num} \n Skipping..."
                    )
                    return 

                # Get the Quickbooks Class Ref
                class_name = row.get("className")
                class_ref = self.classes.get(class_name, {}).get("Id")

                if class_ref is not None:
                    je_detail["ClassRef"] = {"value": class_ref}
                else:
                    self.logger.warning(
                        f"Class is missing on Journal Entry {je_id}! Name={class_name}"
                    )

                # Get the Quickbooks Customer Ref
                customer_name = row["customerName"]
                customer_ref = self.customers.get(customer_name, {}).get("Id")

                if customer_ref is not None:
                    je_detail["Entity"] = {
                        "EntityRef": {"value": customer_ref},
                        "Type": "Customer",
                    }
                else:
                    self.logger.warning(
                        f"Customer is missing on Journal Entry {je_id}! Name={customer_name}"
                    )

                # Create the line item
                line_items.append(
                    {
                        "Description": row["description"],
                        "Amount": row["amount"],
                        "DetailType": "JournalEntryLineDetail",
                        "JournalEntryLineDetail": je_detail,
                    }
                )

            # Create the [ resourceName , resource ]
            entry = {
                "TxnDate": record["transactionDate"],
                "DocNumber": je_id,
                "Line": line_items,
            }

            # Append the currency if provided
            if record.get("currency") is not None:
                entry["CurrencyRef"] = {"value": record["currency"]}


            entry = ["JournalEntry",entry,"create"]

        context["records"].append(entry)

    def make_batch_request(self, url, batch_requests):
        access_token = self.access_token

        # Send the request
        r = requests.post(
            url,
            data=json.dumps({"BatchItemRequest": batch_requests}),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )

        response = r.json()

        if response.get("Fault") is not None:
            self.logger.error(response)

        return response.get("BatchItemResponse")

    def process_batch(self, context: dict) -> None:
        # Build endpoint url
        url = f"{self.base_url}/batch?minorversion=45"

        # Get the journals to post
        records = context.get("records")

        # Create the batch requests
        batch_requests = []

        for i, entity in enumerate(records):
            # entity[0] -> "Customer","JournalEntry", ...
            # entity[1] -> data
            # entity[2] -> "create" or "update"
            if entity[1]:
                batch_requests.append(
                    {"bId": f"bid{i}", "operation": entity[2], entity[0] : entity[1]}
                )

        if batch_requests: 
            response_items = self.make_batch_request(url, batch_requests)
        else:
            response_items = []

        if not response_items: 
            response_items = []

        posted_records = []
        failed = False
        
        for ri in response_items:
            if ri.get("Fault") is not None:
                m = re.search("[0-9]+$", ri.get("bId"))
                index = int(m.group(0))
                self.logger.error(
                    f"Failure creating entity error=[{json.dumps(ri)}] request=[{batch_requests[index]}]"
                )
                failed = True
            elif ri.get("JournalEntry") is not None:
                je = ri.get("JournalEntry")
                # Cache posted journal ids to delete them in event of failure
                posted_records.append(
                    {"Id": je.get("Id"), "SyncToken": je.get("SyncToken")}
                )
            elif ri.get("Customer") is not None:
                je = ri.get("Customer")
                # Cache posted customer ids to delete them in event of failure
                posted_records.append(
                    {"Id": je.get("Id"), "SyncToken": je.get("SyncToken")}
                )
            elif ri.get("Item") is not None:
                je = ri.get("Item")
                # Cache posted customer ids to delete them in event of failure
                posted_records.append(
                    {"Id": je.get("Id"), "SyncToken": je.get("SyncToken")}
                )
            elif ri.get("Invoice") is not None:
                je = ri.get("Invoice")
                # Cache posted customer ids to delete them in event of failure
                posted_records.append(
                    {"Id": je.get("Id"), "SyncToken": je.get("SyncToken")}
                )

        if failed:
            batch_requests = []
            # In the event of failure, we need to delete the posted records
            for i, je in enumerate(posted_records):
                batch_requests.append(
                    {"bId": f"bid{i}", "operation": "delete", "JournalEntry": je}
                )

            # Do delete batch requests
            self.logger.info("Deleting any posted records entries...")
            response = self.make_batch_request(url, batch_requests)
            self.logger.debug(json.dumps(response))

            raise Exception("There was an error posting the records")

        pass