#!/usr/bin/env python3
import os
import json
import sys
import argparse
import requests
import base64
import pandas as pd
import logging
import re

logger = logging.getLogger("target-quickbooks")
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def load_json(path):
    with open(path) as f:
        return json.load(f)


def write_json_file(filename, content):
    with open(filename, 'w') as f:
        json.dump(content, f, indent=4)


def parse_args():
    '''Parse standard command-line args.
    Parses the command-line arguments mentioned in the SPEC and the
    BEST_PRACTICES documents:
    -c,--config     Config file
    -s,--state      State file
    -d,--discover   Run in discover mode
    -p,--properties Properties file: DEPRECATED, please use --catalog instead
    --catalog       Catalog file
    Returns the parsed args object from argparse. For each argument that
    point to JSON files (config, state, properties), we will automatically
    load and parse the JSON file.
    '''
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-c', '--config',
        help='Config file',
        required=True)

    args = parser.parse_args()
    if args.config:
        setattr(args, 'config_path', args.config)
        args.config = load_json(args.config)

    return args


def establish_endpoints(config):
    realm_id = config['realmId']

    if config.get("is_sandbox", False):
        return {
            "base_url": f"https://sandbox-quickbooks.api.intuit.com/v3/company/{realm_id}",
            "auth_url": "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
        }

    return {
        "base_url": f"https://quickbooks.api.intuit.com/v3/company/{realm_id}",
        "auth_url": "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
    }


def login(config, config_path):
    client_id = config['client_id']
    client_secret = config['client_secret']
    refresh_token = config['refresh_token']

    endpoints = establish_endpoints(config)
    auth_url = endpoints['auth_url']

    auth_str = f"{client_id}:{client_secret}".encode('ascii')

    r = requests.post(auth_url,
        data=f'grant_type=refresh_token&refresh_token={refresh_token}',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f"Basic {base64.b64encode(auth_str).decode('ascii')}"
        }
    )

    security_context = r.json()
    security_context.update(endpoints)
    logger.info(f"Successful login -> {json.dumps(security_context)}")

    # Update refresh token if it was changed
    if (security_context['refresh_token'] != refresh_token):
        # Save the file
        config['refresh_token'] = security_context['refresh_token']
        logger.info("New refresh token was received from QuickBooks, updating local config")
        write_json_file(config_path, config)
    else:
        logger.info("Same refresh token was received from QuickBooks auth service, no need to update the config in hotglue.")

    return security_context


def get_entities(entity_type, security_context, key="Name", fallback_key="Name", check_active=True):
    base_url = security_context['base_url']
    access_token = security_context['access_token']
    offset = 0
    max = 100
    entities = {}

    while True:
        query = f"select * from {entity_type}"
        if check_active:
            query = query + " where Active=true"
        query = query + f" STARTPOSITION {offset} MAXRESULTS {max}"
        url = f"{base_url}/query?query={query}&minorversion=45"

        logger.info(f"Fetch {entity_type}; url={url}; query {query}")

        r = requests.get(url, headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        })

        response = r.json()

        # Establish number of records returned.
        count = response['QueryResponse'].get('maxResults')

        # No results - exit loop.
        if not count or count == 0:
            break

        # Parse the results
        records = response['QueryResponse'][entity_type]

        if not records:
            records = []

        # Append the results
        for record in records:
            entity_key = record.get(key, record.get(fallback_key))
            # Ignore None keys
            if entity_key is None:
                logger.warning(f"Failed to parse record f{json.dumps(record)}")
                continue

            entities[entity_key] = record

        # We're done - exit loop
        if count < max:
            break

        offset += max

    logger.debug(f"[get_entities]: Found {len(entities)} {entity_type}.")

    return entities


def load_journal_entries(config, accounts, classes, customers):
    # Get input path
    input_path = f"{config['input_path']}/JournalEntries.csv"
    # Read the passed CSV
    df = pd.read_csv(input_path)
    # Verify it has required columns
    cols = list(df.columns)
    REQUIRED_COLS = ["Transaction Date", "Journal Entry Id", "Customer Name", "Class", "Account Number", "Account Name", "Posting Type", "Description"]

    if not all(col in cols for col in REQUIRED_COLS):
        logger.error(f"CSV is mising REQUIRED_COLS. Found={json.dumps(cols)}, Required={json.dumps(REQUIRED_COLS)}")
        sys.exit(1)

    journal_entries = []
    errored = False

    def build_lines(x):
        # Get the journal entry id
        je_id = x['Journal Entry Id'].iloc[0]
        logger.info(f"Converting {je_id}...")
        line_items = []

        # Create line items
        for index, row in x.iterrows():
            # Create journal entry line detail
            je_detail = {
                "PostingType": row['Posting Type']
            }

            # Get the Quickbooks Account Ref
            acct_num = str(row['Account Number'])
            acct_name = row['Account Name']
            acct_ref = accounts.get(acct_num, accounts.get(acct_name, {})).get("Id")

            if acct_ref is not None:
                je_detail["AccountRef"] = {
                    "value": acct_ref
                }
            else:
                errored = True
                logger.error(f"Account is missing on Journal Entry {je_id}! Name={acct_name} No={acct_num}")

            # Get the Quickbooks Class Ref
            class_name = row['Class']
            class_ref = classes.get(class_name, {}).get("Id")

            if class_ref is not None:
                je_detail["ClassRef"] = {
                    "value": class_ref
                }
            else:
                logger.warning(f"Class is missing on Journal Entry {je_id}! Name={class_name}")

            # Get the Quickbooks Customer Ref
            customer_name = row['Customer Name']
            customer_ref = customers.get(customer_name, {}).get("Id")

            if customer_ref is not None:
                je_detail["Entity"] = {
                    "EntityRef": {
                        "value": customer_ref
                    },
                    "Type": "Customer"
                }
            else:
                logger.warning(f"Customer is missing on Journal Entry {je_id}! Name={customer_name}")

            # Create the line item
            line_items.append({
                "Description": row['Description'],
                "Amount": row['Amount'],
                "DetailType": "JournalEntryLineDetail",
                "JournalEntryLineDetail": je_detail
            })

        # Create the entry
        entry = {
            'TxnDate': row['Transaction Date'],
            'DocNumber': je_id,
            'Line': line_items
        }

        # Append the currency if provided
        if row.get('Currency') is not None:
            entry['CurrencyRef'] = {
                'value': row['Currency']
            }

        journal_entries.append(entry)

    # Build the entries
    df.groupby("Journal Entry Id").apply(build_lines)

    if errored:
        raise Exception("Building QBO JournalEntries failed!")

    # Print journal entries
    logger.info(f"Loaded {len(journal_entries)} journal entries to post")

    return journal_entries


def make_batch_request(url, access_token, batch_requests):
    # Send the request
    r = requests.post(url,
        data=json.dumps({
            "BatchItemRequest": batch_requests
        }),
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
    )

    response = r.json()

    if response.get("Fault") is not None:
        logger.error(response)

    return response.get("BatchItemResponse")


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def post_journal_entries(journals, security_context):
    base_url = security_context['base_url']
    access_token = security_context['access_token']
    url = f"{base_url}/batch?minorversion=45"

    # Create the batch requests
    batch_requests = []

    for i, entity in enumerate(journals):
        batch_requests.append(
            {
                "bId": f"bid{i}",
                "operation": "create",
                "JournalEntry": entity
            }
        )

    # Split batches into size 30
    batches = chunks(batch_requests, 30)
    response_items = []

    # Run all batches
    for batch in batches:
        response_items.extend(make_batch_request(url, access_token, batch))

    posted_journals = []
    failed = False

    for ri in response_items:
        if ri.get("Fault") is not None:
            m = re.search("[0-9]+$", ri.get("bId"))
            index = int(m.group(0))
            logger.error(f"Failure creating entity error=[{json.dumps(ri)}] request=[{batch_requests[index]}]")
            failed = True
        elif ri.get("JournalEntry") is not None:
            je = ri.get("JournalEntry")
            # Cache posted journal ids to delete them in event of failure
            posted_journals.append({
                'Id': je.get("Id"),
                'SyncToken': je.get("SyncToken")
            })

    if failed:
        batch_requests = []
        # In the event of failure, we need to delete the posted journals
        for i, je in enumerate(posted_journals):
            batch_requests.append(
                {
                    "bId": f"bid{i}",
                    "operation": "delete",
                    "JournalEntry": je
                }
            )

        # Do delete batch requests
        logger.info("Deleting any posted journal entries...")
        response = make_batch_request(url, access_token, batch_requests)
        logger.debug(json.dumps(response))


def upload_journals(config, security_context):
    # Load Active Classes, Customers, Accounts
    accounts = get_entities("Account", security_context, key="AcctNum")
    customers = get_entities("Customer", security_context, key="DisplayName")
    classes = get_entities("Class", security_context)

    # Load Journal Entries CSV to post + Convert to QB format
    journals = load_journal_entries(config, accounts, classes, customers)

    # Post the journal entries to Quickbooks
    post_journal_entries(journals, security_context)


def create_class(security_context, cl):
    base_url = security_context['base_url']
    access_token = security_context['access_token']
    url = f"{base_url}/class?minorversion=45"

    # Send the request
    r = requests.post(url,
        data=json.dumps(cl),
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
    )

    response = r.json()
    return response


def create_subclass(security_context, classes, parent_name, parent, sub):
    for cl in sub:
        cl_name = cl["Name"]
        cl_sub = cl.get("Sub", [])
        full_name = f"{parent_name}:{cl_name}"

        if classes.get(full_name) is None:
            # Create the class
            cl_data = create_class(security_context, {
                'Name': cl_name,
                'ParentRef': {
                    'value': parent
                }
            })["Class"]
        else:
            # Get the class
            cl_data = classes.get(full_name)

        # Recursively create sub classes, if necessary
        create_subclass(security_context, classes, full_name, cl_data["Id"], cl_sub)


def upload_classes(config, security_context):
    # Load Active Classes
    classes = get_entities("Class", security_context, key="FullyQualifiedName")

    # Get input path
    input_path = f"{config['input_path']}/Classes.json"
    # Read the classes
    new_cl = load_json(input_path)

    for cl in new_cl:
        cl_name = cl["Name"]
        cl_sub = cl.get("Sub", [])

        if classes.get(cl_name) is None:
            # Create the class
            cl_data = create_class(security_context, {
                'Name': cl_name,
            })["Class"]
        else:
            # Get the class
            cl_data = classes.get(cl_name)

        # Recursively create any sub classes, if necessary
        create_subclass(security_context, classes, cl_name, cl_data["Id"], cl_sub)


def create_invoice(security_context, invoice):
    base_url = security_context['base_url']
    access_token = security_context['access_token']
    url = f"{base_url}/invoice?minorversion=45"

    # Send the request
    r = requests.post(url,
        data=json.dumps(invoice),
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
    )

    response = r.json()
    return response


def upload_invoices(config, security_context):
    # Load Active invoices
    # invoices = get_entities("Invoice", security_context, key="Name", check_active=True)
    customers = get_entities("Customer", security_context, key="DisplayName")
    items = get_entities("Item", security_context, key="DisplayName")
    # Get input path
    input_path = f"{config['input_path']}/Invoices.json"
    # Read the invoices
    new_invoice = load_json(input_path)

    for i, invoice in enumerate(new_invoice):

        customer = invoice.get('CustomerRef')
        if not customer:
            logger.warning(f"Invoice {i} missing CustomerRef, ignoring record.")
            continue
        customer_name = customer.get("name")
        if not customer_name:
            logger.warning(f"Invoice {i} missing CustomerRef.name, ignoring record.")
            continue

        customer_data = customers.get(customer_name)
        if not customer_data:
            logger.warning(f"Customer: {customer_name} does not exist, ignoring record.")
            continue

        invoice['CustomerRef']["value"] = customer_data.get("Id")

        if invoice.get("Line"):

            for item in invoice.get("Line"):
                try:
                    item_name = item["SalesItemLineDetail"]["ItemRef"]["name"]
                except:
                    logger.warning(f"Invoice {i} missing SalesItemLineDetail.ItemRef.name, ignoring invoice.")
                    continue
                item_data = items.get(item_name)
                if not item_data:
                    logger.warning(f"Item: {item_data} does not exist, ignoring invoice that contains it.")
                    continue
                item["SalesItemLineDetail"]["ItemRef"]["value"] = item_data.get("Id")

            create_invoice(security_context, invoice)

        else:
            logger.warning(f"Invoice {i} missing Line, ignoring record.")


def upload(config, args):
    # Login update tap config with new refresh token if necessary
    security_context = login(config, args.config_path)

    if os.path.exists(f"{config['input_path']}/Classes.json"):
        logger.info("Found Classes.json, uploading...")
        upload_classes(config, security_context)
        logger.info("Classes.json uploaded!")
    
    if os.path.exists(f"{config['input_path']}/Invoices.json"):
        logger.info("Found Invoices.json, uploading...")
        upload_invoices(config, security_context)
        logger.info("Invoices.json uploaded!")

    if os.path.exists(f"{config['input_path']}/JournalEntries.csv"):
        logger.info("Found JournalEntries.csv, uploading...")
        upload_journals(config, security_context)
        logger.info("JournalEntries.csv uploaded!")

    logger.info("Posting process has completed!")


def main():
    # Parse command line arguments
    args = parse_args()

    # Upload the new QBO data
    upload(args.config, args)


if __name__ == "__main__":
    main()
