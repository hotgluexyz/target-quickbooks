#!/usr/bin/env python3
import json
import sys
import argparse
import requests
import base64
import pandas as pd
import logging

logger = logging.getLogger("target-quickbooks")
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

def load_json(path):
    with open(path) as f:
        return json.load(f)


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


def login(config):
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

    # TODO: Update refresh token if it was changed
    # if (security_context['refresh_token'] != refresh_token):
    #     # TODO: Save the file
    #     config['refresh_token'] = security_context['refresh_token']
    # else:
    #     logger.info(`Same refresh token was received from QuickBooks auth service, no need to update the config in hotglue.`);

    return security_context


def get_entities(entity_type, security_context, key="Name"):
    base_url = security_context['base_url']
    access_token = security_context['access_token']
    offset = 0
    max = 100
    entities = {}

    while True:
        query = f"select * from {entity_type} where Active=true STARTPOSITION {offset} MAXRESULTS {max}"
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
            entities[record[key]] = record

        # We're done - exit loop
        if count < max:
            break

        offset += max

    logger.debug(f"get_entities -> {json.dumps(entities)}")

    return entities


def load_journal_entries(config, accounts, classes, customers):
    # Get input path
    input_path = config['input_path']
    # Read the passed CSV
    df = pd.read_csv(input_path)
    # Verify it has required columns
    cols = list(df.columns)
    REQUIRED_COLS = ["Transaction Date", "Journal Entry Id", "Customer Name", "Class", "Account Number", "Account Name", "Posting Type", "Description"]

    if not all(col in cols for col in REQUIRED_COLS):
        logger.error(f"CSV is mising REQUIRED_COLS. Found={json.dumps(cols)}, Required={json.dumps(REQUIRED_COLS)}")
        sys.exit(1)

    journal_entries = []

    def build_lines(x):
        # Get the journal entry id
        je_id = x['Journal Entry Id'].iloc[0]
        print(f"Converting {je_id}...")
        line_items = []

        # Create line items
        for index, row in x.iterrows():
            # Create journal entry line detail
            je_detail = {
                "PostingType": row['Posting Type']
            }

            # Get the Quickbooks Account Ref
            acct_name = row['Account Name']
            acct_ref = accounts.get(acct_name, {}).get("Id")

            if acct_ref is not None:
                je_detail["AccountRef"] = {
                    "value": acct_ref
                }

            # Get the Quickbooks Class Ref
            class_name = row['Class']
            class_ref = classes.get(class_name, {}).get("Id")

            if class_ref is not None:
                je_detail["ClassRef"] = {
                    "value": class_ref
                }

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

            # Create the line item
            line_items.append({
                "Description": row['Description'],
                "Amount": row['Amount'],
                "DetailType": "JournalEntryLineDetail",
                "JournalEntryLineDetail": je_detail
            })

        # Create the entry
        journal_entries.append({
            'TxnDate': row['Transaction Date'],
            'DocNumber': je_id,
            'Line': line_items
        })
        
    # Build the entries
    df.groupby("Journal Entry Id").apply(build_lines)

    # Print journal entries
    logger.debug(json.dumps(journal_entries))

    return journal_entries


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
    logger.debug(f"CREATE Journal Entries -> {json.dumps(response)}")
    response_items = response.get("BatchItemResponse")

    for ri in response_items:
        if ri.get("Fault") is not None:
            logger.warn(f"Failure creating entity {json.dumps(ri)}")

    return response_items


def upload(config):
    # Login + TODO: update tap config with new refresh token if necessary
    security_context = login(config)

    # Load Active Classes, Customers, Accounts
    accounts = get_entities("Account", security_context)
    customers = get_entities("Customer", security_context, key="DisplayName")
    classes = get_entities("Class", security_context)

    # Load Journal Entries CSV to post + Convert to QB format
    journals = load_journal_entries(config, accounts, classes, customers)

    # Post the journal entries to Quickbooks
    post_journal_entries(journals, security_context)


def main():
    # Parse command line arguments
    args = parse_args()

    # Upload the 
    upload(args.config)


if __name__ == "__main__":
    main()
