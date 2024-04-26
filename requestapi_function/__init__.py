from urllib.parse import urlparse, parse_qs
import azure.functions as func
import json
import logging
import re
import requests

def main(req: func.HttpRequest) -> func.HttpResponse:

    #Initialise the status code and header check values.
    status_code = ''
    headercheck = 0
    
    #Takes the method supplied in the request, and checks if it's either GET or POST. Exits otherwise.
    method = req.method
    if method not in ('GET','POST'):
        status_code = 400
        logging.info('verb issue')
        return func.HttpResponse(f"1-Function returned with status code: {status_code}")
    # url for result API to return results
    url = 'https://result-api.dev.ultromics.net/api/QueryResults'
    # Keys expected to be found in the request
    expectedkeys = ['SERVICE','PRODUCT','ACCESSION','STUDYINSTANCEUID','SUBSCRIPTION-KEY']

    # Checks if the Content-Type header is of accepted values
    if 'Content-Type' in req.headers and req.headers['Content-Type'].upper() in ('APPLICATION/JSON', 'APPLICATION/X-WWW-FORM-URLENCODED'):
        header_value = req.headers['Content-Type']
        headercheck = 1

    if 'content-type' in req.headers and req.headers['content-type'].upper() in ('APPLICATION/JSON', 'APPLICATION/X-WWW-FORM-URLENCODED'):
        header_value = req.headers['content-type']
        headercheck = 1

    # Exits if header value is incorrect
    # setting header check to 1 for sake of testing - 24042024 - please remove
    #headercheck = 1
    if headercheck != 1:
        logging.info('header issue')
        status_code = 400
        return func.HttpResponse(f"1-Function returned with status code: {status_code}")
    
    # If the method is GET,extracts the parameters from the supplied url. Gets the supplied keys to check against required parameters.
    if method == 'GET':
        parsed_url = urlparse(req.url)
        query_params = parse_qs(parsed_url.query)
        logging.info(str(query_params))
        if 'code' in query_params:
            query_params.pop('code')

        # Create a new dictionary with uppercase keys and values
        uppercase_query_params = {key.upper(): [value.upper() for value in values] for key, values in query_params.items()}

        suppliedkeys = uppercase_query_params.keys()

        params_values = {}

        # Checks for any missing parameters.
        for param in expectedkeys:
            if param not in suppliedkeys:
                status_code = 400
                logging.info(f'{param} is missing')
                return func.HttpResponse(f"2-Function returned with status code: {status_code}")
            else:
                params_values[param] = uppercase_query_params[param][0]
        # Assigns parameters to variables.
        service = params_values['SERVICE']
        product = params_values['PRODUCT']
        accession = params_values['ACCESSION']
        studyinstanceuid = params_values['STUDYINSTANCEUID']
        # Derives the customer code from the returned accession using split.
        customer_code = str(params_values['ACCESSION'].split('-')[0])

    # If the method is POST, extracts parameters from the request body.
    if method == 'POST':
        body_bytes = req.get_body()
        body_str = body_bytes.decode('utf-8')  # Decode bytes to string assuming utf-8 encoding
        body_dict = json.loads(body_str)  # Parse the JSON string into a Python dictionary
         # Create a new dictionary with uppercase keys and uppercase values
        uppercase_body_dict = {key.upper(): value.upper() if isinstance(value, str) else value for key, value in body_dict.items()}
        try:
            suppliedkeys = uppercase_body_dict.keys()
        except Exception as e:
            logging.info(str(e))
            status_code = 400
            return func.HttpResponse(f"3-Function returned with status code: {status_code}")

        service = uppercase_body_dict.get('SERVICE')  
        product = uppercase_body_dict.get('PRODUCT')
        accession = uppercase_body_dict.get('ACCESSION')
        # Derives the customer code from the returned accession using split.
        customer_code = str(uppercase_body_dict.get('ACCESSION').split('-')[0])
        studyinstanceuid = uppercase_body_dict.get('STUDYINSTANCEUID')
    
    # Checks that the supplied keys (extracted from GET or POST) match the expected keys. If there are any missing keys, or any extra keys that aren't required, code exits. 
    missing_keys = [key for key in expectedkeys if key not in suppliedkeys]
    if len(missing_keys) > 0:
        status_code = 400
        logging.info(str(missing_keys) + ' is/are missing - incomplete request')
        return func.HttpResponse(f"4-Function returned with status code: {status_code}")
    extra_keys = [key for key in suppliedkeys if key not in expectedkeys]
    if len(extra_keys) > 0:
        status_code = 400
        logging.info('Extra key(s) '+str(extra_keys)+ ' is/are in the request - invalid request')
        return func.HttpResponse(f"5-Function returned with status code: {status_code}")

    # Checks if the header value is in expected options.
    #if header_value not in ('application/json','application/x-www-form-urlencoded'):
     #   status_code = 400
      #  logging.info('header issue')
       # return func.HttpResponse(f"5-Function returned with status code: {status_code}")

    # Checks if the service is in the expected values.
    if service not in ('HL7','DICOM','JSON'):
        status_code = 400
        logging.info('service issue')
        return func.HttpResponse(f"6-Function returned with status code: {status_code}")

    # Checks that the supplied accession matches the expected format: ABC-123. Uses regular expressions.
    if not re.match(r'^[A-Za-z]{3,4}-\d{1,4}$', accession):
        status_code = 400
        logging.info('order id issue')
        return func.HttpResponse(f"7-Function returned with status code: {status_code}")

    # Checks if the supplied service/product/accession is a list, meaning more than one is requested at once. Exits if so.
    if isinstance(service, list) or isinstance(product, list) or isinstance(accession, list):
        status_code = 400
        logging.info('multiple services/products/accessions requested.')
        return func.HttpResponse(f"8-Function returned with status code: {status_code}")

    # Checks that the 
    #if not url.startswith('https://') or not re.match(r'https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}', url):
    #    status_code = 400
    #    logging.info('url issue')
    #    return func.HttpResponse(f"9-Function returned with status code: {status_code}")

    # Checks that the requested software is EchoGo Heart Failure, returns if not. Converts to upper-case to remove case-sensitivity.
    if product not in ('ECHOGO HEART FAILURE'):
        status_code = 400
        logging.info('software req issue')
        return func.HttpResponse(f"9-Function returned with status code: {status_code}")

    # Creates the data json to post to the results API. Contains the accession and the product.
    data = {
        'order': accession,
        'software': product
    }

    # Passes request on to the results api.
    response = requests.post(url, json=data,allow_redirects=False, timeout=60)
    response_text = response.text
    # Exits if the response cannot be loaded into a json object
    try:
        json_data = json.loads(response_text)
        # Create a new dictionary with uppercase keys and uppercase values
        #uppercase_json_data = {key.upper(): value.upper() if isinstance(value, str) else value for key, value in json_data.items()}
        uppercase_json_data = [{key.upper(): value.upper() if isinstance(value, str) else value for key, value in data.items()} for data in json_data]


    except json.JSONDecodeError as e:
        logging.error("JSON Decode Error:" + str(e))
        status_code = 404
        logging.info('no results returned')
        return func.HttpResponse(f"10-Function returned with status code: {status_code}")

    # Checks if the json object is empty.
    if len(uppercase_json_data) == 0:
        status_code = 404
        logging.info('no results returned')
        return func.HttpResponse(f"11-Function returned with status code: {status_code}")

    # Adds/renames elements of the json to be returned.
    for item in uppercase_json_data:
        outcome = ''
        if item['ACCEPTED'] == True:
            outcome = 'Positive'
        if item['ACCEPTED'] == False:
            outcome = 'Negative'

        item['ULTROMICSID'] = item.pop('ACCESSION')
        item['OUTCOME'] = outcome
        item.pop('ACCEPTED')
        item['PRODUCT'] = item['SOFTWARE'] + ' - ' + item.pop('VERSION')
        item['REJECTION'] = item.pop('REASON')
        item['STUDYINSTANCEUID'] = item.pop('SUID')
        item['CREATED'] = item.pop('RECEIVED')

    # Checks if the returned customer code matches the supplied customer code.
    if customer_code != item['CUSTOMER']:
        status_code = 400
        logging.info('customer code not matching')
        return func.HttpResponse(f"12-Function returned with status code: {status_code}")
    # Checks if the returned accession matches the supplied accession
    if accession != item['ULTROMICSID']:
        status_code = 400
        logging.info('accession not matching')
        return func.HttpResponse(f"13-Function returned with status code: {status_code}")
    # Checks if the returned software matches the requested product
    if product != item['SOFTWARE']:
        status_code = 400
        logging.info('product not matching')
        return func.HttpResponse(f"14-Function returned with status code: {status_code}")
    # Checks if the returned SOP matches the expected format.
    if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+$',item['SOP']):
        status_code = 400
        logging.info('invalid sop format')
        return func.HttpResponse(f"15-Function returned with status code: {status_code}")
    # Checks if the returned studyinstanceuid matches the expected format.
    if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',item['STUDYINSTANCEUID']):
        status_code = 400
        logging.info('invalid studyinstanceuid format')
        return func.HttpResponse(f"16-Function returned with status code: {status_code}")
    # Checks if the returned created date matches the expected format.
    if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}$',item['CREATED']):
        status_code = 400
        logging.info('invalid created datetime')
        return func.HttpResponse(f"17-Function returned with status code: {status_code}")
    
    # Returns the json response as a json item.
    json_response = json.dumps(item)
    
    # 200 status code.
    status_code = 200
    
    # If the service is not DICOM, then returns the json as a response. Otherwise, simply returns with a 200 status code.
    if service != 'DICOM':
        return func.HttpResponse(json_response, mimetype="application/json")
    else:
        return func.HttpResponse(f"18-Function returned with status code: {status_code}")
